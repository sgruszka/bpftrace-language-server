use std::env;
use std::io;
use std::process::Command;
use std::process::Output;
use std::sync::OnceLock;
use std::time::Instant;

use crate::log_mod::{self, CMAND};
use crate::{log_dbg, log_err};

static USE_SUDO: OnceLock<bool> = OnceLock::new();
static CUSTOM_COMMAND: OnceLock<String> = OnceLock::new();

#[allow(unused)]
#[derive(Default, Debug)]
struct Version {
    major: u16,
    minor: u16,
    patch: u16,
    hash: Option<String>,
}

macro_rules! bpftrace_version {
    ($major:literal, $minor:literal, $patch:literal) => {{
        const _: () = assert!($major >= 0 && $major <= 10);
        const _: () = assert!($minor >= 0 && $minor <= 100);
        ($major as u64) << 32 | ($minor as u64) << 16 | ($patch)
    }};
}

fn to_flat_version(ver: &Version) -> u64 {
    let major = ver.major as u64;
    let minor = ver.minor as u64;
    let patch = ver.patch as u64;

    major << 32 | minor << 16 | patch
}

#[allow(unused)]
#[derive(Default, Debug)]
struct Bpftrace {
    version: Version,
    use_dry_run: bool,
    has_fentry_fexit: bool,
    has_dot_deref: bool,
}

static BPFTRACE: OnceLock<Bpftrace> = OnceLock::new();

pub enum BpftraceProperty {
    HasFentryFexit,
    HasDotDeref,
}

pub fn bpftrace_has_property(prop: BpftraceProperty) -> bool {
    let Some(bpftrace) = BPFTRACE.get() else {
        return false;
    };

    match prop {
        BpftraceProperty::HasFentryFexit => bpftrace.has_fentry_fexit,
        BpftraceProperty::HasDotDeref => bpftrace.has_dot_deref,
    }
}

pub fn bpftrace_major_minor_version() -> (u16, u16) {
    let Some(bpftrace) = BPFTRACE.get() else {
        return (0, 0); // TODO: sane defaults
    };

    (bpftrace.version.major, bpftrace.version.minor)
}

fn sudo_bpftrace_command(use_sudo: bool, args: &[&str]) -> io::Result<Output> {
    // TODO: we do not handle args correctly in custom command,
    // at minimum add information in README.md
    let cmd_str = if let Some(custom_cmd) = CUSTOM_COMMAND.get() {
        custom_cmd
    } else {
        "bpftrace"
    };

    let mut cmd = if use_sudo {
        Command::new("sudo")
    } else {
        Command::new(cmd_str)
    };

    if use_sudo {
        cmd.args(["-n", cmd_str]);
    }

    cmd.args(args).output()
}

pub fn bpftrace_list_probes(probes_str: &str, _uprobe: bool) -> Option<String> {
    let cmd_str = if let Some(custom_cmd) = CUSTOM_COMMAND.get() {
        custom_cmd
    } else {
        "bpftrace"
    };

    // TODO: this depends on setup_bpftrace_root_permissions() finish
    // Need to wait, or do something similar like in bpftrace_command()
    let mut sudo = "";
    if let Some(use_sudo) = USE_SUDO.get() {
        if *use_sudo {
            sudo = "sudo -n ";
        }
    }

    let cmd = format!("{}{}", sudo, cmd_str);

    let shell_cmd = format!(r#"({} -l '{}') 2>&1"#, cmd, probes_str);

    let Ok(output) = Command::new("sh").arg("-c").arg(shell_cmd).output() else {
        return None;
    };

    let Ok(all_probes_args) = String::from_utf8(output.stdout) else {
        return None;
    };

    Some(all_probes_args)
}

pub fn bpftrace_list_probes_verbose(probes_str: &str) -> Option<String> {
    let cmd_str = if let Some(custom_cmd) = CUSTOM_COMMAND.get() {
        custom_cmd
    } else {
        "bpftrace"
    };

    // TODO: this depends on setup_bpftrace_root_permissions() finish
    // Need to wait or do something similar like in bpftrace_command()
    let mut sudo = "";
    if let Some(use_sudo) = USE_SUDO.get() {
        if *use_sudo {
            sudo = "sudo -n ";
        }
    }

    let cmd = format!("{}{}", sudo, cmd_str);

    // bpftrace -l -v mixes stdout (for probe names) and stderr (for args),
    // run in sub shell to get coherent output
    let shell_cmd = format!(r#"({} -l -v '{}') 2>&1"#, cmd, probes_str);

    let Ok(output) = Command::new("sh").arg("-c").arg(shell_cmd).output() else {
        return None;
    };

    let Ok(all_probes_args) = String::from_utf8(output.stdout) else {
        return None;
    };

    Some(all_probes_args)
}

pub fn bpftrace_command(args: &[&str]) -> io::Result<Output> {
    if let Some(use_sudo) = USE_SUDO.get() {
        return sudo_bpftrace_command(*use_sudo, args);
    }

    if let Ok(output) = sudo_bpftrace_command(false, args) {
        if output.status.success() {
            let _ = USE_SUDO.set(false);
            return Ok(output);
        }
    }

    if let Ok(output) = sudo_bpftrace_command(true, args) {
        if output.status.success() {
            let _ = USE_SUDO.set(true);
            return Ok(output);
        }
    }

    Err(io::ErrorKind::PermissionDenied.into())
}

pub fn bpftrace_dry_run_command(prog: &str) -> io::Result<Output> {
    let args_dry_run = vec!["--dry-run", "-e", prog];
    let args_d = vec!["-d", "-e", prog];

    if let Some(bpftrace) = BPFTRACE.get() {
        if bpftrace.use_dry_run {
            return bpftrace_command(&args_dry_run);
        } else {
            return bpftrace_command(&args_d);
        }
    }

    Err(io::ErrorKind::PermissionDenied.into())
}

fn parse_version(version: &str) -> Option<Version> {
    let version = version.strip_prefix("bpftrace v")?;
    let mut parts = version.splitn(2, '-');

    let numbers = parts.next()?.trim();
    let hash = parts.next().map(String::from);

    let mut nums = numbers.split('.');

    let major = nums.next()?.parse().ok()?;
    let minor = nums.next()?.parse().ok()?;
    let patch = nums.next()?.parse().ok()?;

    Some(Version {
        major,
        minor,
        patch,
        hash,
    })
}

fn bpftrace_properties(ver: Version) -> Bpftrace {
    Bpftrace {
        use_dry_run: to_flat_version(&ver) >= bpftrace_version!(0, 22, 0),
        has_fentry_fexit: to_flat_version(&ver) >= bpftrace_version!(0, 20, 0),
        has_dot_deref: to_flat_version(&ver) >= bpftrace_version!(0, 25, 0),
        version: ver,
    }
}

fn bpftrace_properties_from_version() -> Result<Bpftrace, io::Error> {
    let output = sudo_bpftrace_command(false, &["--version"])?;

    let Ok(version_str) = String::from_utf8(output.stdout) else {
        log_err!("Failed to convert stdout to string");
        return Err(io::ErrorKind::InvalidData.into());
    };
    log_dbg!(CMAND, "Found {}", version_str.trim());

    let Some(version) = parse_version(&version_str) else {
        log_err!("Failed to parse bpftrace version string");
        return Err(io::ErrorKind::InvalidData.into());
    };

    Ok(bpftrace_properties(version))
}

fn get_used_command<'a>() -> &'a str {
    if let Some(custom_cmd) = CUSTOM_COMMAND.get() {
        custom_cmd
    } else if USE_SUDO.get().copied().unwrap_or(false) {
        "sudo bpftrace"
    } else {
        "bpftrace"
    }
}

pub fn init_bpftrace(custom_cmd_opt: Option<String>) -> Result<(), String> {
    // Environment variable takes precedence
    if let Ok(custom_cmd) = env::var("BPFTRACE_LS_COMMAND") {
        let _ = CUSTOM_COMMAND.set(custom_cmd);
    } else if let Some(custom_cmd) = custom_cmd_opt {
        let _ = CUSTOM_COMMAND.set(custom_cmd);
    }

    let bpftrace = match bpftrace_properties_from_version() {
        Ok(bpftrace) => bpftrace,
        Err(e) => {
            let cmd = get_used_command();
            return Err(format!(
                "'{cmd} --version' failed with '{e}'. LSP functionality limited, see README.md"
            ));
        }
    };

    log_dbg!(CMAND, "Properties {:?} ", bpftrace);
    let _ = BPFTRACE.set(bpftrace);
    Ok(())
}

pub fn setup_bpftrace_root_permissions() -> Result<(), String> {
    let start = Instant::now();
    let cmd;

    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        let _ = USE_SUDO.set(false);
        cmd = get_used_command();
    } else {
        // 'bptrace --info' is faster than 'bpftrace --dry-run -e "BEGIN { exit() }'
        // How much faster depends on bpftrace version. Use it since is faster,
        // even if it might not test all needed CAPABILITIES.
        let result = bpftrace_command(&["--info"]);
        cmd = get_used_command();

        if let Err(_e) = result {
            return Err(format!(
                "'Can not run {cmd} with root permissions. LSP functionality limited, see README.md"
            ));
        }
    }

    log_dbg!(
        CMAND,
        "'{cmd}' command is root capable, detected after {:?} ",
        start.elapsed()
    );

    Ok(())
}
