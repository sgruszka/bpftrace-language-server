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
    let mut cmd = if use_sudo {
        Command::new("sudo")
    } else {
        Command::new("bpftrace")
    };

    if use_sudo {
        cmd.arg("bpftrace");
    }

    cmd.args(args).output()
}

pub fn bpftrace_list_probes_verbose(probes_str: &str) -> Option<String> {
    let cmd = if let Some(custom_cmd) = CUSTOM_COMMAND.get() {
        custom_cmd.to_string()
    } else {
        let mut sudo = "";
        if let Some(use_sudo) = USE_SUDO.get() {
            if *use_sudo {
                sudo = "sudo ";
            }
        }

        format!("{}bpftrace", sudo)
    };

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
    if let Some(custom_cmd) = CUSTOM_COMMAND.get() {
        return Command::new(custom_cmd).args(args).output();
    }

    if let Some(use_sudo) = USE_SUDO.get() {
        return sudo_bpftrace_command(*use_sudo, args);
    }

    if let Ok(output) = sudo_bpftrace_command(false, args) {
        if output.status.success() {
            let _ = USE_SUDO.set(false);
            return Ok(output);
        }
    }

    let _ = USE_SUDO.set(true);
    sudo_bpftrace_command(true, args)
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

    // TODO: we should never get here, log error.
    if let Ok(output) = bpftrace_command(&args_dry_run) {
        if output.status.success() {
            return Ok(output);
        }
    }

    bpftrace_command(&args_d)
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

fn bpftrace_properties_from_version() -> Option<Bpftrace> {
    // We need to properly initialize sudo with bpftrace command that
    // require root privileges, so can not run bpftrace_command() here,
    // but still want custom command if specified
    let result = if let Some(_custom_cmd) = CUSTOM_COMMAND.get() {
        bpftrace_command(&["--version"])
    } else {
        sudo_bpftrace_command(false, &["--version"])
    };

    let Ok(output) = result else {
        log_err!("Failed to get output from bpftrace --version");
        return None;
    };

    let Ok(version_str) = String::from_utf8(output.stdout) else {
        log_err!("Failed to convert stdout to string");
        return None;
    };
    log_dbg!(CMAND, "Found {}", version_str.trim());

    let Some(version) = parse_version(&version_str) else {
        log_err!("Failed to parse bpftrace version string");
        return None;
    };

    Some(bpftrace_properties(version))
}

pub fn init_bpftrace_command(custom_cmd_opt: Option<String>) {
    let start = Instant::now();

    // Environment variable takes precedence
    if let Ok(custom_cmd) = env::var("BPFTRACE_LS_COMMAND") {
        let _ = CUSTOM_COMMAND.set(custom_cmd);
    } else if let Some(custom_cmd) = custom_cmd_opt {
        let _ = CUSTOM_COMMAND.set(custom_cmd);
    }

    // TODO: we initialize to defaults, but really we should make
    // the client know we can not find version of bpftrace
    let bpftrace = bpftrace_properties_from_version().unwrap_or_default();
    log_dbg!(CMAND, "Properties {:?} ", bpftrace);

    let _ = BPFTRACE.set(bpftrace);

    log_dbg!(
        CMAND,
        "Bpftrace command initialized after {:?} ",
        start.elapsed()
    );
}

pub fn init_bpftrace_dry_run() {
    let result = bpftrace_dry_run_command("BEGIN { exit() }");
    if let Err(e) = result {
        log_err!("Failed to detect bpftrace dry-run command, error {:?}", e);
    }
}
