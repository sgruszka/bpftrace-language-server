use std::env;
use std::io;
use std::process::Command;
use std::process::Output;
use std::sync::OnceLock;

use crate::log_err;
use crate::log_mod;

static USE_SUDO: OnceLock<bool> = OnceLock::new();
static USE_DRY_RUN: OnceLock<bool> = OnceLock::new();
static CUSTOM_COMMAND: OnceLock<String> = OnceLock::new();

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

    if let Some(use_dry_run) = USE_DRY_RUN.get() {
        if *use_dry_run {
            return bpftrace_command(&args_dry_run);
        } else {
            return bpftrace_command(&args_d);
        }
    }

    if let Ok(output) = bpftrace_command(&args_dry_run) {
        if output.status.success() {
            let _ = USE_DRY_RUN.set(true);
            return Ok(output);
        }
    }

    let _ = USE_DRY_RUN.set(false);
    bpftrace_command(&args_d)
}

pub fn init_bpftrace_dry_run(custom_cmd_opt: Option<String>) {
    // Environment variable takes precedence
    if let Ok(custom_cmd) = env::var("BPFTRACE_LS_COMMAND") {
        let _ = CUSTOM_COMMAND.set(custom_cmd);
    } else if let Some(custom_cmd) = custom_cmd_opt {
        let _ = CUSTOM_COMMAND.set(custom_cmd);
    }

    let result = bpftrace_dry_run_command("BEGIN { exit() }");
    if let Err(e) = result {
        log_err!("Failed to detect bpftrace dry-run command, error {:?}", e);
    }
}
