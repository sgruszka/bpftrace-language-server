use std::env;
use std::fs::File;
use std::io::Write;
use std::sync::{mpsc, OnceLock};
use std::thread;

pub const PROTO: u32 = 1 << 0;
pub const DIAGN: u32 = 1 << 1;
pub const COMPL: u32 = 1 << 2;
pub const NOTIF: u32 = 1 << 3;
pub const HOVER: u32 = 1 << 4;
pub const BTFRD: u32 = 1 << 5;
pub const PARSE: u32 = 1 << 6;
pub const DEFIN: u32 = 1 << 7;

#[macro_export]
macro_rules! log_err {
    ($fmt:expr) => {
        let msg = format!($fmt);
        let prefix = format!("{} {}:", file!(), line!());
        let full_msg = format!("{:<20} {}", prefix, msg);
        log_mod::log_fn(full_msg);
    };
    ($fmt:expr, $( $arg:tt )* ) => {
        {
        let msg = format!($fmt, $( $arg )* );
        let prefix = format!("{} {}:", file!(), line!());
        let full_msg = format!("{:<20} {}", prefix, msg);
        log_mod::log_fn(full_msg);
        }
    };
}

#[macro_export]
macro_rules! log_dbg {
    ($type:expr, $fmt:expr) => {
        let msg = format!($fmt);
        let prefix = format!("{} {}:", file!(), line!());
        let full_msg = format!("{:<20} {}", prefix, msg);
        log_mod::log_cond_fn($type, full_msg);
    };
    ($type:expr, $fmt:expr, $( $arg:tt )* ) => {
        {
        let msg = format!($fmt, $( $arg )* );
        let prefix = format!("{} {}:", file!(), line!());
        let full_msg = format!("{:<20} {}", prefix, msg);
        log_mod::log_cond_fn($type, full_msg);
        }
    };
}

#[macro_export]
macro_rules! log_vdbg {
    ($type:expr, $fmt:expr) => {
        if $crate::log_mod::is_verbose() {
            let msg = format!($fmt);
            let prefix = format!("{} {}:", file!(), line!());
            let full_msg = format!("{:<20} {}", prefix, msg);
            $crate::log_mod::log_cond_fn($type, full_msg);
        }
    };

    ($type:expr, $fmt:expr, $( $arg:tt )* ) => {
        {
        if $crate::log_mod::is_verbose() {
            let msg = format!($fmt, $( $arg )* );
            let prefix = format!("{} {}:", file!(), line!());
            let full_msg = format!("{:<20} {}", prefix, msg);
            $crate::log_mod::log_cond_fn($type, full_msg);
            }
        }
    };
}

pub struct Logger {
    mask: u32,
    verbose_debug: u32,
    sender: mpsc::Sender<String>,
}

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub fn create_logger(filename: &str) -> Result<(), std::io::Error> {
    let verbose_level = match env::var("BPFTRACE_LS_LOG_VERBOSE") {
        Ok(val) => val.parse::<u32>().unwrap_or(0),
        Err(_) => 0,
    };

    const DEFAULT_MASK: u32 = PROTO;
    let mask = match env::var("BPFTRACE_LS_LOG_MASK") {
        Ok(val) => {
            let mut mask = 0_u32;
            if val.is_empty() {
                // fall through to default
            } else if let Ok(num) = val.parse::<u32>() {
                mask = num;
            } else if let Some(stripped) = val.strip_prefix("0x") {
                if let Ok(num) = u32::from_str_radix(stripped, 16) {
                    mask = num;
                }
            } else {
                for component in val.split(',') {
                    match component.trim().to_uppercase().as_str() {
                        "PROTO" => mask |= PROTO,
                        "DIAGN" => mask |= DIAGN,
                        "COMPL" => mask |= COMPL,
                        "NOTIF" => mask |= NOTIF,
                        "HOVER" => mask |= HOVER,
                        "BTFRD" => mask |= BTFRD,
                        "PARSE" => mask |= PARSE,
                        "DEFIN" => mask |= DEFIN,
                        _ => {} // ignore unknown components
                    }
                }
            }

            if mask == 0 {
                DEFAULT_MASK
            } else {
                mask
            }
        }
        Err(_) => DEFAULT_MASK,
    };

    let mut log_file = File::create(filename)?;
    let (tx, rx) = mpsc::channel::<String>();

    let _logger_thread = thread::spawn(move || {
        while let Ok(msg) = rx.recv() {
            let _r = log_file.write_all(msg.as_bytes());
            let _r = log_file.write_all("\n".as_bytes());
        }
    });

    LOGGER
        .set(Logger {
            mask,
            verbose_debug: verbose_level,
            sender: tx,
        })
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "Logger already initialized",
            )
        })
}

pub fn is_verbose() -> bool {
    if let Some(logger) = LOGGER.get() {
        logger.verbose_debug != 0
    } else {
        false
    }
}

pub fn log_fn(txt: String) {
    if cfg!(test) {
        println!("{}", txt);
    } else if let Some(logger) = LOGGER.get() {
        let _ = logger.sender.send(txt);
    }
}

pub fn log_cond_fn(this_mask: u32, txt: String) {
    if cfg!(test) {
        println!("{}", txt);
    } else if let Some(logger) = LOGGER.get() {
        if (logger.mask & this_mask) == 0 {
            return;
        }

        let _ = logger.sender.send(txt);
    }
}
