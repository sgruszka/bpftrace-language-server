use glob_match::glob_match;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use crate::args::find_common_args_by_btf;
use crate::btf_rd::{Btf, BtfFunction};
use crate::cmd_mod::bpftrace_command;
use crate::log_mod::{self, COMPL};
use crate::{log_dbg, log_err, log_vdbg};

static AVAILABE_TRACES: OnceLock<Option<String>> = OnceLock::new();

pub fn provider_doc_name(name: &str) -> &str {
    match name {
        "k" => "kprobe",
        "kr" => "kretprobe",
        "f" => "fentry",
        "fr" => "fexit",
        "t" => "tracepoint",
        "rt" => "rawtracepoint",
        "u" => "uprobe",
        "ur" => "uretprobe",
        "U" => "usdt",
        "begin" => "BEGIN",
        "end" => "END",
        _ => name,
    }
}

fn is_fentry_probe(probe: &str) -> bool {
    probe.starts_with("fentry") || probe.starts_with("kfunc") || probe.starts_with("f:")
}

fn is_fexit_probe(probe: &str) -> bool {
    probe.starts_with("fexit") || probe.starts_with("kretfunc") || probe.starts_with("fr:")
}

fn is_kprobe_probe(probe: &str) -> bool {
    probe.starts_with("kprobe") || probe.starts_with("k:")
}

fn is_kretprobe_probe(probe: &str) -> bool {
    probe.starts_with("kretprobe") || probe.starts_with("kr:")
}

pub fn is_tracepoint_probe(probe: &str) -> bool {
    probe.starts_with("tracepoint") || probe.starts_with("t:")
}

pub fn is_rawtracepoint_probe(probe: &str) -> bool {
    probe.starts_with("rawtracepoint") || probe.starts_with("rt:")
}

pub fn probe_use_btf(probe: &str) -> bool {
    is_fentry_probe(probe) || is_fexit_probe(probe)
}

pub fn probe_sim_btf(probe: &str) -> bool {
    is_kprobe_probe(probe) || is_kretprobe_probe(probe)
}

pub fn is_uprobe(probe: &str) -> bool {
    probe.starts_with("uprobe") || probe.starts_with("u:")
}

pub fn is_usdt(probe: &str) -> bool {
    probe.starts_with("usdt") || probe.starts_with("U:")
}

// fn is_uretprobe(probe: &str) -> bool {
//     probe.starts_with("uretprobe") || probe.starts_with("ur:")
// }

// fn is_user_probe(probe: &str) -> bool {
//     is_uprobe(probe) || is_uretprobe(probe) || is_usdt(probe)
// }

pub fn kprobe_to_kfunc(probe: &str) -> String {
    let mut v: Vec<&str> = probe.split(":").collect();
    if v[0] == "kprobe" {
        v[0] = "kfunc";
    } else if v[0] == "kretprobe" {
        v[0] = "kretfunc";
    }

    // TODO: use available_traces for finding proper module for function
    // For now use vmlinux
    if v.len() == 2 {
        v.push(v[1]);
        v[1] = "vmlinux"
    }

    let kfunc = v[..].join(":").to_string();

    kfunc
}

fn are_probes_compatible(probes_vec: &[String]) -> bool {
    let mut probes_iter = probes_vec.iter();

    let Some(probe) = probes_iter.next() else {
        return false;
    };

    let Some((prefix, _)) = probe.split_once(':') else {
        return false;
    };

    for next_probe in probes_iter {
        let Some((next_prefix, _)) = next_probe.split_once(':') else {
            return false;
        };

        if prefix != next_prefix {
            return false;
        }
    }

    true
}

fn probe_properties(probe: &str) -> ProbeProperties {
    let mut has_args = false;
    let mut has_retval = false;
    let mut has_arg_n = false;
    let mut use_btf = false;
    let mut use_kfunc_for_kprobe = false;

    if is_fentry_probe(probe) {
        use_btf = true;
        has_args = true;
    }

    if is_fexit_probe(probe) {
        use_btf = true;
        has_args = true;
        has_retval = true;
    }

    if is_kprobe_probe(probe) {
        use_btf = true;
        use_kfunc_for_kprobe = true;
        has_arg_n = true;
    }

    if is_kretprobe_probe(probe) {
        use_btf = true;
        use_kfunc_for_kprobe = true;
        has_retval = true;
    }

    if is_tracepoint_probe(probe) {
        has_args = true;
    }

    if is_rawtracepoint_probe(probe) {
        has_args = true;
    }

    if is_uprobe(probe) {
        // TODO: only if DWARF for binary is available
        has_args = true;
    }

    ProbeProperties {
        has_args,
        has_retval,
        has_arg_n,
        use_btf,
        use_kfunc_for_kprobe,
    }
}

fn bpftrace_get_traces_list() -> Option<String> {
    let start = Instant::now();

    let Ok(output) = bpftrace_command(&["-l"]) else {
        log_err!("Failed to get output from bpftrace command");
        return None;
    };

    let Ok(traces) = String::from_utf8(output.stdout) else {
        log_err!("Failed to convert stdout to string");
        return None;
    };

    log_dbg!(
        COMPL,
        "Got list of available traces after {:?}",
        start.elapsed()
    );

    log_vdbg!(COMPL, "List of available traces: \n{traces}\n");
    Some(traces)
}

pub fn init_available_traces() {
    let _ = AVAILABE_TRACES.get_or_init(bpftrace_get_traces_list);
}

fn expand_wildcard_probe(wildcard_probe: &str) -> Vec<String> {
    let mut result = Vec::new();

    let Some(available_traces) = AVAILABE_TRACES.get_or_init(bpftrace_get_traces_list) else {
        return Vec::new();
    };

    for trace_line in available_traces.lines() {
        if glob_match(wildcard_probe, trace_line) {
            result.push(trace_line.to_string());
        }
    }

    result
}

pub fn expand_probes(probes_vec: Vec<String>) -> Vec<String> {
    let mut new_vec = Vec::new();

    for probe in probes_vec {
        // TODO: limit number of probes ?
        if probe.contains("*") {
            new_vec.extend(expand_wildcard_probe(&probe));
        } else {
            new_vec.push(probe);
        }
    }

    new_vec
}

pub struct ProbeProperties {
    pub has_args: bool,
    pub has_retval: bool,
    pub has_arg_n: bool,
    pub use_btf: bool,
    pub use_kfunc_for_kprobe: bool,
}

pub struct Probes {
    pub probes_vec: Vec<String>,
    pub btf_probe_args: Option<(Arc<Btf>, BtfFunction)>,
    pub properties: ProbeProperties,
}

impl Probes {
    pub fn new(probes_vec: Vec<String>) -> Probes {
        let are_compatible = are_probes_compatible(&probes_vec);
        let mut probes_vec = probes_vec;

        let mut btf_probe_args = None;
        let mut properties = ProbeProperties {
            has_args: false,
            has_retval: false,
            has_arg_n: false,
            use_btf: false,
            use_kfunc_for_kprobe: false,
        };

        if are_compatible {
            let probe = probes_vec.first().unwrap();
            properties = probe_properties(probe);

            if properties.use_btf {
                probes_vec = expand_probes(probes_vec);

                if properties.use_kfunc_for_kprobe {
                    let mut kfuncs_vec: Vec<String> = Vec::new();
                    for p in &probes_vec {
                        kfuncs_vec.push(kprobe_to_kfunc(p));
                    }
                    btf_probe_args = find_common_args_by_btf(&kfuncs_vec);
                } else {
                    btf_probe_args = find_common_args_by_btf(&probes_vec);
                }
            }
        }

        Probes {
            probes_vec,
            btf_probe_args,
            properties,
        }
    }
}

pub fn available_traces() -> Option<&'static str> {
    AVAILABE_TRACES
        .get_or_init(bpftrace_get_traces_list)
        .as_deref()
}
