use glob_match::glob_match;
use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use crate::btf_rd::{btf_module_get, btf_resolve_func};
use crate::btf_rd::{Btf, BtfFunction, BtfVariable};
use crate::cmd_mod::{bpftrace_command, bpftrace_list_probes_verbose};
use crate::log_mod::{self, COMPL, HOVER};
use crate::{log_dbg, log_err, log_vdbg, WarningType, WARNINGS_TO_CLIENT};

static AVAILABE_TRACES: OnceLock<Option<String>> = OnceLock::new();

static TRACEPOINT_ARGS_MAP: OnceLock<Option<HashMap<String, Vec<String>>>> = OnceLock::new();

static RAWTRACEPOINT_ARGS_MAP: OnceLock<Option<HashMap<String, Vec<String>>>> = OnceLock::new();

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

pub fn find_kfunc_args_by_btf(kfunc: &str) -> Option<(Arc<Btf>, BtfFunction)> {
    let kfunc_vec: Vec<&str> = kfunc.split(":").collect();
    log_dbg!(COMPL, "kfunc_vec {:?}", kfunc_vec);

    if kfunc_vec.len() != 3 {
        return None;
    }

    let module = kfunc_vec[1];
    if module.is_empty() {
        return None;
    }

    let btf = btf_module_get(module)?;

    if let Some(ret) = btf_resolve_func(&btf, kfunc_vec[2]) {
        return Some((btf, ret));
    }

    None
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

fn bpftrace_init_pattern_args(pattern: &str) -> Option<HashMap<String, Vec<String>>> {
    let start = Instant::now();

    let Some(all_tracepoint_args) = bpftrace_list_probes_verbose(pattern) else {
        log_err!("Failed to get output from bpftrace -lv command");
        return None;
    };

    let mut probe_idx = 0;
    let mut probe = String::new();
    let mut args = Vec::new();
    let mut map: HashMap<String, Vec<String>> = HashMap::new();

    for line in all_tracepoint_args.lines() {
        if line.trim().is_empty() {
            continue;
        }

        if !line.chars().next().is_some_and(|c| c.is_whitespace()) {
            if probe_idx > 1 {
                map.insert(probe, args);
                args = Vec::new();
            }
            probe = line.to_string();
            probe_idx += 1;
        } else {
            args.push(line.to_string());
        }
    }

    // In the loop we did not handle last probe
    if probe_idx >= 1 {
        map.insert(probe, args);
    }

    log_dbg!(
        COMPL,
        "Got list of {} args after {:?}",
        pattern,
        start.elapsed()
    );

    Some(map)
}

fn bpftrace_init_tracepoint_args() -> Option<HashMap<String, Vec<String>>> {
    bpftrace_init_pattern_args("tracepoint:*")
}

fn bpftrace_init_rawtracepoint_args() -> Option<HashMap<String, Vec<String>>> {
    bpftrace_init_pattern_args("rawtracepoint:*")
}

pub fn init_tracepoints_args() {
    let _ = TRACEPOINT_ARGS_MAP.get_or_init(bpftrace_init_tracepoint_args);
}

pub fn init_rawtracepoints_args() {
    let _ = RAWTRACEPOINT_ARGS_MAP.get_or_init(bpftrace_init_rawtracepoint_args);
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

fn cmp_arg(a: &BtfVariable, b: &BtfVariable) -> bool {
    if a.name != b.name {
        return false;
    }

    if a.type_id != b.type_id {
        return false;
    }

    true
}

fn find_preloaded_cmd_args(probe_str: &str) -> Option<Vec<String>> {
    if is_tracepoint_probe(probe_str) {
        let mut tokens: Vec<&str> = probe_str.split(":").collect();
        if tokens[0] == "t" {
            tokens[0] = "tracepoint";
        }
        let probe = tokens.join(":");

        if let Some(map) = TRACEPOINT_ARGS_MAP.get_or_init(bpftrace_init_tracepoint_args) {
            let args = map.get(&probe).cloned();
            log_dbg!(
                COMPL,
                "Found arguments using TRACEPOINT_ARGS_MAP: {:?}",
                args
            );
            return args;
        }
    }

    if is_rawtracepoint_probe(probe_str) {
        let mut tokens: Vec<&str> = probe_str.split(":").collect();
        if tokens[0] == "rt" {
            tokens[0] = "rawtracepoint";
        }
        let probe = tokens.join(":");
        if let Some(map) = RAWTRACEPOINT_ARGS_MAP.get_or_init(bpftrace_init_rawtracepoint_args) {
            let args = map.get(&probe).cloned();
            log_dbg!(
                COMPL,
                "Found arguments using RAWTRACEPOINT_ARGS_MAP: {:?}",
                args
            );
            return args;
        }
    }

    None
}

// For multiple probes we can have common arguments that will work,
// but need having matching type and name.
pub fn find_common_args_by_cmd(probes_vec: &[String]) -> Option<Vec<String>> {
    let all_probes = probes_vec.join(",");
    log_dbg!(
        COMPL | HOVER,
        "Looking for arguments for probes {:?}",
        all_probes
    );

    // TODO: use for expanded multi probe
    // For single tracepoint, rawtracepoint, try preloaded hash map first
    if probes_vec.len() == 1 && !probes_vec[0].contains('*') {
        if let Some(args) = find_preloaded_cmd_args(&probes_vec[0]) {
            return Some(args);
        }
    }

    let all_probes_args = bpftrace_list_probes_verbose(&all_probes)?;
    log_dbg!(
        COMPL | HOVER,
        "Found arguments using command line:\n{}",
        all_probes_args
    );

    let mut probe_idx = 0;
    let mut common_args = Vec::new();
    let mut new_args = Vec::new();

    // TODO: we skip adding arguments to the PROBES_ARGS_MAP cache.

    for line in all_probes_args.lines() {
        if line.trim().is_empty() {
            continue;
        }

        // uprobe no DWARF warning
        if line.contains("WARNING: No DWARF") {
            log_dbg!(COMPL | HOVER, "No DWARF for {}", all_probes);
            WARNINGS_TO_CLIENT.push(WarningType::NoDwarf, line.to_string());

            return None;
        }

        if line.chars().next().is_some_and(|c| c.is_whitespace()) {
            if probe_idx == 1 {
                common_args.push(line);
            } else {
                new_args.push(line);
            }
        } else {
            probe_idx += 1;

            if probe_idx > 2 {
                common_args.retain(|arg| new_args.contains(arg));
                if common_args.is_empty() {
                    break;
                }
                new_args = Vec::new()
            }
        }
    }

    // In the loop we did not handle last probe
    if probe_idx >= 2 {
        common_args.retain(|arg| new_args.contains(arg));
    }

    log_dbg!(COMPL | HOVER, "Common arguments:\n{:?}", common_args);

    Some(
        common_args
            .into_iter()
            .map(|s| s.trim().to_string())
            .collect(),
    )
}

fn find_common_args_by_btf(probes_vec: &[String]) -> Option<(Arc<Btf>, BtfFunction)> {
    let mut probes_iter = probes_vec.iter();
    let probe = probes_iter.next()?;

    let btf_probe_args = find_kfunc_args_by_btf(probe);
    let (btf, mut resolved_func) = btf_probe_args?;

    let mut args_to_remove: Vec<usize> = Vec::new();

    for (i, arg) in resolved_func.args.iter().enumerate() {
        for probe in probes_vec.iter().skip(1) {
            let btf_probe_args = find_kfunc_args_by_btf(probe);
            let (next_btf, next_resolved_func) = btf_probe_args?;
            // TODO: we can support diffrent modules if arguments belong to not-split BTF
            if !Arc::ptr_eq(&btf, &next_btf) {
                return None;
            }

            let found = next_resolved_func
                .args
                .iter()
                .any(|next_arg| cmp_arg(arg, next_arg));

            if !found {
                args_to_remove.push(i);
            }
        }
    }

    let mut common_args: Vec<BtfVariable> = Vec::new();
    for (i, args) in resolved_func.args.iter().enumerate() {
        if args_to_remove.contains(&i) {
            continue;
        }

        common_args.push(args.clone());
    }

    resolved_func.args = common_args;

    Some((btf, resolved_func))
}

pub fn available_traces() -> Option<&'static str> {
    AVAILABE_TRACES
        .get_or_init(bpftrace_get_traces_list)
        .as_deref()
}
