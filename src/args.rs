use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use crate::btf_rd::{btf_module_get, btf_resolve_func};
use crate::btf_rd::{Btf, BtfFunction, BtfVariable};
use crate::cmd_mod::bpftrace_list_probes_verbose;
use crate::log_mod::{self, COMPL, HOVER};
use crate::probes::{is_rawtracepoint_probe, is_tracepoint_probe};
use crate::{log_dbg, log_err, WarningType, WARNINGS_TO_CLIENT};

static TRACEPOINT_ARGS_MAP: OnceLock<Option<HashMap<String, Vec<String>>>> = OnceLock::new();

static RAWTRACEPOINT_ARGS_MAP: OnceLock<Option<HashMap<String, Vec<String>>>> = OnceLock::new();

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

pub fn find_common_args_by_btf(probes_vec: &[String]) -> Option<(Arc<Btf>, BtfFunction)> {
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
