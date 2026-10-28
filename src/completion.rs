use json::{self, object, JsonValue};
use std::collections::HashMap;
use std::fs;
use std::sync::{Arc, OnceLock};
use tree_sitter::Node;

use crate::args;
use crate::btf_rd::{
    btf_item_to_str, btf_iterate_function_args, btf_resolve_container_members, btf_resolve_variable,
};
use crate::btf_rd::{Btf, BtfResolvedType, BtfVariable};
use crate::cmd_mod::{
    bpftrace_has_property, bpftrace_list_probes, bpftrace_major_minor_version, BpftraceProperty,
};
use crate::docs;
use crate::gen::completion::{
    bpftrace_config_variables, bpftrace_probe_providers, bpftrace_stdlib_helpers,
};
use crate::log_mod::{self, COMPL};
use crate::parser::{self, SyntaxLocation};
use crate::probes::{
    available_traces, is_rawtracepoint_probe, is_tracepoint_probe, is_uprobe, is_usdt,
    probe_sim_btf, probe_use_btf, Probes,
};
use crate::{from_utf16_position, get_document_state, unpack_text_document_info, DOCUMENTS_STATE};
use crate::{log_dbg, log_err, log_vdbg};

#[allow(unused)]
#[derive(PartialEq, Clone, Copy)]
enum CompletionItemKind {
    Text = 1,
    Method = 2,
    Function = 3,
    Constructor = 4,
    Field = 5,
    Variable = 6,
    Class = 7,
    Interface = 8,
    Module = 9,
    Property = 10,
    Unit = 11,
    Value = 12,
    Enum = 13,
    Keyword = 14,
    Snippet = 15,
    Color = 16,
    File = 17,
    Reference = 18,
    Folder = 19,
    EnumMember = 20,
    Constant = 21,
    Struct = 22,
    Event = 23,
    Operator = 24,
    TypeParameter = 25,
}

impl From<CompletionItemKind> for JsonValue {
    fn from(kind: CompletionItemKind) -> JsonValue {
        JsonValue::from(kind as u8)
    }
}

static FENTRY_KFUNC_NAME: OnceLock<&'static str> = OnceLock::new();

fn add_items_from_btf_member(btf: Arc<Btf>, member: &BtfVariable, items: &mut JsonValue) {
    if let Some(member_type) = btf_resolve_variable(&btf, member) {
        // Anonymous member with named or inserted struct/union
        if member.name.is_empty() {
            if let Some(actual_type) = member_type.actual_type {
                for m in actual_type.members.iter() {
                    add_items_from_btf_member(btf.clone(), m, items);
                }
            } else {
                log_err!(
                    "No actual_type for anonymous container, type_id {} actual_type_id {}",
                    member_type.type_id,
                    member_type.actual_type_id
                );
            }
        } else {
            let detail = btf_item_to_str(&member_type, Some(member));
            let completion = object! {
                "label": member.name.clone(),
                "kind" : 5,
                "detail" : detail,
                // "documentation" : field_type,
            };
            let _ = items.push(completion);
        }
    } else {
        let completion = object! {
            "label": member.name.clone(),
            "kind" : 5,
        };
        let _ = items.push(completion);
    }
}

fn items_from_resolved_btf(btf: Arc<Btf>, btf_tuple: &(BtfVariable, BtfResolvedType)) -> JsonValue {
    let mut items = JsonValue::new_array();

    let (_res_var, res_type) = btf_tuple;

    let Some(actual_type) = &res_type.actual_type else {
        return items;
    };

    for m in actual_type.members.iter() {
        add_items_from_btf_member(btf.clone(), m, &mut items);
    }

    items
}

fn items_from_probe_args(probe_args_iter: impl Iterator<Item = String>) -> JsonValue {
    let mut items = JsonValue::new_array();

    for arg in probe_args_iter {
        let tokens: Vec<&str> = arg.split(" ").collect();
        if tokens.len() <= 1 {
            continue;
        }
        let end = tokens.len() - 1;

        // let field = format!("args.{}", tokens[end]);
        let field = tokens[end];
        let _field_type = tokens[0..end].join(" ").to_string();
        let completion = object! {
            "label": field,
            "kind" : 5,
            "detail" : arg, //field_type.clone(),
            // TODO
            // "documentation" : field_type,
        };
        let _ = items.push(completion);
    }
    items
}

fn encode_completion_for_field_expression(
    probes: Probes,
    field_expr: Vec<&str>,
) -> Option<JsonValue> {
    if field_expr.is_empty() {
        return None;
    }
    let mut items = JsonValue::new_array();

    let probes_vec = &probes.probes_vec;
    let probe = probes_vec.first()?;

    if field_expr[0] == "args" && !probes.properties.has_args {
        return None;
    }

    if field_expr[0] == "retval" && !probes.properties.has_retval {
        return None;
    }

    if probes.btf_probe_args.is_none() {
        let probe_args = args::find_common_args_by_cmd(&[probe.to_string()]).unwrap_or_default();
        let probe_args_iter = probe_args.into_iter();

        if (field_expr.len() == 1 || field_expr.len() == 2) && field_expr[0] == "args" {
            items = items_from_probe_args(probe_args_iter)
        } else if let Some((btf, res_var, res_type)) =
            btf_resolve_container_members(probe_args_iter, field_expr)
        {
            items = items_from_resolved_btf(btf, &(res_var, res_type))
        }
    } else if let Some((btf, resolved_func)) = probes.btf_probe_args {
        if let Some(next_items) = btf_iterate_function_args(&btf, &resolved_func, field_expr) {
            items = items_from_resolved_btf(btf, &next_items)
        }
    }

    let data = object! {
        "result": {
            "isIncomplete": false,
            "items": items,
        }
    };

    Some(data)
}

// Complete args. i.e. kfunc:xe:__fini_dbm { printf("%s\n", str(args.drm->driver->name)) }
fn encode_completion_for_args_or_retval(probes: Probes, fields: &str) -> Option<JsonValue> {
    let fields_vec = parser::chain_str_to_tokens(fields);
    encode_completion_for_field_expression(probes, fields_vec)
}

fn add_block_keywords(items: &mut JsonValue) {
    let keywords = [
        "break", "continue", "else", "for", "if", "let", "offsetof", "return", "sizeof", "unroll",
        "while",
    ];

    for kw in keywords {
        let item = object! {
            "label": kw.to_owned(),
            "kind": CompletionItemKind::Keyword,
            // "detail": "TODO",
            // "documentation": "need better documentation",
        };

        let _ = items.push(item);
    }
}

fn add_block_variables(
    var_node: &Node,
    text: &str,
    line_nr: usize,
    char_nr: usize,
    items: &mut JsonValue,
    var_kind: parser::VariableKind,
) {
    let kind = match var_kind {
        parser::VariableKind::Map => "map",
        parser::VariableKind::Scratch => "scratch",
    };

    let variables = parser::find_variables(var_node, text, line_nr, char_nr, var_kind);
    log_dbg!(COMPL, "Completion: found variables {variables:?}");

    for (var, node) in variables {
        // Drop [..] for map
        // let (var_name, _) = var.split_once("[").unwrap_or((&var, ""));
        let detail = format!("{} variable", kind);

        let mut item = object! {
            "label": var.to_owned(),
            "kind": CompletionItemKind::Variable,
            "detail": detail,
        };
        if let Some(definition) = parser::node_to_variable_definition(&node, text) {
            item["documentation"] = format!("```\n{definition}\n```").into();
        }

        let _ = items.push(item);
    }
}

fn add_source_file_macros(node: &Node, text: &str, items: &mut JsonValue) {
    let macros = parser::find_source_file_macros(node, text);
    log_dbg!(COMPL, "Completion: found macros {macros:?}");

    // TODO add parameters
    for m in macros {
        let item = object! {
            "label": m.0.to_owned(),
            "kind": CompletionItemKind::Function,
            // "detail": "TODO",
            // "documentation": "need better documentation",
        };

        let _ = items.push(item);
    }
}

fn add_retval(probes: &Probes, items: &mut JsonValue) {
    let (details, docs) =
        docs::get_details_and_docs_by_btf(probes, vec!["retval"], false).unwrap_or_default();

    let retval_item = object! {
        "label": r#"retval"#,
        "kind" : CompletionItemKind::Keyword,
        "detail": details,
        "documentation" : {
            "kind": "markdown",
            "value": docs,
        },
    };
    let _ = items.push(retval_item);
}

#[allow(clippy::collapsible_else_if)]
fn add_args(probes: &Probes, items: &mut JsonValue) {
    let mut details = String::new();
    let mut docs = String::new();

    if probes.properties.use_btf {
        if let Some((btf_details, btf_docs)) =
            docs::get_details_and_docs_by_btf(probes, vec!["args"], false)
        {
            details = btf_details;
            docs = btf_docs;
        }
    } else {
        if let Some((cmd_details, cmd_docs)) =
            docs::get_details_and_docs_by_cmd(probes, vec!["args"], false)
        {
            details = cmd_details;
            docs = cmd_docs;
        }
    }

    let completion_args = object! {
        "label": "args",
        "kind" : CompletionItemKind::Keyword,
        "detail" : details,
        "documentation" : {
            "kind": "markdown",
            "value": docs,
        },
    };

    let _ = items.push(completion_args);
}

fn add_arg_n(probes: &Probes, items: &mut JsonValue) {
    let Some((btf, resolved_func)) = probes.btf_probe_args.as_ref() else {
        return;
    };

    // TODO: add documentation

    for (i, var) in resolved_func.args.iter().enumerate() {
        let detail = if let Some(res_type) = btf_resolve_variable(btf, var) {
            let arg_i_type = btf_item_to_str(&res_type, None);
            let cast = format!("(({})arg{})", arg_i_type, i);

            let snippet = object! {
                "label": format!("arg{}", i),
                "kind" : CompletionItemKind::Snippet,
                "detail" : cast.clone(),
                "insertText": cast,
            };
            let _ = items.push(snippet);

            let mut arg_var = var.clone();
            arg_var.name = format!("arg{}", i);
            btf_item_to_str(&res_type, Some(&arg_var))
        } else {
            var.name.clone()
        };

        let arg_i = object! {
            "label": format!("arg{}", i),
            "kind" : CompletionItemKind::Keyword,
            "detail" : detail,
        //     "documentation" : {
        //         "kind": "markdown",
        //         "value": docs,
        //     },
        };

        let _ = items.push(arg_i);
    }
}

// Special args and retval builtin
fn add_args_and_retval_keywords(probes: &Probes, items: &mut JsonValue) {
    if probes.probes_vec.is_empty() {
        return;
    }

    if probes.properties.has_retval {
        add_retval(probes, items);
    }

    if probes.properties.has_args {
        add_args(probes, items);
    }

    if probes.properties.has_arg_n {
        add_arg_n(probes, items);
    }
}

fn add_completion_items_for_block(
    text: &str,
    node: &Node,
    line_nr: usize,
    char_nr: usize,
    probes_opt: Option<Probes>,
    items: &mut JsonValue,
) {
    if let Some((var_type, var_node)) = parser::is_location_variable(text, node, line_nr, char_nr) {
        add_block_variables(&var_node, text, line_nr, char_nr, items, var_type)
    } else {
        if let Some(probes) = probes_opt {
            add_args_and_retval_keywords(&probes, items);
        }
        bpftrace_stdlib_helpers(items, bpftrace_major_minor_version());
        add_block_keywords(items);
        add_source_file_macros(node, text, items);
    }
}

fn encode_completion_for_action(
    text: &str,
    node: &Node,
    line_nr: usize,
    char_nr: usize,
    probes: Probes,
) -> Option<JsonValue> {
    log_dbg!(COMPL, "Complete for action block");

    // TODO preload btf module
    let mut items = JsonValue::new_array();

    add_completion_items_for_block(text, node, line_nr, char_nr, Some(probes), &mut items);

    let data = object! {
        "result": {
            "isIncomplete": true,
            "items": items,
        }
    };

    Some(data)
}

fn encode_completion_for_macro(
    text: &str,
    node: &Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<JsonValue> {
    log_dbg!(COMPL, "Complete for macro");

    let mut items = JsonValue::new_array();

    add_completion_items_for_block(text, node, line_nr, char_nr, None, &mut items);

    let data = object! {
        "result": {
            "isIncomplete": true,
            "items": items,
        }
    };

    Some(data)
}

fn encode_completion_for_probe_list(
    prefix: &str,
    line_str: &str,
    short_prefix: Option<&str>,
) -> Option<JsonValue> {
    log_dbg!(
        COMPL,
        "Check completion for prefix '{}' with short name {:?}",
        prefix,
        short_prefix
    );

    // TOOD separate traces for each type i.e. kprobe, tracepoint
    let Some(available_traces) = available_traces() else {
        return Some(encode_no_completion());
    };

    let mut items = JsonValue::new_array();

    let max_count = 10_000;
    let mut count = max_count;
    let mut duplicates: HashMap<String, u32> = HashMap::new();

    let mut line_tokens: Vec<&str> = line_str.split(":").collect();

    if let Some(short_name) = short_prefix {
        assert!(line_str.trim().starts_with(short_name));
        line_tokens[0] = prefix;
    }

    if line_tokens[0] == "kfunc"
        || line_tokens[0] == "kretfunc"
        || line_tokens[0] == "fentry"
        || line_tokens[0] == "fexit"
    {
        let fentry_kfunc_name = FENTRY_KFUNC_NAME.get_or_init(|| {
            if available_traces.contains("\nfentry") {
                "fentry"
            } else {
                "kfunc"
            }
        });
        line_tokens[0] = fentry_kfunc_name;
    } else if line_tokens[0] == "kretprobe" {
        line_tokens[0] = "kprobe";
    }

    let search_line = line_tokens.join(":");
    log_dbg!(COMPL, "Searching for line '{}'", search_line);

    for trace_line in available_traces.lines() {
        if trace_line.trim().starts_with(search_line.trim()) {
            //TODO: save matched tokens ans skip duplicate lines here
            // log_vdbg!(COMPL, "Found available traces line '{}'", trace_line);

            let trace_tokens: Vec<&str> = trace_line.split(":").collect();

            let mut match_tokens = 0;
            for i in 0..std::cmp::min(trace_tokens.len(), line_tokens.len()) {
                if trace_tokens[i] != line_tokens[i] {
                    break;
                }
                match_tokens += 1;
            }

            if trace_tokens.len() > match_tokens {
                let label = trace_tokens[match_tokens];

                match duplicates.get(label) {
                    None => duplicates.insert(label.to_string(), 1),
                    Some(_) => continue,
                };

                let item = if match_tokens + 1 == trace_tokens.len() {
                    // We could be using Function for fentry, kprobe, ...
                    // but this can give annoying client behavior - adding extra '()'
                    // Using InsertText does not prevent this annoyance
                    object! {
                        "label": label,
                        "kind": CompletionItemKind::Event,
                        "data": trace_line,
                    }
                } else {
                    object! {
                        "label": label,
                        "kind": CompletionItemKind::Module,
                    }
                };

                log_vdbg!(COMPL, "Adding complete item: {}", item);

                let _ = items.push(item);
                count -= 1;
                if count < 0 {
                    break;
                }
            }
        }
    }

    let data = object! {
        "result": {
            "isIncomplete": count < 0,
            "items": items,
        }
    };

    Some(data)
}

fn encode_completion_for_file_path(path: &str) -> Option<JsonValue> {
    let mut head;
    let mut tail = "";

    if path.is_empty() {
        head = ".";
    } else if path == "/" {
        head = "/"
    } else {
        (head, tail) = path.rsplit_once("/").unwrap_or((path, ""));

        if head.is_empty() {
            if path.starts_with('/') {
                head = "/";
            } else {
                head = ".";
            }
        }
    }

    let dir = &format!("{}/", head);

    log_dbg!(COMPL, "Listing files in '{}' with '{}'", dir, tail);

    let entries = fs::read_dir(dir).ok()?;
    let mut items = JsonValue::new_array();

    for entry in entries {
        let Ok(path) = entry.map(|e| e.path()) else {
            continue;
        };

        let Some(path_str) = path.to_str() else {
            continue;
        };

        // TODO symlinks,
        if path.is_dir() || path.is_file() {
            // TOOD check if file is executable ?

            let base_name = path_str.strip_prefix(dir).unwrap_or(path_str);

            let item = if path.is_dir() {
                object! {
                    "label": format!("{}/", base_name),
                    "kind": CompletionItemKind::Folder
                }
            } else {
                object! {
                    "label" : base_name,
                    "kind": CompletionItemKind::File
                }
            };

            let _ = items.push(item);
        }
    }

    let data = object! {
        "result": {
            "isIncomplete": true,
            "items": items,
        }
    };

    Some(data)
}

fn encode_completion_for_user_space_functions(line_tokens: Vec<&str>) -> Option<JsonValue> {
    assert!(line_tokens.len() > 2);

    let num_tokens = if line_tokens.len() > 3 { 3 } else { 2 };
    let probe_match = line_tokens[0..num_tokens].join(":") + ":*";
    log_dbg!(COMPL, "Looking for completion items for '{}'", probe_match);

    let matched_probes = bpftrace_list_probes(&probe_match, true)?;
    let mut duplicates: HashMap<String, u32> = HashMap::new();

    let mut items = JsonValue::new_array();

    for probe_line in matched_probes.lines() {
        let probe_tokens: Vec<&str> = probe_line.split(":").collect();

        let mut match_tokens = 0;
        for i in 0..std::cmp::min(probe_tokens.len(), line_tokens.len()) {
            if probe_tokens[i] != line_tokens[i] {
                break;
            }
            match_tokens += 1;
        }

        if probe_tokens.len() <= match_tokens {
            continue;
        }
        let label = probe_tokens[match_tokens];

        match duplicates.get(label) {
            None => duplicates.insert(label.to_string(), 1),
            Some(_) => continue,
        };

        let mut item = object! {
            "label": label,
        };

        if match_tokens + 1 == probe_tokens.len() {
            item["kind"] = CompletionItemKind::Event.into();
            item["data"] = probe_line.trim().into();
        } else {
            item["kind"] = CompletionItemKind::Module.into();
        }

        log_vdbg!(COMPL, "Adding complete item: {}", item);

        let _ = items.push(item);
    }

    let data = object! {
        "result": {
            "isIncomplete": false,
            "items": items,
        }
    };

    Some(data)
}

fn encode_completion_for_user_probes(
    prefix: &str,
    line_str: &str,
    short_prefix: Option<&str>,
) -> Option<JsonValue> {
    log_dbg!(
        COMPL,
        "Check completion for prefix '{}' with short name {:?}",
        prefix,
        short_prefix
    );

    let line_tokens: Vec<&str> = line_str.split(":").collect();
    log_dbg!(
        COMPL,
        "line_tokens {:?} len {}",
        line_tokens,
        line_tokens.len()
    );

    if line_tokens.len() == 2 {
        return encode_completion_for_file_path(line_tokens[1]);
    } else if line_tokens.len() >= 3 {
        return encode_completion_for_user_space_functions(line_tokens);
    }

    None
}

pub fn add_empty_line_keywords(items: &mut JsonValue) {
    // TODO "config" is only allowed in preamble
    let keywords = ["config", "import", "macro", "let"];

    for kw in keywords {
        let item = object! {
            "label": kw.to_owned(),
            "kind": CompletionItemKind::Keyword,
            // "detail": "TODO",
            // "documentation": "need better documentation",
        };

        let _ = items.push(item);
    }
}

fn add_map_declarations(items: &mut JsonValue) {
    let item = object! {
        "label": r#"hash"#,
        "kind" : CompletionItemKind::Function
    };
    let _ = items.push(item);

    let item = object! {
        "label": r#"lruhash"#,
        "kind" : CompletionItemKind::Function
    };
    let _ = items.push(item);

    let item = object! {
        "label": r#"percpuhash"#,
        "kind" : CompletionItemKind::Function
    };
    let _ = items.push(item);

    let item = object! {
        "label": r#"percpulruhash"#,
        "kind" : CompletionItemKind::Function
    };
    let _ = items.push(item);
}

fn add_small_case_builtins(items: &mut JsonValue) {
    let item = object! {
        "label": r#"begin"#,
        "kind" : 8,
        "detail": r#"begin
    "#,
        "documentation" : {
            "kind": "markdown",
            "value": r#"Built-in event

Special built-in event provided by the bpftrace runtime.
`begin` is triggered before all other probes are attached.
"#,
        },
    };
    let _ = items.push(item);

    let item = object! {
        "label": r#"end"#,
        "kind" : 8,
        "detail": r#"end
    "#,
        "documentation" : {
            "kind": "markdown",
            "value": r#"Built-in event

Special built-in event provided by the bpftrace runtime.
`end` is triggered after all other probes are detached.
Each of these probes can be used any number of times, and they will be executed in the same order they are declared.

#### Notes
Specifying an `end` probe doesn’t override the printing of 'non-empty' maps at exit.
To prevent printing all used maps need be cleared in the `end` probe:

#### Example
```
end {
    clear(@map1);
    clear(@map2);
}
```

"#,
        },
    };
    let _ = items.push(item);
}

fn encode_completion_for_new_line(line_str: &str) -> JsonValue {
    let mut items = JsonValue::new_array();

    let line = line_str.trim();

    // Do not complete when entering macro name
    if line.starts_with("macro") {
        return encode_no_completion();
    // I.e. let @map = percpuhash()
    } else if line.starts_with("let") && line.contains("=") {
        add_map_declarations(&mut items);
    // Do not complete after space or some special symbol/number, only for single word
    } else if line.is_empty() || line.chars().all(|c| c.is_alphabetic()) {
        bpftrace_probe_providers(&mut items, bpftrace_major_minor_version());
        add_empty_line_keywords(&mut items);

        if bpftrace_has_property(BpftraceProperty::CaseInsensitive) {
            add_small_case_builtins(&mut items);
        }
    }

    let data = object! {
        "result": {
            "isIncomplete": true,
            "items": items,
        }
    };

    data
}

fn encode_no_completion() -> JsonValue {
    let items = JsonValue::new_array();
    let empty_data = object! {
        "result": {
            "isIncomplete": false,
            "items": items,
        }
    };

    empty_data
}

fn encode_completion_for_probe_provider(
    line_str: &str,
    providers: Vec<(&str, Option<&str>)>,
    encode_completion: impl Fn(&str, &str, Option<&str>) -> Option<JsonValue>,
) -> Option<JsonValue> {
    if !line_str.trim().is_empty() {
        for prefix in providers.iter() {
            if !line_str.trim().starts_with(prefix.0) {
                continue;
            }
            if let Some(data) = encode_completion(prefix.0, line_str, None) {
                return Some(data);
            }
        }

        for prefix in providers.iter() {
            let Some(short_prefix) = prefix.1 else {
                continue;
            };

            if line_str.trim().len() <= short_prefix.len()
                || line_str.trim().chars().nth(short_prefix.len()) != Some(':')
            {
                continue;
            }

            if !line_str.trim().starts_with(short_prefix) {
                continue;
            }

            if let Some(data) = encode_completion(prefix.0, line_str, prefix.1) {
                return Some(data);
            }
        }
    }

    None
}

fn encode_completion_for_line(line_str: &str) -> JsonValue {
    let mut providers = vec![
        ("test", None),
        ("bench", None),
        ("self", None),
        ("interval", Some("i")),
        ("profile", Some("p")),
        ("iter", Some("it")),
        ("hardware", Some("h")),
        ("software", Some("s")),
        ("rawtracepoint", Some("rt")),
        ("tracepoint", Some("t")),
        ("kprobe", Some("k")),
        ("kretprobe", Some("kr")),
        ("kfunc", None),
        ("kretfunc", None),
    ];

    if bpftrace_has_property(BpftraceProperty::FentryFexit) {
        let fentry = ("fentry", Some("f"));
        let fexit = ("fexit", Some("fr"));

        providers.push(fentry);
        providers.push(fexit);
    }

    if let Some(data) =
        encode_completion_for_probe_provider(line_str, providers, encode_completion_for_probe_list)
    {
        return data;
    }

    let providers = vec![
        ("uprobe", Some("u")),
        ("uretprobe", Some("ur")),
        ("usdt", Some("U")),
    ];

    if let Some(data) =
        encode_completion_for_probe_provider(line_str, providers, encode_completion_for_user_probes)
    {
        return data;
    }

    encode_completion_for_new_line(line_str)
}

fn encode_completion_for_config_block() -> JsonValue {
    let mut items = JsonValue::new_array();

    bpftrace_config_variables(&mut items, bpftrace_major_minor_version());

    object! {
        "result": {
            "isIncomplete": false,
            "items": items,
        }
    }
}

#[allow(clippy::collapsible_else_if)]
pub fn encode_completion(content: JsonValue) -> JsonValue {
    let (uri, line_nr, char_nr) = unpack_text_document_info(content);

    let Some(text_doc) = DOCUMENTS_STATE.get(&uri) else {
        return encode_no_completion();
    };

    // For completion look at place before the cursor.
    let char_nr = char_nr.saturating_sub(1);
    let char_nr = from_utf16_position(&text_doc.text, line_nr, char_nr);

    let (text, loc, node, line_str) =
        get_document_state!(text_doc, line_nr, char_nr, encode_no_completion(), COMPL);

    if loc == SyntaxLocation::Action || loc == SyntaxLocation::Predicate {
        let probes_vec = parser::find_probes_for_node(&node, text);
        log_dbg!(COMPL, "Action completion for probes vec {:?}", probes_vec);

        let probes = Probes::new(probes_vec);

        if let Some(args) = parser::is_location_args_keyword(&node, line_nr, char_nr)
            .and_then(|node| node.utf8_text(text.as_bytes()).ok())
        {
            log_dbg!(COMPL, "Completion for args: '{}'", args);
            if let Some(data) = encode_completion_for_field_expression(probes, vec![args]) {
                return data;
            }
        } else if let Some(retval) = parser::is_location_retval_identifier(&node, line_nr, char_nr)
            .and_then(|node| node.utf8_text(text.as_bytes()).ok())
        {
            log_dbg!(COMPL, "Completion for retval: '{}'", retval);
            if let Some(data) = encode_completion_for_field_expression(probes, vec![retval]) {
                return data;
            }
        // TODO: make this work better for when there are parse errors
        // } else if let Some((field_expr, last_field)) =
        //     parser::is_location_field_expression(&node, line_nr, char_nr)
        // {
        //     let vec = parser::field_expr_to_vec(text, &field_expr, &last_field);
        //     log_dbg!(COMPL, "Completion for field expression: '{:?}'", vec);
        //     if let Some(data) = encode_completion_for_field_expression(probes, vec) {
        //         return data;
        //     }
        //     // We do not handle errors on syntax tree well yet, fallback to to manual
        //     // string parsing if not detect field expression
        } else if let Some(args) = parser::is_args_or_retval(line_str, char_nr) {
            log_dbg!(COMPL, "Completion for args_or_retval: '{:?}'", args);
            if let Some(data) = encode_completion_for_args_or_retval(probes, &args) {
                return data;
            }
        } else {
            if let Some(data) = encode_completion_for_action(text, &node, line_nr, char_nr, probes)
            {
                return data;
            }
        }
    }

    if loc == SyntaxLocation::SourceFile && node.has_error() {
        if let Some(args) = parser::is_args_or_retval(line_str, char_nr) {
            log_dbg!(
                COMPL,
                "Parse error completion for args_or_retval: '{:?}'",
                args
            );
            if let Some(error_node) = parser::find_error_location(text, &node, line_nr, char_nr) {
                let probes_vec = parser::find_probes_vec_for_error(&error_node, text);
                log_dbg!(
                    COMPL,
                    "Parse error completion for probes vec {:?}",
                    probes_vec
                );
                let probes = Probes::new(probes_vec);

                if let Some(data) = encode_completion_for_args_or_retval(probes, &args) {
                    return data;
                }
            }
        }
    }

    if loc == SyntaxLocation::MacroDefinition {
        if let Some(data) = parser::is_location_macro_body(&node, line_nr, char_nr)
            .and_then(|block_node| encode_completion_for_macro(text, &block_node, line_nr, char_nr))
        {
            return data;
        }
    }

    if loc == SyntaxLocation::SourceFile || loc == SyntaxLocation::ProbesList {
        let up_to_char = char_nr.saturating_add(1);
        let line_head = if let Some(splited_line) = line_str.split_at_checked(up_to_char) {
            let (head, _tail) = splited_line;
            head
        } else {
            line_str
        };

        log_dbg!(COMPL, "Complete for line head: '{line_head}'");
        return encode_completion_for_line(line_head);
    }

    if loc == SyntaxLocation::ConfigBlock {
        return encode_completion_for_config_block();
    }

    encode_no_completion()
}

pub fn encode_completion_resolve(content: JsonValue) -> JsonValue {
    let mut params = content["params"].clone();
    log_dbg!(
        COMPL,
        "Completion resolve for '{}' with data '{}'",
        params["label"],
        params["data"]
    );

    if !params.is_null() {
        if let Some(probe) = params["data"].as_str() {
            if probe_use_btf(probe) || probe_sim_btf(probe) {
                if let Some((_btf, resolved_func)) = args::find_kfunc_args_by_btf(probe) {
                    params["detail"] = resolved_func.full_name.into();
                }
            } else if is_tracepoint_probe(probe) || is_rawtracepoint_probe(probe) || is_usdt(probe)
            {
                if let Some(args) = args::find_common_args_by_cmd(&[probe.to_string()]) {
                    let docs = docs::args_to_block(&args, false);
                    params["detail"] = probe.into();
                    params["documentation"] = docs.into();
                }
            } else if is_uprobe(probe)
            /* TODO || is_uretprobe(probe) */
            {
                if let Some(func_name) = params["label"].as_str() {
                    if let Some(args) = args::find_common_args_by_cmd(&[probe.to_string()]) {
                        let proto = docs::args_to_func_proto(func_name, &args);
                        params["detail"] = proto.into();
                    }
                }
            }
        }
    }

    let data = object! {
        "result": params,
    };

    data
}

#[allow(clippy::len_zero)]
#[allow(dead_code, unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_mod::{
        bpftrace_command, bpftrace_list_probes_verbose, init_bpftrace,
        setup_bpftrace_root_permissions,
    };
    use crate::probes::kprobe_to_kfunc;
    use crate::test_support::document_content_setup;
    use std::process::Command;
    use std::sync::{LazyLock, Mutex};

    static PROBES_ARGS_MAP: LazyLock<Mutex<HashMap<String, String>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn preload_probes_args(probes_vec: &[&str]) {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let probes_str = probes_vec.join(",");

        let Some(all_probes_args) = bpftrace_list_probes_verbose(&probes_str) else {
            println!(
                "bpfrace did not provide arguments for probes '{}'",
                probes_str
            );
            return;
        };

        if all_probes_args.is_empty() {
            println!("Empty arguments for probe {}", probes_str);
            return;
        }

        let mut probe = String::new();
        let mut probe_args = String::new();

        for line in all_probes_args.lines() {
            if line.starts_with(" ") {
                probe_args.push_str(line);
                probe_args.push('\n');
            } else {
                if !probe.is_empty() {
                    let mut probes_args_map = PROBES_ARGS_MAP.lock().unwrap();
                    probes_args_map.insert(probe, probe_args);
                }
                probe = line.to_string();
                probe_args = line.to_string();
                probe_args.push('\n');
            }
        }

        if !probe.is_empty() {
            let mut probes_args_map = PROBES_ARGS_MAP.lock().unwrap();
            probes_args_map.insert(probe, probe_args);
        }
    }

    fn find_probe_args_by_command(probe: &str) -> String {
        if probe.is_empty() {
            return "".to_string();
        }

        // Use kfunc for getting arguments, kprobe/kretprobe does not work
        // TODO: above can not to be true on newer bpftrace versions
        let probe = if probe_sim_btf(probe) {
            kprobe_to_kfunc(probe)
        } else {
            probe.to_string()
        };

        let mut probes_args_map = PROBES_ARGS_MAP.lock().unwrap();

        let mut probe_args = "".to_string();
        if let Some(args) = probes_args_map.get(&probe) {
            probe_args = args.to_string();
        } else if let Ok(output) = bpftrace_command(&["-l", "-v", &probe]) {
            if let Ok(stdout_probe_args) = String::from_utf8(output.stdout) {
                probe_args = stdout_probe_args.clone();
            }
            if let Ok(stderr_probe_args) = String::from_utf8(output.stderr) {
                probe_args.push_str(&stderr_probe_args);
            }

            if probe_args.is_empty() {
                log_err!("No arguments for probe {}", probe);
            } else {
                probes_args_map.insert(probe.clone(), probe_args.clone());
                log_dbg!(COMPL, "Found arguments using command line\n{}", probe_args);
            }
        }

        probe_args
    }

    fn compare_btf_and_cmd(s: &str) {
        let args_by_cmd = find_probe_args_by_command(s);
        let args_by_btf = args::find_kfunc_args_by_btf(s);

        let Some((btf, resolved_btf)) = args_by_btf else {
            println!("{s}");
            panic!();
        };

        // for (i, c) in resolved_btf.args.iter().enumerate() {
        //     println!("{i}: '{}'", c.name /* btf_item_to_str(c, ).trim()*/);
        // }

        let mut n = 0;
        for (i, arg) in args_by_cmd.lines().enumerate() {
            if i == 0 {
                // fentry vs kfunc, the rest after colon must be the same
                assert!(arg.split_once(":").map(|x| x.1) == s.split_once(":").map(|x| x.1));
                continue;
            }

            if arg.ends_with("retval") {
                continue;
            }

            assert!(resolved_btf.args.len() > i - 1);

            let btf_var = &resolved_btf.args[i - 1];
            let btf_type = btf_resolve_variable(&btf, btf_var).unwrap();
            let a = arg.trim().replace("* ", "*");
            assert_eq!(a, btf_item_to_str(&btf_type, Some(btf_var)));
            n += 1;
        }

        assert!(resolved_btf.args.len() == n);
    }

    fn check_completion_resutls_negative(result: &JsonValue, values: Vec<&str>) {
        let labels: Vec<_> = result["result"]["items"]
            .members()
            .map(|item| item["label"].to_string())
            .collect();

        for val in values.iter() {
            assert!(
                !labels.contains(&val.to_string()),
                "'{val}' present in completion results: {:?}",
                labels
            );
        }
    }

    fn check_completion_resutls(result: JsonValue, values: Vec<&str>) {
        let labels: Vec<_> = result["result"]["items"]
            .members()
            .map(|item| item["label"].to_string())
            .collect();

        for val in values.iter() {
            assert!(
                labels.contains(&val.to_string()),
                "'{val}' missed in completion results: {:?}",
                labels
            );
        }
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_find_probe_args() {
        let mut probes_vec = vec![
            "kfunc:vmlinux:posixtimer_free_timer",
            "kfunc:vmlinux:vfs_open",
        ];

        probes_vec.push("kfunc:vmlinux:acpi_unregister_gsi");
        probes_vec.push("kfunc:vmlinux:acpi_register_gsi");

        preload_probes_args(&probes_vec);
        for p in probes_vec {
            compare_btf_and_cmd(p);
        }
    }

    #[test]
    fn test_variable_completion_definitions() {
        for (body, label, definition) in [
            ("$x = 1", "$x", "$x = 1"),
            (
                "$skb = (struct skb *) arg0",
                "$skb",
                "$skb = (struct skb *) arg0",
            ),
            ("let $x: uint8 = 222", "$x", "let $x: uint8 = 222"),
            ("$x = $y + $z", "$x", "$x = $y + $z"),
            ("@map[pid] = true", "@map[]", "@map[pid] = true"),
            ("$x = 1; $x = 2", "$x", "$x = 1"),
        ] {
            let marker = if label.starts_with('$') {
                "$cursor"
            } else {
                "@cursor"
            };
            let text = format!("begin {{ {body}; {marker}; }}");
            let column = text.find(marker).unwrap() + 1;
            let content = document_content_setup(&text, 0, column);
            let result = encode_completion(content);
            let item = result["result"]["items"]
                .members()
                .find(|item| item["label"] == label)
                .unwrap();
            assert!(item["documentation"].as_str().unwrap().contains(definition));
        }

        let text = "begin { for $i : 0..10 { $cursor; } }";
        let content = document_content_setup(text, 0, text.find("$cursor").unwrap() + 1);
        let result = encode_completion(content);
        let item = result["result"]["items"]
            .members()
            .find(|item| item["label"] == "$i")
            .unwrap();
        assert!(item["documentation"].is_null());
    }

    #[test]
    fn test_scratch_variable_completion_in_predicate() {
        let text = "interval:s:1 / $x / { $x = 1; }";
        let char_nr = text.find("$x").unwrap() + "$x".len();
        let json_content = document_content_setup(text, 0, char_nr);

        let result = encode_completion(json_content);

        // Scratch variables from the action are not in scope in the predicate.
        assert_eq!(result["result"]["items"], JsonValue::new_array());
    }

    #[test]
    fn test_action_completion_for_do_sys_open() {
        let text = "kprobe:do_sys_open { ";
        let json_content = document_content_setup(text, 0, text.len() - 1);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let functions = vec![
            "bswap", "buf", "printf", "print", "str", "signal", "strncmp", "cpu", "curtask",
            "exit", "count", "avg", "kptr", "uptr",
        ];
        check_completion_resutls(result, functions);
    }

    #[test]
    fn test_probes_completion_for_new_line() {
        let json_content = document_content_setup("", 0, 0);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let prefixes = vec![
            "iter",
            "hardware",
            "tracepoint",
            "kprobe",
            "kretprobe",
            "software",
            "rawtracepoint",
            "kfunc",
            "kretfunc",
        ];
        check_completion_resutls(result, prefixes);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_probes_completion_for_vmlinux() {
        assert_eq!(init_bpftrace(None), Ok(()));
        for text in vec!["kfunc:v", "kretfunc:v", "fentry:v", "fexit:v"].into_iter() {
            let json_content = document_content_setup(text, 0, text.len());

            let result = encode_completion(json_content);
            assert!(result["result"]["items"].len() > 0);

            check_completion_resutls(result, vec!["vmlinux"]);
        }
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_probes_completion_for_modules() {
        assert_eq!(init_bpftrace(None), Ok(()));
        for text in vec!["kfunc:", "kretfunc:", "fentry:", "fexit:"].into_iter() {
            let json_content = document_content_setup(text, 0, text.len());

            let result = encode_completion(json_content);
            assert!(result["result"]["items"].len() > 0);

            let mut modules = Vec::new();

            let output = Command::new("lsmod").output().unwrap();
            let mod_list = String::from_utf8(output.stdout).unwrap();
            let mut count = 0;
            for line in mod_list.lines() {
                if count == 0 {
                    continue;
                }

                let module = line.split_whitespace().next().unwrap();
                modules.push(module);

                // encode completion limitation is 200 entries
                count += 1;
                if count > 200 {
                    break;
                }
            }

            check_completion_resutls(result, modules);
        }
    }

    #[test]
    fn test_probes_completion_for_vfs_functions() {
        let text = "kfunc:vmlinux:vfs_";
        let json_content = document_content_setup(text, 0, text.len() - 1);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let functions = vec![
            "vfs_open",
            "vfs_read",
            "vfs_write",
            "vfs_fstatat",
            "vfs_mknod",
            "vfs_llseek",
            "vfs_readv",
            "vfs_writev",
            "vfs_truncate",
            "vfs_unlink",
        ];
        check_completion_resutls(result, functions);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_completion_for_uprobe_files() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));
        let text = "uprobe:target/debug/ ";

        let json_content = document_content_setup(text, 0, text.len() - 1);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let functions = vec!["build/", "deps/", "examples/", "bpftrace-ls"];
        check_completion_resutls(result, functions);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_completion_for_uprobe_functions() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));
        let text = "uprobe:target/debug/bpftrace-ls: ";

        let json_content = document_content_setup(text, 0, text.len() - 1);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let functions = vec![
            "main",
            "__rust_try",
            "ts_language_abi_version",
            "ts_query_new",
        ];
        check_completion_resutls(result, functions);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_completion_for_uprobe_args() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));
        let text = "u:target/debug/bpftrace-ls:ts_query_new { args. ";

        let json_content = document_content_setup(text, 0, text.len() - 1);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let functions = vec!["language", "source", "source_len", "error_type"];
        check_completion_resutls(result, functions);
    }

    #[test]
    fn test_args_completion_for_hrtimer_base() {
        let text = r#"kfunc:vmlinux:posix_timer_fn { printf("%d\n", args.timer->base-> ); }"#;
        let json_content = document_content_setup(text, 0, text.len() - 5);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec![
            "cpu_base", "index", "clockid", "seq", "running", "active", "offset",
        ];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_args_completion_for_posix_cpu_clock_get() {
        let text = r#"fexit:vmlinux:posix_cpu_clock_get { args. }"#;
        let json_content = document_content_setup(text, 0, text.len() - 2);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec!["tp", "clock"];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_args_completion_posix_acl_alloc_retval() {
        let text = r#"fexit:vmlinux:posix_acl_alloc { retval-> }"#;
        let json_content = document_content_setup(text, 0, text.len() - 2);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec!["a_entries"];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_args_completion_find_ge_pid_retval() {
        let text = r#"fexit:vmlinux:find_ge_pid { retval->rcu }"#;
        let json_content = document_content_setup(text, 0, text.len() - 2);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec!["func"];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_args_completion_find_ge_pid_retval_anonymous() {
        let text = r#"fexit:vmlinux:find_ge_pid { retval->attr-> }"#;
        let json_content = document_content_setup(text, 0, text.len() - 2);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec![
            "attr_mask",
            "xattrs",
            "cgroupid",
            "exit_code",
            "coredump_mask",
        ];
        check_completion_resutls(result, fields);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_args_completion_for_wildcard_tracepoint() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r#"tracepoint:syscalls:sys_enter_opena*, { args."#;
        let json_content = document_content_setup(text, 0, text.len());

        let result = encode_completion(json_content);
        assert_eq!(result["result"]["items"].len(), 4);

        let fields = vec!["how", "mode", "usize"];
        check_completion_resutls_negative(&result, fields);

        let fields = vec!["dfd", "filename", "__syscall_nr"];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_modules_completion_for_short_tracepoint() {
        let text = r#"t:"#;
        let json_content = document_content_setup(text, 0, text.len());

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec![
            "vmalloc",
            "syscalls",
            "timer",
            "notifier",
            "workqueue",
            "writeback",
            "dma",
        ];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_args_completion_for_two_vfs_write_probes() {
        let text = r#" fentry:vmlinux:vfs_write, fentry:vmlinux:vfs_writev { args. }"#;
        let json_content = document_content_setup(text, 0, text.len() - 2);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() == 2);

        let fields = vec!["file", "pos"];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_args_completion_for_vfs_probes_when_parse_error() {
        let text = r#"
fentry:vmlinux:vfs_read,
fentry:vmlinux:vfs_readv,
fentry:vmlinux:vfs_write,
fentry:vmlinux:vfs_writev,
{
  printf("%p\n", args.
"#;
        let json_content = document_content_setup(text, 6, 22);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() == 2);

        let fields = vec!["file", "pos"];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_modules_completion_for_short_clk() {
        let text = r#"t:clk:"#;
        let json_content = document_content_setup(text, 0, text.len());

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec![
            "clk_disable",
            "clk_disable_complete",
            "clk_enable",
            "clk_enable_complete",
            "clk_prepare",
            "clk_prepare_complete",
            "clk_set_max_rate",
            "clk_set_min_rate",
        ];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_args_completion_for_struct_with_bitfield() {
        let text = r#"
fentry:vmlinux:async_schedule_node_domain {
  print(args.domain->
}
"#;
        let json_content = document_content_setup(text, 2, 21);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() == 2);

        assert_eq!(
            result["result"]["items"][1]["detail"].as_str(),
            Some("unsigned int registered:1")
        );
    }

    #[test]
    fn test_kretprobe_retval_completion() {
        let text = r#"
kretprobe:vmlinux:posix_timer_fn {
  print(retv
}
"#;
        let json_content = document_content_setup(text, 2, 14);

        let result = encode_completion(json_content);

        check_completion_resutls(result, vec!["retval"]);
    }

    #[test]
    fn test_kprobe_arg_n_completion() {
        let text = r#"
k:posix_acl_from_xattr {
  print(a
}
"#;
        let json_content = document_content_setup(text, 2, 10);

        let result = encode_completion(json_content);

        check_completion_resutls_negative(&result, vec!["arg4", "arg5", "arg9", "args", "retval"]);
        check_completion_resutls(result, vec!["arg0", "arg1", "arg2"]);
    }

    #[test]
    fn test_config_variables_completion() {
        let text = r#"config = {  }"#;
        let json_content = document_content_setup(text, 0, text.len() - 2);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec![
            "stack_mode",
            "missing_probes",
            "log_size",
            "license",
            "max_probes",
            "print_maps_on_exit",
        ];
        check_completion_resutls(result, fields);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_cma_tracepoint_page_completion() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r#"
tracepoint:cma:cma_release {
  print(args.page->
}
"#;
        let json_content = document_content_setup(text, 2, 19);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec![
            "pp",
            "pp_magic",
            "lru",
            "flags",
            "mapping",
            "callback_head",
            "page_type",
            "private",
            "_refcount",
        ];
        check_completion_resutls(result.clone(), fields);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[ignore] // Works on bpftrace version >= 0.25
    #[test]
    fn test_rawtracepoint_args_completion() {
        assert_eq!(init_bpftrace(None), Ok(()));

        let (major, minor) = bpftrace_major_minor_version();
        assert!(major >= 1 || minor >= 25);

        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r#"rt:fuse:fuse_request_end { args."#;

        let json_content = document_content_setup(text, 0, text.len());

        let result = encode_completion(json_content);
        assert_eq!(result["result"]["items"].len(), 1);

        let fields = vec!["req"];
        check_completion_resutls(result, fields);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[ignore] // Works on bpftrace version >= 0.25
    #[test]
    fn test_rawtracepoint_struct_competion() {
        assert_eq!(init_bpftrace(None), Ok(()));
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let (major, minor) = bpftrace_major_minor_version();
        assert!(major >= 1 || minor >= 25);

        let text = r#"
rawtracepoint:vmlinux:xhci_queue_trb {
  print(args.ring->);
}
"#;
        let json_content = document_content_setup(text, 2, 19);

        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec![
            "first_seg",
            "last_seg",
            "enqueue",
            "enq_seg",
            "dequeue",
            "td_list",
            "cycle_state",
            "stream_id",
        ];
        check_completion_resutls(result.clone(), fields);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_missing_right_bracket_action() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r#"t:syscalls:sys_enter_bpf { args."#;
        let json_content = document_content_setup(text, 0, text.len());
        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec!["size", "cmd", "uattr"];
        check_completion_resutls(result, fields);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_missing_left_bracket_action() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r#"t:syscalls:sys_enter_bpf args. }"#;
        let json_content = document_content_setup(text, 0, text.len() - 2);
        let result = encode_completion(json_content);
        assert!(result["result"]["items"].len() > 0);

        let fields = vec!["size", "cmd", "uattr"];
        check_completion_resutls(result, fields);
    }

    #[test]
    fn test_completion_inside_string() {
        let text = r#"
fentry:mac80211:ieee80211_check_fast_xmit_iface {
  printf("Frag threshold %x\n", args.sdata->local.hw.wiphy->frag_threshold)
}
    "#;
        let json_content = document_content_setup(text, 2, 15);
        let result = encode_completion(json_content);
        assert_eq!(result["result"]["items"].len(), 0);
    }
}
