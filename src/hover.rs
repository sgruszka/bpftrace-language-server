use json::{object, JsonValue};
use tree_sitter::Node;

use crate::cmd_mod::bpftrace_major_minor_version;
use crate::gen::completion::{
    bpftrace_config_variables, bpftrace_probe_providers, bpftrace_stdlib_helpers,
};
use crate::log_mod::{self, HOVER};
use crate::parser::{self, SyntaxLocation};
use crate::utils::{
    args_to_block, args_to_func_proto, expand_probes, find_common_args_by_cmd,
    find_kfunc_args_by_btf, get_details_and_docs_by_btf, get_details_and_docs_by_cmd,
    is_rawtracepoint_probe, is_tracepoint_probe, is_uprobe, kprobe_to_kfunc, probe_sim_btf,
    probe_use_btf, Probes,
};
use crate::{from_utf16_position, get_document_state, unpack_text_document_info, DOCUMENTS_STATE};
use crate::{log_dbg, log_vdbg};

fn provider_doc_name(name: &str) -> &str {
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

fn hover_from_completion_items(items: &JsonValue, item_name: &str) -> Option<JsonValue> {
    let item = items.members().find(|item| item["label"] == item_name)?;

    log_dbg!(HOVER, "Hover for '{}'", item_name);

    let details = item["detail"].to_string();
    let docs = &item["documentation"]["value"];

    let hover = details + "\n" + &docs.to_string();
    log_vdbg!(HOVER, "Hover:\n{:?}", hover);

    Some(object! {
          "result": {
              "contents": hover,
          },
    })
}

fn encode_hover_for_function(node: &Node, text: &str) -> JsonValue {
    let empty_data = object! { "result": JsonValue::Null };

    let Ok(func) = node.utf8_text(text.as_bytes()) else {
        return empty_data;
    };

    let mut items = JsonValue::new_array();
    bpftrace_stdlib_helpers(&mut items, bpftrace_major_minor_version());

    let Some(hover) = hover_from_completion_items(&items, func) else {
        return empty_data;
    };

    hover
}

fn encode_hover_for_config_variable(node: &Node, text: &str) -> JsonValue {
    let empty_data = object! { "result": JsonValue::Null };

    let Ok(variable) = node.utf8_text(text.as_bytes()) else {
        return empty_data;
    };

    let variable = variable.to_ascii_lowercase();
    let variable = variable.strip_prefix("bpftrace_").unwrap_or(&variable);

    let mut items = JsonValue::new_array();
    bpftrace_config_variables(&mut items, bpftrace_major_minor_version());

    let Some(hover) = hover_from_completion_items(&items, variable) else {
        return empty_data;
    };

    hover
}

fn encode_hover_for_syntax(node: &Node, text: &str) -> JsonValue {
    let Ok(source) = node.utf8_text(text.as_bytes()) else {
        return object! { "result": JsonValue::Null };
    };

    object! {
        "result": {
            "contents": format!("```c\n{source}\n```"),
        },
    }
}

fn encode_hover_for_probe_provider(node: &Node, text: &str) -> JsonValue {
    let empty_data = object! { "result": JsonValue::Null };

    let Ok(provider) = node.utf8_text(text.as_bytes()) else {
        return empty_data;
    };

    let mut items = JsonValue::new_array();
    bpftrace_probe_providers(&mut items, bpftrace_major_minor_version());

    let provider_name = provider_doc_name(provider);

    let Some(hover) = hover_from_completion_items(&items, provider_name) else {
        return empty_data;
    };

    hover
}

fn encode_hover_for_field_expression(
    main_node: &Node,
    text: &str,
    field_expr: Vec<&str>,
) -> JsonValue {
    log_dbg!(HOVER, "Hover for field expression {:?}", field_expr);

    let empty_data = object! { "result": JsonValue::Null };

    let probes_vec = parser::find_probes_for_node(main_node, text);
    if probes_vec.is_empty() {
        return empty_data;
    }

    log_dbg!(HOVER, "Found probes vec {:?}", probes_vec);
    let probes = Probes::new(probes_vec);

    let hover = if probes.btf_probe_args.is_some() {
        let Some((details, docs)) = get_details_and_docs_by_btf(&probes, field_expr, true) else {
            return empty_data;
        };

        details + &docs
    } else if !field_expr.is_empty() && field_expr[0] == "args" {
        let Some((details, docs)) = get_details_and_docs_by_cmd(&probes, field_expr, true) else {
            return empty_data;
        };

        details + &docs
    } else {
        return empty_data;
    };

    log_vdbg!(HOVER, "Hover:\n{:?}", hover);

    object! {
          "result": {
              "contents": hover,
          },
    }
}

pub fn encode_hover(content: JsonValue) -> JsonValue {
    log_dbg!(HOVER, "Received hover with data {}", content);
    let (uri, line_nr, char_nr) = unpack_text_document_info(content);

    let mut data = object! { "result": JsonValue::Null };

    let Some(text_doc) = DOCUMENTS_STATE.get(&uri) else {
        return data;
    };

    let char_nr = from_utf16_position(&text_doc.text, line_nr, char_nr);

    let (text, loc, node, _line_str) = get_document_state!(text_doc, line_nr, char_nr, data, HOVER);

    if loc == SyntaxLocation::ProbesList {
        assert_eq!(node.kind(), "probes_list");

        if node.child_count() < 1 {
            return data;
        }

        let Some(probe_node) = parser::find_probe_in_probes_list(&node, line_nr, char_nr) else {
            return data;
        };
        let probe = probe_node.utf8_text(text.as_bytes()).unwrap_or_default();
        log_dbg!(HOVER, "Hover for probe {}", probe);

        if let Some(provider) = parser::is_location_probe_provider(&probe_node, line_nr, char_nr) {
            return encode_hover_for_probe_provider(&provider, text);
        }

        if probe.contains("*") {
            log_dbg!(HOVER, "Probe is wildcard");
            // Wildcard probe might expand to thousands of individual probes
            // Just print them, do not try to calculate common arguments
            let all_probes = expand_probes(vec![probe.to_string()]);

            let mut all_probes_str = String::new();
            for p in &all_probes {
                all_probes_str.push_str(&format!("{}\n", p));
            }

            let hover = format!(
                "Wildcard probe {}\nExpands into {} individual probes\n\n{}",
                probe,
                all_probes.len(),
                all_probes_str
            );

            data = object! {
                  "result": {
                      "contents": hover,
                },
            };
        } else if probe_use_btf(probe) || probe_sim_btf(probe) {
            log_dbg!(HOVER, "Probe is BTF");
            let args_by_btf = if probe_sim_btf(probe) {
                find_kfunc_args_by_btf(&kprobe_to_kfunc(probe))
            } else {
                find_kfunc_args_by_btf(probe)
            };
            if let Some((_btf, resolved_func)) = args_by_btf {
                data = object! {
                      "result": {
                          "contents": format!("{}\n```c\n{}", probe, &resolved_func.full_name),
                      },
                };
            }
        } else if is_tracepoint_probe(probe) || is_rawtracepoint_probe(probe) {
            log_dbg!(HOVER, "Probe is tracepoint");
            let args = find_common_args_by_cmd(&[probe.to_string()]).unwrap_or_default();
            let docs = args_to_block(&args, true);

            data = object! {
                  "result": {
                      "contents": format!("{}\n{}", probe, docs),
                  },
            };
        } else if is_uprobe(probe)
        /* TODO || is_uretprobe(probe) */
        {
            if let Some(args) = find_common_args_by_cmd(&[probe.to_string()]) {
                let (_, func_name) = probe.rsplit_once(":").unwrap_or_default();
                let proto = args_to_func_proto(func_name, &args);

                data = object! {
                      "result": {
                          "contents": format!("{}\n```c\n{}", probe, proto),
                      },
                };
            }
        }
    } else if loc == SyntaxLocation::Action
        || loc == SyntaxLocation::Predicate
        || loc == SyntaxLocation::MacroDefinition
    {
        // TODO handle probes with wildcard
        if let Some(type_node) = parser::is_location_type(&node, line_nr, char_nr) {
            // TODO
            data = encode_hover_for_syntax(&type_node, text);
        } else if let Some(record) = parser::is_location_record_field(&node, line_nr, char_nr) {
            // TOOD
            data = encode_hover_for_syntax(&record, text);
        } else if let Some(func) = parser::is_location_function_call(text, &node, line_nr, char_nr)
        {
            data = encode_hover_for_function(&func, text);
        } else if let Some(args) = parser::is_location_args_keyword(&node, line_nr, char_nr)
            .and_then(|node| node.utf8_text(text.as_bytes()).ok())
        {
            data = encode_hover_for_field_expression(&node, text, vec![args]);
        } else if let Some(retval) = parser::is_location_retval_identifier(&node, line_nr, char_nr)
            .and_then(|node| node.utf8_text(text.as_bytes()).ok())
        {
            data = encode_hover_for_field_expression(&node, text, vec![retval]);
        } else if let Some(hover) =
            parser::is_location_expression_identifier(&node, line_nr, char_nr)
                .map(|ident| encode_hover_for_function(&ident, text))
                .filter(|hover| !hover["result"].is_null())
        {
            // TODO: identifier can also be a #define name.
            data = hover;
        } else if let Some((field_expr, last_field)) =
            parser::is_location_field_expression(&node, line_nr, char_nr)
        {
            let vec = parser::field_expr_to_vec(text, &field_expr, &last_field);
            if !vec.is_empty() {
                data = encode_hover_for_field_expression(&node, text, vec);
            }
        }
    } else if loc == SyntaxLocation::ConfigBlock {
        if let Some(variable) = parser::is_location_expression_identifier(&node, line_nr, char_nr) {
            data = encode_hover_for_config_variable(&variable, text);
        }
    }

    data
}

#[allow(clippy::len_zero)]
#[allow(dead_code, unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_mod::{init_bpftrace, setup_bpftrace_root_permissions};
    use crate::utils::test_support::document_content_setup;

    #[test]
    fn test_hover_for_type_expressions() {
        let cases = [
            ("begin { $p = (struct path *)0; }", "path", "struct path *"),
            (
                "begin { $p = (struct path *)0; }",
                "struct",
                "struct path *",
            ),
            ("begin { $p = (struct path *)0; }", "*", "struct path *"),
            ("begin { $n = (uint64)0; }", "uint64", "uint64"),
            ("begin { $p = (path)0; }", "path", "path"),
            ("begin { $n = sizeof(struct path); }", "path", "struct path"),
            (
                "begin { let $p: struct path **; }",
                "path",
                "struct path **",
            ),
            (
                "begin { let $p: struct path[2]; }",
                "path",
                "struct path[2]",
            ),
            ("begin { $p = (enum path)0; }", "path", "enum path"),
            (
                "begin { $n = offsetof(struct path, comm); }",
                "path",
                "struct path",
            ),
            ("begin { $n = offsetof(path, comm); }", "path", "path"),
            (
                "begin { print(typeof(struct path *)); }",
                "path",
                "struct path *",
            ),
            ("begin /sizeof(struct path) > 0/ {}", "path", "struct path"),
            (
                "macro example() { let $p: struct path *; }",
                "path",
                "struct path *",
            ),
            (
                "begin { $p = (struct unresolved_hover_type *)0; }",
                "unresolved_hover_type",
                "struct unresolved_hover_type *",
            ),
        ];

        for (text, token, expected_type) in cases {
            let json_content = document_content_setup(text, 0, text.find(token).unwrap());
            let result = encode_hover(json_content);

            assert_eq!(
                result["result"]["contents"].as_str(),
                Some(format!("```c\n{expected_type}\n```").as_str()),
                "hover on {token:?} in {text:?}"
            );
        }
    }

    #[test]
    fn test_hover_excludes_offsetof_members() {
        let cases = [
            ("begin { $n = offsetof(struct task_struct, comm); }", "comm"),
            (
                "begin { $n = offsetof(struct task_struct, comm.cpu); }",
                "comm",
            ),
            (
                "begin { $n = offsetof(struct task_struct, comm.cpu); }",
                "cpu",
            ),
        ];

        for (text, token) in cases {
            let json_content = document_content_setup(text, 0, text.find(token).unwrap());
            let result = encode_hover(json_content);

            assert_eq!(
                result["result"],
                JsonValue::Null,
                "hover on {token:?} in {text:?}"
            );
        }
    }

    #[test]
    fn test_hover_for_record_fields() {
        let cases = [
            ("begin { $r = (comm = 1, cpu = 2); }", "comm", "comm = 1"),
            ("begin { $r = (comm = 1, cpu = 2); }", "cpu", "cpu = 2"),
            (
                "begin { $r = (comm = cpu, other = 1); }",
                "comm",
                "comm = cpu",
            ),
            (
                "begin { $r = (comm = (struct path *)0, other = 1); }",
                "comm",
                "comm = (struct path *)0",
            ),
            (
                "macro example() { $r = (comm = 1, cpu = 2); }",
                "comm",
                "comm = 1",
            ),
        ];

        for (text, token, expected_field) in cases {
            let json_content = document_content_setup(text, 0, text.find(token).unwrap());
            let result = encode_hover(json_content);

            assert_eq!(
                result["result"]["contents"].as_str(),
                Some(format!("```c\n{expected_field}\n```").as_str()),
                "hover on {token:?} in {text:?}"
            );
        }
    }

    #[test]
    fn test_hover_for_builtin_expression_identifiers() {
        let cases = [
            "begin { print(comm); }",
            "begin { print((uint64)comm); }",
            "begin { print(typeof(comm)); }",
            "begin { $r = (field = comm, other = 1); }",
        ];

        for text in cases {
            let json_content = document_content_setup(text, 0, text.find("comm").unwrap());
            let result = encode_hover(json_content);
            let hover = result["result"]["contents"].as_str().unwrap();

            assert!(
                hover.contains("bpf_get_current_comm"),
                "hover in {text:?}: {hover:?}"
            );
        }
    }

    #[test]
    fn test_hover_for_builtin_field_receivers() {
        let cases = [
            ("begin { print(config.max_strlen); }", "config"),
            ("begin { print(curtask->pid); }", "curtask"),
            ("begin { print(curtask->group_leader->pid); }", "curtask"),
        ];

        for (text, builtin) in cases {
            let plain_text = format!("begin {{ print({builtin}); }}");
            let plain_content =
                document_content_setup(&plain_text, 0, plain_text.find(builtin).unwrap());
            let expected = encode_hover(plain_content);
            assert!(!expected["result"].is_null(), "missing hover for {builtin}");

            let json_content = document_content_setup(text, 0, text.find(builtin).unwrap());
            let result = encode_hover(json_content);

            assert_eq!(result, expected, "hover on {builtin:?} in {text:?}");
        }
    }

    #[test]
    fn test_hover_excludes_builtin_names_in_fields() {
        let cases = [
            ("begin { print(curtask->pid); }", "pid"),
            ("begin { print(curtask->comm); }", "comm"),
        ];

        for (text, field) in cases {
            let json_content = document_content_setup(text, 0, text.find(field).unwrap());
            let result = encode_hover(json_content);

            assert_eq!(
                result["result"],
                JsonValue::Null,
                "hover on {field:?} in {text:?}"
            );
        }
    }

    #[test]
    fn test_hover_for_config_variable_word() {
        let text = r"config = { print_maps_on_exit }";
        let json_content = document_content_setup(text, 0, text.len() - 5);
        let result = encode_hover(json_content);

        let hover = result["result"]["contents"].as_str().unwrap();
        println!("{hover:?}");
        assert!(hover.contains(r"config variable"));
        assert!(hover.contains(r"Controls whether bpftrace automatically prints maps on exit"));
    }

    #[test]
    fn test_hover_for_config_variable_aliases() {
        let aliases = [
            "stack_mode",
            "STACK_MODE",
            "BPFTRACE_STACK_MODE",
            "bpftrace_stack_mode",
            "bPfTrAcE_StAcK_MoDe",
        ];

        for alias in aliases {
            for assignment in [" = raw", ""] {
                let text = format!("config = {{ {alias}{assignment} }}");
                let json_content = document_content_setup(&text, 0, text.find(alias).unwrap());
                let result = encode_hover(json_content);
                let hover = result["result"]["contents"].as_str().unwrap();

                assert!(hover.starts_with("stack_mode - config variable\n"));
                assert!(hover.contains("Sets the output format for `ustack` and `kstack`"));
            }
        }
    }

    #[test]
    fn test_hover_for_config_variable() {
        let text = r"config = { print_maps_on_exit = false }";
        let json_content = document_content_setup(text, 0, text.len() - 20);
        let result = encode_hover(json_content);

        let hover = result["result"]["contents"].as_str().unwrap();
        println!("{hover:?}");
        assert!(hover.contains(r"config variable"));
        assert!(hover.contains(r"Controls whether bpftrace automatically prints maps on exit"));
    }

    #[test]
    fn test_hover_for_kfunc() {
        let text = r"kfunc:vmlinux:posix_timer_fn {}";
        let json_content = document_content_setup(text, 0, text.len() - 10);
        let result = encode_hover(json_content);

        let hover = result["result"]["contents"].as_str().unwrap();
        assert!(hover.contains(r"kfunc:vmlinux:posix_timer_fn"));
        println!("{hover:?}");
        // TODO remove space in function arguments: struct hrtimer *hrtmer
        assert!(hover.contains(r"hrtimer_restart posix_timer_fn(struct hrtimer * timer)"));
    }

    #[test]
    fn test_hover_on_comma_between_probes() {
        let text = "kprobe:foo,kprobe:bar {}";
        let json_content = document_content_setup(text, 0, text.find(',').unwrap());
        let result = encode_hover(json_content);

        assert_eq!(result["result"], JsonValue::Null);
    }

    #[test]
    fn test_hover_for_fentry_provider() {
        let text = r"fentry:vmlinux:posix_timer_fn {}";
        let json_content = document_content_setup(text, 0, 2);
        let result = encode_hover(json_content);

        let hover = result["result"]["contents"].as_str().unwrap();
        println!("{hover:?}");
        assert!(hover.contains(r"fentry[:module]:function"));
        assert!(hover.contains(r"Kernel function entry probe using BTF"));
        assert!(hover.contains(r"Short name `f`"));
    }

    #[test]
    fn test_hover_for_t_provider() {
        let text = r"t:dma:dma_free {}";
        let json_content = document_content_setup(text, 0, 0);
        let result = encode_hover(json_content);

        let hover = result["result"]["contents"].as_str().unwrap();
        println!("{hover:?}");
        assert!(hover.contains(r"tracepoint:subsys:event"));
        assert!(hover.contains(r"Kernel static tracepoint probe"));
        assert!(hover.contains(r"Short name `t`"));
    }

    #[test]
    fn test_hover_for_u_provider() {
        let text = r"u:/lib64/libc.so.6:__libc_calloc {}";
        let json_content = document_content_setup(text, 0, 0);
        let result = encode_hover(json_content);

        let hover = result["result"]["contents"].as_str().unwrap();
        assert!(hover.contains(r"uprobe:binary:function"));
        assert!(hover.contains(r"User-space function entry probe"));
        assert!(hover.contains(r"Short name `u`"));
    }

    #[test]
    fn test_hover_for_begin_provider() {
        let text = r"begin { }";
        let json_content = document_content_setup(text, 0, 2);
        let result = encode_hover(json_content);

        let hover = result["result"]["contents"].as_str().unwrap();
        println!("{hover:?}");
        assert!(hover.contains(r"Special built-in event provided by the bpftrace runtime."));
    }

    #[test]
    fn test_hover_for_args() {
        let text = r"
fentry:vmlinux:find_ge_pid {
  print(args);
}";
        let json_content = document_content_setup(text, 2, 10);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains(r"of find_ge_pid"));
        assert!(hover.contains("struct {"));
        assert!(hover.contains("int nr"));
        assert!(hover.contains("struct pid_namespace * ns"));
        assert!(hover.contains("} args;"));
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_hover_for_uprobe_args() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));
        let text = "u:target/debug/bpftrace-ls:ts_query_new { print(args) }";

        let json_content = document_content_setup(text, 0, text.len() - 6);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");

        let hover = hover.replace(" *", "*");
        assert!(hover.contains(r"of ts_query_new"));
        assert!(hover.contains(r"const TSLanguage* language;"));
        assert!(hover.contains(r"TSQueryError* error_type;"));
        assert!(hover.contains(r"uint32_t source_len;"));
        assert!(hover.contains(r"const char* source;"));
    }

    #[test]
    fn test_hover_inside_call_expression() {
        let text = r#"
fentry:vmlinux:find_ge_pid {
  printf("%d %d\n", args.ns->level, args.nr);
}"#;
        let json_content = document_content_setup(text, 2, 26);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");

        assert!(hover.contains("struct pid_namespace {"));
        assert!(hover.contains("struct idr idr;"));
        assert!(hover.contains("struct ns_common ns;"));
        assert!(hover.contains("unsigned int level;"));
        assert!(hover.contains("int pid_max;"));
        assert!(hover.contains("struct work_struct work;"));
        assert!(hover.contains("struct task_struct * child_reaper;"));

        let json_content = document_content_setup(text, 2, 30);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        assert_eq!(formatted_hover.lines().count(), 2);

        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        assert!(hover.contains("unsigned int level;"));
    }

    #[test]
    fn test_hover_for_retval() {
        let text = r"
fexit:vmlinux:find_ge_pid {
  print(retval);
}";
        let json_content = document_content_setup(text, 2, 10);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains(r"Return value of find_ge_pid"));
        assert!(hover.contains("refcount_t count;"));
        assert!(hover.contains("unsigned int level;"));
        assert!(hover.contains("spinlock_t lock;"));
        assert!(hover.contains("struct hlist_head inodes"));
    }

    #[test]
    fn test_hover_for_fs_pin_struct() {
        let text = r"
fentry:vmlinux:find_ge_pid {
  print(args.ns);
}";
        let json_content = document_content_setup(text, 2, 14);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains(r"struct pid_namespace {"));
        assert!(hover.contains("struct idr idr;"));
        assert!(hover.contains("struct callback_head rcu;"));
        assert!(hover.contains("struct pid_namespace * parent;"));
        assert!(hover.contains("unsigned int level;"));
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_hover_for_tracepoint_args() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r"
tracepoint:dma:dma_alloc {
  print(args);
}";
        let json_content = document_content_setup(text, 2, 10);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains(r" of dma_alloc"));
        assert!(hover.contains("struct {"));
        assert!(hover.contains("u64 dma_addr;"));
        assert!(hover.contains("size_t size;"));
        assert!(hover.contains("enum dma_data_direction dir;"));
        assert!(hover.contains("} args;"));
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_hover_multiple_tracepoint_args() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r#"
tracepoint:syscalls:sys_enter_open,
tracepoint:syscalls:sys_enter_openat,
tracepoint:syscalls:sys_enter_openat2, {
  print(args);
}"#;
        let json_content = document_content_setup(text, 4, 11);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        assert_eq!(formatted_hover.lines().count(), 7);

        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");

        assert!(hover.contains(r"common arguments of sys"));
        assert!(hover.contains("..."));
        assert!(hover.contains("struct {"));
        assert!(hover.contains("int __syscall_nr"));
        assert!(hover.contains("const char * filename"));
        assert!(hover.contains("} args;"));
    }

    #[test]
    fn test_hover_for_bitfield() {
        let text = r#"
fentry:vmlinux:async_schedule_node_domain {
  print(args.domain)
}
"#;
        let json_content = document_content_setup(text, 2, 15);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains("struct async_domain"));
        assert!(hover.contains("registered:1"));
    }

    // This test is slow, it has to read availabe traces,
    // TODO: init AVAILABE_TRACES during test module start
    #[ignore]
    #[test]
    fn test_hover_for_wildcard_probe() {
        let text = r#"tracepoint:syscalls:sys_enter_open* { }"#;

        let json_content = document_content_setup(text, 0, text.len() - 8);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        assert_eq!(formatted_hover.lines().count(), 9);

        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains("Wildcard probe"));
        assert!(hover.contains("Expands into 6 individual probes"));
        assert!(hover.contains("sys_enter_open"));
        assert!(hover.contains("sys_enter_openat"));
        assert!(hover.contains("sys_enter_openat2"));
        assert!(hover.contains("sys_enter_open_by_handle_at"));
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[test]
    fn test_hover_for_tracepoint_struct() {
        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r"
tracepoint:xhci-hcd:xhci_dbc_alloc_request {
  print(args.req)
}";
        let json_content = document_content_setup(text, 2, 14);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains(r"struct dbc_request {"));
        assert!(hover.contains("void * buf"));
        assert!(hover.contains("dma_addr_t dma;"));
        assert!(hover.contains("struct list_head list_pool;"));
        assert!(hover.contains("union xhci_trb * trb;"));
        assert!(hover.contains("unsigned int direction:1;"));
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[ignore] // Works only on bpftrace >= 0.25
    #[test]
    fn test_hover_for_rawtracepoint() {
        assert_eq!(init_bpftrace(None), Ok(()));

        let (major, minor) = bpftrace_major_minor_version();
        assert!(major >= 1 || minor >= 25);

        assert_eq!(setup_bpftrace_root_permissions(), Ok(()));

        let text = r"rawtracepoint:mei:mei_reg_read { }";

        let json_content = document_content_setup(text, 0, text.len() - 8);
        let result = encode_hover(json_content);

        let formatted_hover = result["result"]["contents"].as_str().unwrap();
        let hover = formatted_hover
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        println!("{hover:?}");
        assert!(hover.contains("const struct device * dev;"));
        assert!(hover.contains("const char * reg;"));
        assert!(hover.contains("u32 offs;"));
        assert!(hover.contains("u32 val"));
    }
}
