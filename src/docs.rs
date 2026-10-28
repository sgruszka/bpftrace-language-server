use crate::args::find_common_args_by_cmd;
use crate::btf_rd::{
    btf_item_to_str, btf_iterate_function_args, btf_resolve_container_members, btf_resolve_variable,
};
use crate::btf_rd::{Btf, BtfComposite, BtfResolvedType};
use crate::log_mod::{self, DOCUM};
use crate::probes::Probes;
use crate::{log_dbg, log_err};

fn is_anonymous_type(res_type: &BtfResolvedType) -> bool {
    res_type.type_prefix == "struct " || res_type.type_prefix == "union "
}

pub fn args_to_block(args: &Vec<String>, hover: bool) -> String {
    let mut docs = String::new();

    let c_open;
    let c_close;
    if hover {
        c_open = "```c \n";
        c_close = "";
    } else {
        c_open = "```c \n";
        c_close = "\n"
    }

    docs.push_str(&format!("{}{{\n", c_open));
    for arg in args {
        docs.push_str(&format!("{:<indent$}{};\n", "", arg.trim(), indent = 2));
    }
    docs.push_str(&format!("}}{}", c_close));

    docs
}

pub fn args_to_func_proto(func_name: &str, args: &[String]) -> String {
    let mut proto = String::new();

    let first_arg = if args.len() > 1 { &args[0] } else { "" };
    proto.push_str(&format!("void {}({}", func_name, first_arg));

    for arg in args.iter().skip(1) {
        proto.push_str(&format!(", {}", arg.trim()));
    }

    proto.push_str(")\n");

    proto
}

// Structure/union members
fn members_to_lines(
    btf: &Btf,
    actual_type: &BtfComposite,
    indent: usize,
    need_field_aligment: bool,
    lines: &mut Vec<(usize, bool, bool, String, String, String)>,
) -> usize {
    let mut max_type_width = 0;
    for member in actual_type.members.iter() {
        let Some(member_type) = btf_resolve_variable(btf, member) else {
            log_err!("Failed to resolve BTF type {}", member.type_id);
            continue;
        };

        if is_anonymous_type(&member_type) {
            if let Some(sub_type) = member_type.actual_type.as_ref() {
                lines.push((
                    indent,
                    false,
                    false,
                    format!("{}{{", member_type.type_prefix),
                    "".to_string(),
                    "".to_string(),
                ));

                members_to_lines(btf, sub_type, indent + 1, false, lines);

                lines.push((
                    indent,
                    !member.name.is_empty() && need_field_aligment,
                    true,
                    "}".to_string(),
                    if member.name.is_empty() {
                        "".to_string()
                    } else {
                        format!(" {}", member.name)
                    },
                    member_type.type_suffix,
                ));

                continue;
            } else {
                log_err!(
                    "Failed to get anonymous struct/union members for id {} (actual type id {})",
                    member_type.type_id,
                    member_type.actual_type_id,
                );
                continue;
            }
        } else if need_field_aligment {
            let width = member_type.type_prefix.len() + 1;
            if width > max_type_width {
                max_type_width = width;
            }
        }

        let left_indent = indent;
        let type_name;
        let var_name;

        let type_suffix = if let Some(bits) = member.bits {
            format!(":{}", bits)
        } else {
            member_type.type_suffix
        };

        if member_type.type_prefix.ends_with("(*") {
            // Function pointer;
            type_name = member_type.type_prefix.replace("(*", "");
            var_name = format!(" (*{}", member.name);
        } else {
            type_name = member_type.type_prefix;
            var_name = format!(" {}", member.name);
        }

        lines.push((
            left_indent,
            need_field_aligment,
            true,
            type_name,
            var_name,
            type_suffix,
        ))
    }

    max_type_width
}

// Structure/union members
fn members_to_string(btf: &Btf, actual_type: &BtfComposite) -> String {
    let mut lines = Vec::new();
    let mut out_str = String::new();

    let max_type_width = members_to_lines(btf, actual_type, 1, true, &mut lines);

    for l in lines {
        let (indent, alignment, semicolon, type_name, var_name, type_suffix) = l;
        let line_str = format!(
            "{:<left_indent$}{:<width$}{}{}{}\n",
            "",
            type_name,
            var_name,
            type_suffix,
            if semicolon { ";" } else { "" },
            left_indent = indent * 8,
            width = if alignment { max_type_width } else { 0 }
        );

        out_str.push_str(&line_str);
    }

    out_str
}

fn get_args_details(probes_vec: &[String]) -> String {
    if probes_vec.len() > 1 {
        let (_, name1) = probes_vec[0].rsplit_once(":").unwrap_or_default();
        let (_, name2) = probes_vec[1].rsplit_once(":").unwrap_or_default();
        if probes_vec.len() > 2 {
            format!(
                "Struct representing common arguments of {}, {}, ...\n",
                name1, name2
            )
        } else {
            format!(
                "Struct representing common arguments of {} and {}\n",
                name1, name2
            )
        }
    } else if probes_vec.len() == 1 {
        let common = if probes_vec[0].contains("*") {
            " commmon "
        } else {
            " "
        };
        let (_, name) = probes_vec[0].rsplit_once(":").unwrap_or_default();

        format!("Struct representing{}arguments of {}\n", common, name)
    } else {
        String::new()
    }
}

pub fn get_details_and_docs_by_btf(
    probes: &Probes,
    field_expr: Vec<&str>,
    hover: bool,
) -> Option<(String, String)> {
    log_dbg!(
        DOCUM,
        "Looking for details of field expression '{:?}' with probes '{:?}' using BTF",
        field_expr,
        probes.probes_vec
    );

    if field_expr.is_empty() {
        return None;
    }

    if probes.probes_vec.is_empty() {
        return Some((
            "".to_owned(),
            "Probe list did not resolve to any probes, no valid arguments".to_owned(),
        ));
    }

    let mut is_args = false;
    if field_expr.len() == 1 && field_expr[0] == "args" {
        is_args = true;
    }

    let mut is_retval = false;
    if field_expr.len() == 1 && field_expr[0] == "retval" {
        is_retval = true;
    }

    let (btf, resolved_func) = probes.btf_probe_args.as_ref()?;
    let func_name = resolved_func.name.clone();

    let (res_var, res_type) = btf_iterate_function_args(btf, resolved_func, field_expr)?;
    let declaration = btf_item_to_str(&res_type, Some(&res_var));
    log_dbg!(DOCUM, "Found BTF variable declaration {}", declaration);

    let mut details = String::new();
    let mut docs = String::new();

    let c_open;
    let c_close;
    if hover {
        c_open = "```c\n";
        c_close = "";
    } else {
        c_open = "```c\n";
        c_close = "\n"
    }
    //struct of all arguments of the traced function.
    if is_args {
        details.push_str(&get_args_details(&probes.probes_vec));
    } else if is_retval {
        details.push_str(&format!("Return value of {}\n", func_name));
        docs.push_str(&format!("{}{};{}\n", c_open, declaration, c_close));
    } else if res_type.actual_type.is_some() {
        details = declaration;
        details.push_str(":\n");
    } else {
        details = format!("{}{};{}\n", c_open, declaration, c_close)
    }

    if let Some(actual_type) = res_type.actual_type {
        let s = if is_args {
            &format!("{}struct {{\n", c_open)
        } else {
            &format!("{}{}\n{{\n", c_open, actual_type.type_name)
        };
        docs.push_str(s);
        docs.push_str(&members_to_string(btf, &actual_type));
        docs.push_str(&format!(
            "}}{};{}",
            if is_args { " args" } else { "" },
            c_close
        ));
    }

    Some((details, docs))
}

pub fn get_details_and_docs_by_cmd(
    probes: &Probes,
    field_expr: Vec<&str>,
    hover: bool,
) -> Option<(String, String)> {
    log_dbg!(
        DOCUM,
        "Looking for details of field expression '{:?}' with probes '{:?}' using command line",
        field_expr,
        probes.probes_vec
    );

    if field_expr.is_empty() {
        return None;
    }

    if probes.probes_vec.is_empty() {
        return Some((
            "".to_owned(),
            "Probe list did not resolve to any probes, no valid arguments".to_owned(),
        ));
    }

    let probe_args = find_common_args_by_cmd(&probes.probes_vec)?;

    log_dbg!(DOCUM, "Found probe args by command: {:?}\n", probe_args);

    let c_open;
    let c_close;
    if hover {
        c_open = "```c\n";
        c_close = "";
    } else {
        c_open = "```c\n";
        c_close = "\n";
    }

    let mut details = String::new();
    let mut docs = String::new();

    if field_expr.len() == 1 && field_expr[0] == "args" {
        details = get_args_details(&probes.probes_vec);

        docs.push_str(&format!("{}struct {{\n", c_open));
        for arg in probe_args {
            docs.push_str(&format!("{:<indent$}{};\n", "", arg, indent = 8));
        }
        docs.push_str(&format!("}} args;{}", c_close));
    } else if let Some((btf, res_var, res_type)) =
        btf_resolve_container_members(probe_args.into_iter(), field_expr)
    {
        if let Some(actual_type) = res_type.actual_type {
            let s = &format!("{}{}\n{{\n", c_open, actual_type.type_name);
            docs.push_str(s);
            docs.push_str(&members_to_string(&btf, &actual_type));
            docs.push_str(&format!("}} {};{}", res_var.name, c_close));
        }
    }

    Some((details, docs))
}
