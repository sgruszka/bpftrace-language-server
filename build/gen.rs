use std::fs;

#[derive(Default, Debug)]
struct DocItem {
    label: String,
    detail: String,
    variants: Vec<String>,
    full_info: String,
    version: Version,
    helper_flags: usize,
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Version {
    min_ver: Option<(u32, u32)>,
    max_ver: Option<(u32, u32)>,
}

#[derive(Debug, PartialEq, Eq)]
enum ParseVersionError {
    InvalidFormat,
    InvalidVersion,
}

pub const IS_ASYNC: usize = 1 << 0;
pub const MAP_VALUE: usize = 1 << 1;
pub const IS_UNSAFE: usize = 1 << 2;
pub const IS_COMPTIME: usize = 1 << 3;

fn parse_tuple(s: &str) -> Result<Option<(u32, u32)>, ParseVersionError> {
    let s = s.trim();

    if s.is_empty() {
        return Ok(None);
    }

    let Some((major, minor)) = s.split_once('.') else {
        return Err(ParseVersionError::InvalidVersion);
    };

    let major = major
        .parse::<u32>()
        .map_err(|_| ParseVersionError::InvalidVersion)?;

    let minor = minor
        .parse::<u32>()
        .map_err(|_| ParseVersionError::InvalidVersion)?;

    Ok(Some((major, minor)))
}

fn parse_version(input: &str) -> Result<Version, ParseVersionError> {
    let input = input.trim();

    // Empty string and [] mean no bounds.
    if input.is_empty() || input == "[]" {
        return Ok(Version {
            min_ver: None,
            max_ver: None,
        });
    }

    // Must be enclosed in [...]
    let Some(input) = input.strip_prefix('[') else {
        return Err(ParseVersionError::InvalidFormat);
    };

    let Some(input) = input.strip_suffix(']') else {
        return Err(ParseVersionError::InvalidFormat);
    };

    let Some((min, max)) = input.split_once("..") else {
        return Err(ParseVersionError::InvalidFormat);
    };

    Ok(Version {
        min_ver: parse_tuple(min)?,
        max_ver: parse_tuple(max)?,
    })
}

fn add_json_obj(text: &mut String, doc_item: &DocItem, kind: usize) {
    let label = &doc_item.label;
    let detail = &doc_item.detail;
    let docs = &doc_item.full_info;

    let obj = format!(
        r##"
    let json_obj = object! {{
        "label": r#"{label}"#,
        "kind" : {kind},
        "detail": r#"{detail}"#,
        "documentation" : {{
            "kind": "markdown",
            "value": r#"{docs}"#,
        }},
    }};
    let _ = items.push(json_obj);
    "##
    );

    text.push_str(&obj);
}

fn item_detail_and_kind(doc_item: &DocItem) -> (String, i32) {
    let label = &doc_item.label;

    let mut kind = 3;
    let mut detail = format!("{} - synchronous function", label);

    if doc_item.helper_flags & MAP_VALUE == MAP_VALUE {
        detail = format!("{} - map value function", label);
    } else if doc_item.helper_flags & (IS_ASYNC | IS_UNSAFE) == (IS_ASYNC | IS_UNSAFE) {
        detail = format!("{} - asynchronous *unsafe* function", label)
    } else if doc_item.helper_flags & IS_UNSAFE == IS_UNSAFE {
        detail = format!("{} - synchronous *unsafe* function", label)
    } else if doc_item.helper_flags & IS_ASYNC == IS_ASYNC {
        detail = format!("{} - asynchronous function", label)
    } else if doc_item.helper_flags & IS_COMPTIME == IS_COMPTIME {
        detail = format!("{} - compile-time function", label)
    } else if doc_item.variants.len() == 1 {
        if !doc_item.variants[0].ends_with(")") {
            kind = 6;
            detail = format!("{} - builtin variable", label);
        }
    } else {
        for variant in &doc_item.variants {
            if !variant.ends_with(")") {
                detail = format!("{} - builtin function/variable", label);
                break;
            }
        }
    }

    (detail, kind)
}
fn stdlib_add_json_obj(text: &mut String, doc_item: &DocItem) {
    let label = &doc_item.label;

    let (detail, kind) = item_detail_and_kind(doc_item);

    let mut docs = String::new();
    docs.push_str(&doc_item.full_info);

    let mut cond_min_end = "";
    let mut cond_max_end = "";

    if let Some(min_ver) = doc_item.version.min_ver {
        text.push_str(&format!(
            "if this_version >= ({},{}) {{",
            min_ver.0, min_ver.1
        ));
        cond_min_end = "}"
    }

    if let Some(max_ver) = doc_item.version.max_ver {
        text.push_str(&format!(
            "if this_version <= ({},{}) {{",
            max_ver.0, max_ver.1
        ));
        cond_max_end = "}"
    }

    let obj = format!(
        r##"
    let json_obj = object! {{
        "label": r#"{label}"#,
        "kind" : {kind},
        "detail": r#"{detail}"#,
        "documentation" : {{
            "kind": "markdown",
            "value": r#"{docs}"#,
        }},
    }};
    let _ = items.push(json_obj);
    "##
    );
    text.push_str(&obj);

    text.push_str(cond_max_end);
    text.push_str(cond_min_end);
}

fn gen_completion_probes(language_md: &str) -> String {
    let mut probes_section = false;
    let mut collected_probe = false;
    let mut after_variants = false;

    let mut doc_item = DocItem::default();

    let mut text = r#"
pub fn bpftrace_probe_providers(
    items: &mut json::JsonValue,
    this_version: (u16, u16),
) {
    "#
    .to_string();

    for line in language_md.lines() {
        if line.trim().starts_with("## ") && probes_section {
            probes_section = false;
        }

        if line.trim().starts_with("## Probes") {
            probes_section = true;
        }
        if !probes_section {
            continue;
        }

        if line.trim().starts_with("### ") {
            if collected_probe {
                probe_add_json_obj(&mut text, &mut doc_item);
            }

            doc_item = DocItem::default();
            let (label, range) = parse_header(line).unwrap();
            doc_item.label = label.to_string();
            doc_item.version = parse_version(range).unwrap();
            doc_item.detail = format!("{} - probe provider", doc_item.label);

            collected_probe = true;
            after_variants = false;
            continue;
        }

        if line.trim().starts_with("**variants**") {
            after_variants = true;
            continue;
        }
        if after_variants {
            if line.trim().is_empty() {
                continue;
            } else {
                after_variants = false;
            }
        }

        doc_item.full_info.push_str(line);
        doc_item.full_info.push('\n');
    }

    if collected_probe {
        probe_add_json_obj(&mut text, &mut doc_item);
    }

    text.push_str("}");

    text
}

fn parse_header(s: &str) -> Option<(&str, &str)> {
    let s = s.strip_prefix("### ")?;
    s.split_once(|c: char| c.is_whitespace())
}

fn gen_completion_stdlib(stdlib_md: &str) -> String {
    let mut doc_item = DocItem::default();
    let mut collected_item = false;
    let mut after_label = false;
    let mut after_summary = false;
    let mut after_variants = false;
    let mut map_value_func = false;

    let mut text = r#"
pub fn bpftrace_stdlib_helpers(items: &mut json::JsonValue, this_version: (u16, u16) ) {
"#
    .to_string();

    for line in stdlib_md.lines() {
        if line.trim() == "## MAP VALUE FUNCTIONS" {
            map_value_func = true;
            continue;
        }

        if line.trim().starts_with("### ") {
            if collected_item {
                stdlib_add_json_obj(&mut text, &doc_item);
            }

            doc_item = DocItem::default();

            let (label, range) = parse_header(line).unwrap();
            doc_item.label = label.to_string();
            doc_item.version = parse_version(range).unwrap();
            if map_value_func {
                doc_item.helper_flags |= MAP_VALUE;
            }

            collected_item = true;

            after_label = true;
            after_summary = false;
            after_variants = false;
            continue;
        }

        if after_label {
            if line.trim().is_empty() {
                after_summary = true;
                after_label = false;
            } else {
                doc_item.full_info.push_str(line);
                doc_item.full_info.push('\n');
            }
        }

        if after_summary {
            if line.trim().is_empty() {
                doc_item.full_info.push('\n');
                continue;
            }

            if line.trim().starts_with("**async**")
                || line.trim().starts_with("**unsafe**")
                || line.trim().starts_with("**compile time**")
            {
                if line.trim().starts_with("**async**") {
                    doc_item.helper_flags |= IS_ASYNC;
                }
                if line.trim().starts_with("**unsafe**") {
                    doc_item.helper_flags |= IS_UNSAFE;
                }
                if line.trim().starts_with("**compile time**") {
                    doc_item.helper_flags |= IS_COMPTIME;
                }

                if doc_item.full_info.ends_with("\n") {
                    let _ = doc_item.full_info.pop();
                }

                continue;
            }

            if !after_variants {
                if line.trim().starts_with("- ") || line.trim().starts_with("* ") {
                    doc_item.variants.push(line[3..line.len() - 1].to_string());
                } else {
                    after_variants = true;
                }
            }
            doc_item.full_info.push_str(line);
            doc_item.full_info.push('\n');
        }
    }

    if collected_item {
        stdlib_add_json_obj(&mut text, &doc_item);
    }

    text.push_str("}");

    text
}

fn gen_completion_config_variables(stdlib_md: &str) -> String {
    let mut doc_item = DocItem::default();
    let mut collected_item = false;
    let mut after_label = false;

    let mut text = r#"
pub fn bpftrace_config_variables(items: &mut json::JsonValue, this_version: (u16, u16)) {
    "#
    .to_string();

    for line in stdlib_md.lines() {
        if line.trim().starts_with("### ") {
            if collected_item {
                config_add_json_obj(&mut text, &doc_item);
            }

            if line.trim() == "### END" {
                collected_item = false;
                break;
            }

            doc_item = DocItem::default();
            let (label, range) = parse_header(line.trim()).unwrap();
            doc_item.label = label.to_string();
            doc_item.detail = format!("{} - config variable", label);
            doc_item.version = parse_version(range).unwrap();
            collected_item = true;

            after_label = true;
            continue;
        }

        if after_label {
            doc_item.full_info.push_str(line);
            doc_item.full_info.push('\n');
        }
    }

    if collected_item {
        config_add_json_obj(&mut text, &doc_item);
    }

    text.push_str("}");

    text
}

fn probe_add_json_obj(text: &mut String, doc_item: &mut DocItem) {
    let mut cond_min_end = "";
    let mut cond_max_end = "";

    if let Some(min_ver) = doc_item.version.min_ver {
        text.push_str(&format!(
            "if this_version >= ({},{}) {{",
            min_ver.0, min_ver.1
        ));
        cond_min_end = "}";
    }

    if let Some(max_ver) = doc_item.version.max_ver {
        text.push_str(&format!(
            "if this_version <= ({},{}) {{",
            max_ver.0, max_ver.1
        ));
        cond_max_end = "}";
    }

    add_json_obj(text, doc_item, 8);

    text.push_str(cond_max_end);
    text.push_str(cond_min_end);
}

fn config_add_json_obj(text: &mut String, doc_item: &DocItem) {
    let mut cond_min_end = "";
    let mut cond_max_end = "";

    if let Some(min_ver) = doc_item.version.min_ver {
        text.push_str(&format!(
            "if this_version >= ({},{}) {{",
            min_ver.0, min_ver.1
        ));
        cond_min_end = "}";
    }

    if let Some(max_ver) = doc_item.version.max_ver {
        text.push_str(&format!(
            "if this_version <= ({},{}) {{",
            max_ver.0, max_ver.1
        ));
        cond_max_end = "}";
    }

    add_json_obj(text, doc_item, 6);

    text.push_str(cond_max_end);
    text.push_str(cond_min_end);
}
