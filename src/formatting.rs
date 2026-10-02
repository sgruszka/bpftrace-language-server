use crate::cmd_mod;
use crate::cmd_mod::bpftrace_major_minor_version;
use crate::log_mod::{self, FRMAT};
use crate::{log_dbg, log_err, log_vdbg, WarningType, WARNINGS_TO_CLIENT};
use crate::{to_utf16_position, DOCUMENTS_STATE};

use json::{self, object, JsonValue};

fn encode_no_formatting() -> JsonValue {
    object! { "result": JsonValue::Null }
}

fn format(text: &str) -> Option<String> {
    let Ok(output) = cmd_mod::bpftrace_command(&["--fmt", "-e", text]) else {
        log_err!(
            "Failed to run: {} --fmt -e '{}'",
            cmd_mod::get_used_command(),
            text
        );
        return None;
    };

    if !output.status.success() {
        log_err!(
            "bpftrace --fmt command failed: {:?}",
            String::from_utf8(output.stderr)
        );
        return None;
    }

    let Ok(formatted_text) = String::from_utf8(output.stdout) else {
        log_err!("Failed to convert stdout to string");
        return None;
    };

    Some(formatted_text)
}

pub fn encode_formatting(content: JsonValue) -> JsonValue {
    log_dbg!(FRMAT, "Received formatting with data {}", content);

    let (major, minor) = bpftrace_major_minor_version();
    if (major, minor) < (0, 25) {
        WARNINGS_TO_CLIENT.push(
            WarningType::NoFmt,
            format!(
                "bpftrace formatting (--fmt) requires version 0.25 or later, detected v{major}.{minor}."
            ),
        );
        return encode_no_formatting();
    }

    let Some(uri) = content["params"]["textDocument"]["uri"].as_str() else {
        return encode_no_formatting();
    };
    // TODO: format according to options
    // let options = &content["params"]["options"];

    let Some(text_doc) = DOCUMENTS_STATE.get(uri) else {
        return encode_no_formatting();
    };

    let Some(tree) = text_doc.syntax_tree.as_ref() else {
        return encode_no_formatting();
    };

    let Some(formatted_text) = format(&text_doc.text) else {
        return encode_no_formatting();
    };

    log_vdbg!(FRMAT, "Original text:\n{}", text_doc.text);
    log_vdbg!(FRMAT, "Formatted text:\n{}", formatted_text);
    // TODO: provide diff ?

    let end_pos_ts = tree.root_node().end_position();
    let end_pos = to_utf16_position(&text_doc.text, end_pos_ts);

    let text_edit = object! {
        "range": {
            "start": { "line": 0, "character": 0 },
            "end": { "line": end_pos.row  , "character": end_pos.column },
        },
        "newText": formatted_text,
    };

    object! { "result": [text_edit] }
}

#[allow(dead_code, unused_imports)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cmd_mod::init_bpftrace;

    #[cfg(all(test, feature = "live_system_tests"))]
    #[ignore] // Works on bpftrace version >= 0.25
    #[test]
    fn format_begin_action_block() {
        assert_eq!(init_bpftrace(None), Ok(()));

        let text = r#"
    BEGIN{@count=0;     printf("hello  world" 
 );  }            "#;
        let formatted_text = r#"
BEGIN
{
  @count = 0;
  printf("hello  world");
}
"#;
        assert_eq!(format(text).unwrap(), formatted_text);
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[ignore] // Works on bpftrace version >= 0.25
    #[test]
    fn format_predicate_and_comments() {
        assert_eq!(init_bpftrace(None), Ok(()));

        let input = r#"kprobe:vfs_read /pid == 1/{ // keep  spaces
 @calls[comm]=count(); }"#;
        let expected = r#"kprobe:vfs_read
/pid == 1/
{
  // keep  spaces
  @calls[comm] = count();
}
"#;
        assert_eq!(format(input).as_deref(), Some(expected));
    }

    #[cfg(all(test, feature = "live_system_tests"))]
    #[ignore] // Works on bpftrace version >= 0.25
    #[test]
    fn format_invalid_syntax() {
        assert_eq!(init_bpftrace(None), Ok(()));
        assert_eq!(format("BEGIN { @x = ; }"), None);
    }

    #[test]
    fn format_utf16_end_column() {
        let text = r#"BEGIN { printf("🐝b🐝p🐝f🐝t🐝r🐝a🐝c🐝e🐝"); }"#;

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_bpftrace::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(text, None).unwrap();
        let root = tree.root_node();
        assert!(!root.has_error());

        let end_pos = to_utf16_position(text, root.end_position());
        assert_eq!(end_pos.column, text.encode_utf16().count());
    }
}
