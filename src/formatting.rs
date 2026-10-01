use crate::cmd_mod;
use crate::log_mod::{self, FRMAT};
use crate::DOCUMENTS_STATE;
use crate::{log_dbg, log_err, log_vdbg};

use json::{self, object, JsonValue};

fn encode_no_formatting() -> JsonValue {
    object! { "result": JsonValue::Null }
}

pub fn encode_formatting(content: JsonValue) -> JsonValue {
    log_dbg!(FRMAT, "Received formatting with data {}", content);

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

    // TODO: check version of bpftrace that supports --fmt
    let Ok(output) = cmd_mod::bpftrace_command(&["--fmt", "-e", &text_doc.text]) else {
        log_err!("Failed to run bpftrace --fmt command");
        return encode_no_formatting();
    };

    if !output.status.success() {
        log_err!("bpftrace --fmt command failed: {:?}", output.stderr);
        return encode_no_formatting();
    }

    let Ok(formatted_text) = String::from_utf8(output.stdout) else {
        log_err!("Failed to convert stdout to string");
        return encode_no_formatting();
    };

    log_vdbg!(FRMAT, "Original text:\n{}", text_doc.text);
    log_vdbg!(FRMAT, "Formatted text:\n{}", formatted_text);
    // TODO: provide diff ?

    let end_pos = tree.root_node().end_position();
    // TODO utf-16 ?
    // let line = text_doc.text.bytes().filter(|&byte| byte == b'\n').count();
    // let last_line = text_doc.text.rsplit('\n').next().unwrap_or_default();
    // let last_line = last_line.strip_suffix('\r').unwrap_or(last_line);
    // let character = last_line.encode_utf16().count();

    let text_edit = object! {
        "range": {
            "start": { "line": 0, "character": 0 },
            "end": { "line": end_pos.row  , "character": end_pos.column },
        },
        "newText": formatted_text,
    };

    object! { "result": [text_edit] }
}
