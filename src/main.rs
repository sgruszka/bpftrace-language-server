#![allow(clippy::single_char_add_str)]
#![allow(clippy::let_and_return)]

use json::{self, object};

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    sync::{mpsc, Arc, LazyLock, RwLock},
    thread,
    time::{Duration, Instant},
};

mod btf_rd;
mod cmd_mod;
mod completion;
pub mod gen;
pub mod parser;

#[macro_use]
pub mod log_mod;

use log_mod::{DEFIN, DIAGN, NOTIF, PROTO, REFER};

const PKG_VERSION: &str = env!("CARGO_PKG_VERSION");
const PKG_NAME: &str = env!("CARGO_PKG_NAME");

pub const JSON_RPC_VERSION: &str = "2.0";

// #[derive(Debug)]
pub struct TextDocument {
    text: String,
    version: u64,
    syntax_tree: Option<tree_sitter::Tree>,
}

pub struct DocumentsData {
    map: HashMap<String, Arc<TextDocument>>,
    parser: tree_sitter::Parser,
}

impl DocumentsData {
    fn new() -> Self {
        let map = HashMap::new();
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_bpftrace::LANGUAGE.into())
            .expect("Error loading bpftrace grammar"); //TODO
        Self { map, parser }
    }
}

pub struct DocumentsState(LazyLock<RwLock<DocumentsData>>);

pub static DOCUMENTS_STATE: DocumentsState =
    DocumentsState(LazyLock::new(|| RwLock::new(DocumentsData::new())));

impl DocumentsState {
    fn get(&self, uri: &str) -> Option<Arc<TextDocument>> {
        let read_guard = self.0.read().unwrap();
        read_guard.map.get(uri).cloned()
    }

    fn set(&self, uri: String, text: String, version: u64) {
        let mut write_guard = self.0.write().unwrap();

        let syntax_tree = write_guard.parser.parse(text.as_bytes(), None);

        let text_doc = Arc::new(TextDocument {
            text,
            version,
            syntax_tree,
        });
        write_guard.map.insert(uri, text_doc);
    }
}

pub fn unpack_text_document_info(content: json::JsonValue) -> (String, usize, usize) {
    let uri = content["params"]["textDocument"]["uri"].to_string();

    let position = &content["params"]["position"];

    let line_nr = position["line"].as_usize().unwrap_or_default();
    let char_nr = position["character"].as_usize().unwrap_or_default();

    (uri, line_nr, char_nr)
}

#[macro_export]
macro_rules! get_document_state {
    ($text_doc:ident, $line_nr:ident, $char_nr:ident, $none:expr, $log:ident) => {{
        let Some(tree) = &$text_doc.syntax_tree else {
            return $none;
        };

        let text = &$text_doc.text;

        let log_str = match $log {
            log_mod::COMPL => "Completion",
            log_mod::HOVER => "Hover",
            log_mod::DEFIN => "Definition",
            log_mod::REFER => "References",
            _ => "",
        };

        let line_str = text.lines().nth($line_nr).unwrap_or_default();
        log_dbg!(
            $log,
            "{} for line {}: '{}', char at {}: '{}'",
            log_str,
            $line_nr,
            line_str,
            $char_nr,
            line_str.chars().nth($char_nr).unwrap_or_default()
        );

        let (loc, node) = parser::find_syntax_location(text, tree, $line_nr, $char_nr);
        log_dbg!($log, "{}: found syntax location: {:?}", log_str, loc);

        (text, loc, node, line_str)
    }};
}

#[derive(Debug)]
enum LspMessageType {
    Request(u64),
    Response,
    Notification,
}

enum NotificationAction {
    None,
    Exit,
    SendDiagnostics(String),
}

struct LspClientMessage {
    msg_type: LspMessageType,
    method: String,
    content: json::JsonValue,
    start_time: Instant,
}

struct DiagnosticsResutls {
    uri: String,
    version: u64,
    diagnostics: json::JsonValue,
}

struct DiagnosticsRequest {
    uri: String,
    version: u64,
}

enum MpscMessage {
    ClientMessage(LspClientMessage),
    Diagnostics(DiagnosticsResutls),
}

enum DiagnosticsCommand {
    DiagRequest(DiagnosticsRequest),
    Exit,
}

fn handle_notification(method: String, content: json::JsonValue) -> NotificationAction {
    match &method[..] {
        "textDocument/didOpen" => {
            let text_document = &content["params"]["textDocument"];
            let uri = text_document["uri"].to_string();
            let text = text_document["text"].to_string();
            let version = text_document["version"].as_u64().unwrap_or_default();

            DOCUMENTS_STATE.set(uri.clone(), text, version);

            log_dbg!(NOTIF, "Open: textDocument: {}", text_document);
            return NotificationAction::SendDiagnostics(uri);
        }
        "textDocument/didChange" => {
            let text_document = &content["params"]["textDocument"];
            let uri = text_document["uri"].to_string();
            let version = text_document["version"].as_u64().unwrap_or_default();

            let changes = &content["params"]["contentChanges"];
            let text = changes[0]["text"].to_string();

            // let text_doc = Arc::new(TextDocument { text, version });
            DOCUMENTS_STATE.set(uri.clone(), text, version);

            log_dbg!(NOTIF, "Change: textDocument: {}", text_document);
            return NotificationAction::SendDiagnostics(uri);
        }
        "textDocument/didSave" => {
            let text_document = &content["params"]["textDocument"];
            let uri = text_document["uri"].to_string();
            return NotificationAction::SendDiagnostics(uri);
        }
        "exit" => {
            return NotificationAction::Exit;
        }
        _ => log_dbg!(
            NOTIF,
            "Unhandled {} notification with content {}",
            method,
            content
        ),
    }

    NotificationAction::None
}

fn encode_initalize_result() -> json::JsonValue {
    let capabilities = object! {
        "textDocumentSync": 1,
        "hoverProvider": true,
        "definitionProvider": true,
        "referencesProvider": true,
        // "codeActionProvider": true,
        "completionProvider": {
            "triggerCharacters": [":", ".", ">", "$", "@"],
            // TODO "resolveProvider": true,

        },
    };

    let server_info = object! {
        name: PKG_NAME,
        version: PKG_VERSION,
    };

    let data = object! {
        "result": {
            "capabilities": capabilities,
            "serverInfo": server_info,
        },
    };

    data
}

fn encode_shutdown() -> json::JsonValue {
    let data = object! {
        "result": null,
    };

    data
}

fn encode_no_definition() -> json::JsonValue {
    object! { "result": json::JsonValue::Null }
}

fn encode_definition(content: json::JsonValue) -> json::JsonValue {
    let (uri, line_nr, char_nr) = unpack_text_document_info(content);

    let Some(text_doc) = DOCUMENTS_STATE.get(&uri) else {
        return encode_no_definition();
    };

    let (text, _loc, main_node, _line_str) =
        get_document_state!(text_doc, line_nr, char_nr, encode_no_definition(), DEFIN);

    let mut def_node = None;

    if let Some(func_call) = parser::is_location_function_call(text, &main_node, line_nr, char_nr) {
        let call_name = func_call.utf8_text(text.as_bytes()).unwrap_or_default();
        log_dbg!(DEFIN, "Definition for function call: {}", call_name);

        let all_macros = parser::find_source_file_macros(&main_node, text);
        log_vdbg!(DEFIN, "All macros definitions: {:?}", all_macros);

        for m in all_macros {
            if m.0 == call_name {
                def_node = Some(m.1);
                break;
            }
        }
    }

    if let Some((map_var, _refs)) =
        parser::is_location_map_variable(text, &main_node, line_nr, char_nr, false)
    {
        let full_name = map_var.utf8_text(text.as_bytes()).unwrap_or_default();
        let (name, _) = full_name.split_once("[").unwrap_or((full_name, ""));
        log_dbg!(DEFIN, "Definition for map_variable: {}", name);

        let assignments = parser::find_all_map_variable_assignments(text, &main_node);
        log_vdbg!(DEFIN, "All map varibles assignments {:?}", assignments);

        for map_node in assignments {
            let Ok(map_var_full_name) = map_node.utf8_text(text.as_bytes()) else {
                continue;
            };

            let (map_var_name, _) = map_var_full_name
                .split_once("[")
                .unwrap_or((map_var_full_name, ""));

            if map_var_name == name {
                def_node = Some(map_node);
                break;
            }
        }
    }

    if let Some(def) = def_node {
        let start = def.start_position();
        let end = def.end_position();
        log_dbg!(
            DEFIN,
            "Found {} defintion at ({},{}) - ({},{})",
            def.kind(),
            start.row,
            start.column,
            end.row,
            end.column,
        );

        let data = object! {
            "result": {
                "uri": uri.to_string(),
                "range": {
                    "start": { "line": start.row, "character": start.column,},
                    "end": {"line": end.row, "character": end.column, },
                },
            },
        };

        data
    } else {
        encode_no_definition()
    }
}

fn encode_no_references() -> json::JsonValue {
    object! { "result": json::JsonValue::Null }
}

fn encode_references_for_nodes<'t>(
    uri: String,
    ref_nodes: Vec<tree_sitter::Node<'t>>,
) -> json::JsonValue {
    let mut location = json::JsonValue::new_array();

    if ref_nodes.is_empty() {
        return encode_no_references();
    }

    for node in ref_nodes {
        let start = node.start_position();
        let end = node.end_position();

        let loc = object! {
            "uri": uri.clone(),
            "range": {
                "start": { "line": start.row, "character": start.column },
                 "end": { "line": end.row, "character": end.column },
            },
        };
        let _ = location.push(loc);
    }

    let data = object! {
        "result": location,
    };

    data
}

fn get_references_for_map_variable<'t>(
    text: &str,
    main_node: &'t tree_sitter::Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Vec<tree_sitter::Node<'t>>> {
    let (_map_var, map_var_refs) =
        parser::is_location_map_variable(text, main_node, line_nr, char_nr, true)?;

    Some(map_var_refs)
}

fn get_references_for_macro<'t>(
    text: &str,
    loc: parser::SyntaxLocation,
    main_node: &'t tree_sitter::Node,
    line_nr: usize,
    char_nr: usize,
) -> Option<Vec<tree_sitter::Node<'t>>> {
    let mut macro_name = "";

    if loc == parser::SyntaxLocation::MacroDefinition {
        if let Some(name_node) = parser::is_location_macro_name(main_node, line_nr, char_nr) {
            macro_name = name_node.utf8_text(text.as_bytes()).unwrap_or_default();
            log_dbg!(REFER, "References for macro defintion: {}", macro_name);
        }
    }

    if macro_name.is_empty() {
        if let Some(func_call) =
            parser::is_location_function_call(text, main_node, line_nr, char_nr)
        {
            macro_name = func_call.utf8_text(text.as_bytes()).unwrap_or_default();
            log_dbg!(REFER, "References for function call: {}", macro_name);
        }
    }

    if macro_name.is_empty() {
        return None;
    }

    Some(parser::find_source_file_func_calls(
        main_node, text, macro_name,
    ))
}

fn encode_references(content: json::JsonValue) -> json::JsonValue {
    let (uri, line_nr, char_nr) = unpack_text_document_info(content);

    let Some(text_doc) = DOCUMENTS_STATE.get(&uri) else {
        return encode_no_references();
    };

    let (text, loc, main_node, _line_str) =
        get_document_state!(text_doc, line_nr, char_nr, encode_no_references(), REFER);

    if let Some(ref_nodes) = get_references_for_map_variable(text, &main_node, line_nr, char_nr) {
        encode_references_for_nodes(uri, ref_nodes)
    } else if let Some(ref_nodes) =
        get_references_for_macro(text, loc, &main_node, line_nr, char_nr)
    {
        encode_references_for_nodes(uri, ref_nodes)
    } else {
        encode_no_references()
    }
}

// TODO implement correct codeAction and enable codeActionProvider
fn encode_code_action(content: json::JsonValue) -> json::JsonValue {
    log_err!("Received codeAction with data {}", content);
    let uri = &content["params"]["textDocument"]["uri"].to_string();

    let range = &content["params"]["range"];
    let start = &range["start"];
    let end = &range["end"];

    let (start_line, _start_char) = (
        start["line"].as_u64().unwrap(),
        start["character"].as_u64().unwrap(),
    );

    let (end_line, _end_char) = (
        end["line"].as_u64().unwrap(),
        end["character"].as_u64().unwrap(),
    );

    let text_edit = object! {
        "range": {
            "start": { "line": start_line, "character": 0,},
            "end": { "line": end_line, "character": 0, }
        },

         "newText": format!("{}: ", start_line),
    };

    let code_action = object! {
        "title": "Add line number at the beginning\r\n",
        "edit": {
            "changes": {
                [uri]: [text_edit],
            },
        }
    };

    let data = object! {
        "result": [code_action],
    };

    data
}

fn do_parser_diagnostics(text: &str, root_node: &tree_sitter::Node) -> json::JsonValue {
    let error_nodes = parser::find_errors(text, root_node);

    let mut diagnostics = json::JsonValue::new_array();
    for node in error_nodes {
        let start = node.start_position();
        let end = node.end_position();

        let line_nr = start.row;
        let char_nr = start.column;

        let end_line_nr = end.row;
        let end_char_nr = end.column;

        let mut diag = object! {
            "range": {
                "start": { "line": line_nr, "character": char_nr },
                 "end": { "line": end_line_nr, "character": end_char_nr },
            },
            "severity": 1,
            "source": "parser",
            "message": format!("Parse error"),
        };

        if node.is_missing() && node.kind().len() == 1 {
            diag["message"] = format!("Missing '{}'", node.kind()).into();
        } else {
            diag["message"] = "Parse error".into();
        }
        let _ = diagnostics.push(diag);
    }
    diagnostics
}

// Parse single line errors:
// stdin:6:60-69: ERROR: str() expects an integer or a pointer type as first argument (struct _tracepoint_syscalls_sys_exit_bpf provided)
fn bpftrace_diag_single_line_error(
    mut line_nr: usize,
    tokens: &[&str],
) -> Result<json::JsonValue, std::num::ParseIntError> {
    assert!(tokens.len() > 2);

    if line_nr > 1 {
        line_nr -= 1;
    }

    let chars: Vec<&str> = tokens[2].split("-").collect();
    let start_char_nr: usize = chars[0].parse()?;
    let end_char_nr: usize = chars[1].parse()?;

    let to_severity = |e: &str| -> u32 {
        match e.trim() {
            "ERROR" => 1,
            _ => 2,
        }
    };

    let tail = if tokens.len() > 4 {
        tokens[4..].join(":")
    } else {
        "".to_string()
    };

    let diag = object! {
        "range": { "start": { "line": line_nr, "character": start_char_nr}, "end": {"line": line_nr, "character": end_char_nr, }, },
        "severity": to_severity(tokens[3]),
        // "source": "bpftrace -d",
        "message": format!("{}:{}", tokens[3], tail),
    };

    Ok(diag)
}

// Parse errors with lines range like this:
// stdin:2-4: ERROR: Invalid probe type: kkprobe
fn bpftrace_diag_multi_line_error(
    tokens: &[&str],
) -> Result<json::JsonValue, std::num::ParseIntError> {
    assert!(tokens.len() > 1);

    let start_and_end: Vec<&str> = tokens[1].split("-").collect();

    let mut line_nr: usize = start_and_end[1].parse()?;
    if line_nr > 1 {
        line_nr -= 1;
    }

    let mut end_line_nr: usize = start_and_end[1].parse()?;
    if end_line_nr > 1 {
        end_line_nr -= 1;
    }

    let to_severity = |e: &str| -> u32 {
        match e.trim() {
            "ERROR" => 1,
            _ => 2,
        }
    };

    let tail = if tokens.len() > 3 {
        tokens[3..].join(":")
    } else {
        "".to_string()
    };

    let diag = object! {
        "range": { "start": { "line": line_nr, "character": 0}, "end": {"line": end_line_nr, "character": 0, }, },
        "severity": to_severity(tokens[2]),
        // "source": "bpftrace -d",
        "message": format!("{}:{}", tokens[2], tail),
    };

    Ok(diag)
}

// Parse definitions errors:
// definitions.h:10:18: error: expected ';' at end of declaration list
fn bpftrace_diag_definitions_error(
    tokens: &[&str],
) -> Result<json::JsonValue, std::num::ParseIntError> {
    assert!(tokens.len() > 2);

    let mut line_nr = tokens[1].parse::<usize>()?;
    if line_nr > 1 {
        line_nr -= 1;
    }

    let end_char_nr = tokens[2].parse::<usize>()?;
    let start_char_nr = if end_char_nr > 0 {
        end_char_nr - 1
    } else {
        end_char_nr
    };

    let msg = if tokens.len() > 4 {
        tokens[4..].join(":")
    } else {
        "".to_string()
    };

    let diag = object! {
        "range": { "start": { "line": line_nr, "character": start_char_nr}, "end": {"line": line_nr, "character": end_char_nr, }, },
        "severity": 1,
        // "source": "bpftrace -d",
        "message": format!("ERROR:{}", msg),
    };

    Ok(diag)
}

fn do_bpftrace_diagnostics(text: &str) -> json::JsonValue {
    let mut diagnostics = json::JsonValue::new_array();

    let output = if let Ok(ok_output) = cmd_mod::bpftrace_dry_run_command(text) {
        ok_output
    } else {
        return diagnostics;
    };

    let output = if let Ok(ok_output) = String::from_utf8(output.stderr) {
        ok_output
    } else {
        return diagnostics;
    };

    log_vdbg!(DIAGN, "Parsing bpftrace dry-run lines:");

    for line in output.lines() {
        let tokens: Vec<&str> = line.split(":").collect();
        log_vdbg!(DIAGN, "{}", line);

        if tokens.len() < 3 {
            continue;
        }

        let diag_res = if tokens[0] == "stdin" {
            let stdin_diag_err = if let Ok(line_nr) = tokens[1].parse::<usize>() {
                bpftrace_diag_single_line_error(line_nr, &tokens)
            } else {
                bpftrace_diag_multi_line_error(&tokens)
            };
            stdin_diag_err
        } else if tokens[0] == "definitions.h" {
            bpftrace_diag_definitions_error(&tokens)
        } else {
            continue;
        };

        if let Ok(diag) = diag_res {
            let _ = diagnostics.push(diag);
        }
    }

    diagnostics
}

fn send_diag_command(uri: String, version: u64, diag_tx: &mpsc::Sender<DiagnosticsCommand>) {
    log_dbg!(
        DIAGN,
        "Send diagnostics command for uri {} version {}",
        uri,
        version,
    );

    let diag_req = DiagnosticsRequest { uri, version };

    let _ = diag_tx.send(DiagnosticsCommand::DiagRequest(diag_req));
}

fn do_diagnostics(uri: String, diag_tx: &mpsc::Sender<DiagnosticsCommand>) -> Option<String> {
    let Some(text_doc) = DOCUMENTS_STATE.get(&uri) else {
        log_dbg!(DIAGN, "No text document for {}", uri);
        return None;
    };

    if text_doc.text.trim().is_empty() {
        log_dbg!(DIAGN, "No diagnostics for empty text {}", text_doc.text);
        return None;
    }

    let version = text_doc.version;

    // If there are parser errors publish those
    if let Some(tree) = &text_doc.syntax_tree {
        if cfg!(feature = "parser_diagnostics") && tree.root_node().has_error() {
            let diagnostics = do_parser_diagnostics(&text_doc.text, &tree.root_node());
            let diag_results = DiagnosticsResutls {
                uri,
                version,
                diagnostics,
            };

            return publish_diagnostics(diag_results);
        }
    }

    // Otherwise send command to diffrent thread to do bpftrace --dry-run for diagnostics
    send_diag_command(uri, version, diag_tx);
    None
}

fn send_diag_exit(diag_tx: &mpsc::Sender<DiagnosticsCommand>) {
    let _ = diag_tx.send(DiagnosticsCommand::Exit);
}

fn publish_diagnostics(diag_results: DiagnosticsResutls) -> Option<String> {
    let uri = &diag_results.uri;
    log_dbg!(
        DIAGN,
        "Got diagnostics results for uri: {} version {}",
        uri,
        diag_results.version
    );

    let text_doc = DOCUMENTS_STATE.get(uri)?;

    if text_doc.version != diag_results.version {
        log_dbg!(
            DIAGN,
            "Text document versions do not match: {} vs {}",
            text_doc.version,
            diag_results.version
        );
        return None;
    }

    log_vdbg!(DIAGN, "Text: \n{}\n", &text_doc.text);

    let params = object! {
        "uri": uri.to_string(),
        "version": text_doc.version,
        "diagnostics": diag_results.diagnostics,
    };

    let data = object! {
        "jasonrpc": JSON_RPC_VERSION,
        "method": "textDocument/publishDiagnostics",
        "params": params,
    };

    let resp = data.dump();
    Some(format!(
        "Content-Length: {}\r\n\r\n{}\r\n",
        resp.len() + 2,
        resp
    ))
}

fn encode_message(id: u64, method: &str, content: json::JsonValue) -> String {
    let mut data = match method {
        "initialize" => encode_initalize_result(),
        "shutdown" => encode_shutdown(),
        "textDocument/hover" => completion::encode_hover(content),
        "textDocument/definition" => encode_definition(content),
        "textDocument/references" => encode_references(content),
        "textDocument/codeAction" => encode_code_action(content),
        "textDocument/completion" => completion::encode_completion(content),
        "completionItem/resolve" => completion::encode_completion_resolve(content),
        unhandled_method => {
            log_dbg!(PROTO, "No handler for method: {}", unhandled_method);
            object! {}
        }
    };

    data["id"] = id.into();
    data["jasonrpc"] = JSON_RPC_VERSION.into();

    let resp = data.dump();
    format!("Content-Length: {}\r\n\r\n{}\r\n", resp.len() + 2, resp)
}

fn decode_message(msg: String) -> (LspMessageType, String, json::JsonValue) {
    // TODO remove unwrap() and handle errors
    let content = json::parse(&msg).unwrap();

    let method = &content["method"];
    //let client_info = &content["params"]["clientInfo"];
    //log_dbg!(PROTO, "client Info {}", client_info);

    let msg_type;

    if let Some(id) = content["id"].as_u64() {
        if !content["result"].is_null() || !content["error"].is_null() {
            msg_type = LspMessageType::Response;
        } else {
            msg_type = LspMessageType::Request(id);
        }
    } else {
        msg_type = LspMessageType::Notification;
    }

    log_dbg!(PROTO, "Received {} {:?}", method, msg_type);

    (msg_type, method.to_string(), content)
}

fn recv_message() -> Result<String, i32> {
    log_vdbg!(PROTO, "Wait for the next message");
    let mut header = String::new();
    io::stdin()
        .read_line(&mut header)
        .expect("Failed to read header");

    let start_idx = "Content-Length: ".len();
    if header.len() < start_idx {
        log_err!("Not enough input, got header: '{}'\n", header);
        return Err(-1);
    }

    let parse_result = header[start_idx..].trim().parse::<usize>();
    let len = match parse_result {
        Ok(val) => val,
        Err(_) => {
            log_err!("Failed to parse length");
            return Err(-2);
        }
    };
    // let mut buf: Vec<u8> = Vec::with_capacity(len);
    let mut buf: Vec<u8> = vec![0; len];
    let mut n_read = 0;
    let mut idx = 0;
    let mut count = 0;

    // Skip empty line
    io::stdin()
        .read_line(&mut header)
        .expect("Failed to eat empty line");

    loop {
        match io::stdin().read(&mut buf[idx..]) {
            Ok(n) => {
                log_dbg!(PROTO, "Read n bytes {} buf.len() {}", n, buf.len());
                n_read += n;
                count += 0;
                if count > 9 {
                    break;
                }
            }
            Err(e) => log_err!("Read error {}", e),
        }

        // TODO: handle partial messages
        if n_read < len {
            idx = n_read;
            continue;
        }

        break;
    }

    match String::from_utf8(buf) {
        Ok(s) => {
            log_vdbg!(PROTO, "Read message: '{}'", s);
            return Ok(s);
        }
        Err(e) => log_err!("Failed to convert to string: {}", e),
    }

    Err(-1)
}

fn send_message(s: String) {
    let res = io::stdout().write(s.as_bytes());
    match res {
        Ok(n) => log_dbg!(PROTO, "Send {} bytes out of {}", n, s.len()),
        Err(e) => log_err!("Failed to write to stdout with error {}", e),
    }
}

fn thread_input(mpsc_tx: mpsc::Sender<MpscMessage>) {
    let mut error_count = 0;

    loop {
        match recv_message() {
            Ok(msg) => {
                let start_time = Instant::now();
                let (msg_type, method, content) = decode_message(msg);

                let exit: bool = match &msg_type {
                    LspMessageType::Notification => method == "exit",
                    _ => false,
                };

                let lsp_client_msg = LspClientMessage {
                    msg_type,
                    method,
                    content,
                    start_time,
                };

                let res = mpsc_tx.send(MpscMessage::ClientMessage(lsp_client_msg));
                if let Err(err) = res {
                    log_err!("MPSC send error {}", err);
                    break;
                }

                if exit {
                    log_dbg!(PROTO, "Received exit notification");
                    break;
                }
            }

            Err(e) => {
                log_err!("Read error {}", e);
                error_count += 1;
                if error_count >= 10 {
                    log_err!("To many read errors, exiting ...");
                    break;
                }
            }
        }
    }
}

fn thread_diagnostics(
    mpsc_tx: mpsc::Sender<MpscMessage>,
    diag_rx: mpsc::Receiver<DiagnosticsCommand>,
) {
    loop {
        match diag_rx.recv() {
            Ok(diag_msg) => match diag_msg {
                DiagnosticsCommand::DiagRequest(diag_req) => {
                    let uri = diag_req.uri;
                    let version = diag_req.version;

                    // Skip diagnostics if file is edited
                    // TODO: check if 300ms is more or less good heuristics
                    thread::sleep(Duration::from_millis(300));

                    let option = DOCUMENTS_STATE.get(&uri);
                    if option.is_none() {
                        log_err!("Can not find document for {uri}");
                        continue;
                    }
                    let text_doc = option.unwrap();

                    if text_doc.version != diag_req.version {
                        log_dbg!(
                            DIAGN,
                            "Skip diagnostics for old version {}, version is {}",
                            diag_req.version,
                            text_doc.version
                        );
                        continue;
                    }

                    let diagnostics = do_bpftrace_diagnostics(&text_doc.text);

                    let diag_msg = DiagnosticsResutls {
                        uri,
                        version,
                        diagnostics,
                    };
                    let _res = mpsc_tx.send(MpscMessage::Diagnostics(diag_msg));
                }
                DiagnosticsCommand::Exit => {
                    log_dbg!(DIAGN, "Exit diagnostics thread");
                    break;
                }
            },
            Err(e) => {
                log_err!("Diagnostics MPSC error {}", e);
                break;
            }
        }
    }
}

fn handle_client_msg(
    lsp_client_msg: LspClientMessage,
    diag_tx: &mpsc::Sender<DiagnosticsCommand>,
) -> bool {
    let LspClientMessage {
        msg_type,
        method,
        content,
        start_time,
    } = lsp_client_msg;

    match msg_type {
        LspMessageType::Request(id) => {
            let s = encode_message(id, &method, content);
            let time_diff = start_time.elapsed();
            log_dbg!(PROTO, "Response time {:?}", time_diff);
            log_vdbg!(PROTO, "Answer:\n{}", s);
            send_message(s);
            // TOOD response with InvalidRequest after shutdown
            // if method == "shutdown" {
            //     break;
            // }
            //
        }
        LspMessageType::Response => (),
        LspMessageType::Notification => {
            let notif_action = handle_notification(method, content);
            // TODO consider moving this to handle notification
            match notif_action {
                NotificationAction::SendDiagnostics(uri) => {
                    if let Some(s) = do_diagnostics(uri, diag_tx) {
                        log_dbg!(DIAGN, "Send diagnostics: {}", s);
                        send_message(s);
                    }
                }
                NotificationAction::Exit => {
                    log_dbg!(PROTO, "Exiting");
                    send_diag_exit(diag_tx);
                    return true;
                }
                NotificationAction::None => {}
            }
        }
    }

    false /* No exit */
}

fn main() {
    if let Err(e) = log_mod::create_logger("log.txt") {
        println!("Failed to create logger, error {e}");
    }

    log_dbg!(PROTO, "{} {} started", PKG_NAME, PKG_VERSION);

    let completion_init = thread::spawn(completion::init_available_traces);
    let command_init = thread::spawn(cmd_mod::init_bpftrace_dry_run);

    let (mpsc_tx, mpsc_rx) = mpsc::channel::<MpscMessage>();
    let diag_mpsc_tx = mpsc_tx.clone();
    thread::spawn(move || thread_input(mpsc_tx));

    let (diag_tx, diag_rx) = mpsc::channel::<DiagnosticsCommand>();
    thread::spawn(move || {
        let _ = completion_init.join();
        let _ = command_init.join();
        thread_diagnostics(diag_mpsc_tx, diag_rx)
    });

    loop {
        match mpsc_rx.recv() {
            Ok(mpsc_msg) => {
                match mpsc_msg {
                    MpscMessage::ClientMessage(client_msg) => {
                        let do_exit = handle_client_msg(client_msg, &diag_tx);
                        if do_exit {
                            break;
                        }
                    }
                    MpscMessage::Diagnostics(diag_results) => {
                        if let Some(s) = publish_diagnostics(diag_results) {
                            log_dbg!(DIAGN, "Send diagnostics: {}", s);
                            send_message(s);
                        }
                    }
                };
            }
            Err(err) => {
                log_err!("Subthread error {}", err);
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    static URI_COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn document_content_setup(text: &str, line_nr: usize, char_nr: usize) -> json::JsonValue {
        let uri = format!(
            "file:///main_test{}.bt",
            URI_COUNTER.fetch_add(1, Ordering::Relaxed)
        );

        DOCUMENTS_STATE.set(uri.to_string(), text.to_string(), 1);

        object! {
            "params": {
                "textDocument": {
                    "uri": uri,
                },
                "position": {
                    "line": line_nr,
                    "character": char_nr,
                }
            }
        }
    }

    #[test]
    fn test_decode_message() {
        let msg = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"capabilities":{"general":{"positionEncodings":["utf-16"]}}}}"#;

        let (msg_type, method, _content) = decode_message(msg.to_string());
        assert!(matches!(msg_type, LspMessageType::Request(1)));

        assert!(method == "initialize");
    }

    #[test]
    fn test_goto_macro_definition() {
        let text = r#"
macro print1(x) {
  print(x);
}
macro print2(x, y) {
  print1(x + y)
}
"#;
        let json_content = document_content_setup(text, 5, 4);

        let result = encode_definition(json_content);
        let start = &result["result"]["range"]["start"];
        assert_eq!(start["line"], 1);
        assert_eq!(start["character"], 0);

        let end = &result["result"]["range"]["end"];
        assert_eq!(end["line"], 3);
        assert_eq!(end["character"], 1);
    }

    #[test]
    fn test_goto_map_variable() {
        let text = r#"
fentry:rt2x00lib:rt2x00lib_config {
  @start[tid] = nsecs();
}

fexit:rt2x00lib:rt2x00lib_config {
  $duration = nsecs() - @start[tid];
  printf("%s took %u\n", probe(), $duration);
  delete(@start, tid);
}
"#;
        let json_content = document_content_setup(text, 8, 12);

        let result = encode_definition(json_content);
        let start = &result["result"]["range"]["start"];
        assert_eq!(start["line"], 2);
        assert_eq!(start["character"], 2);

        let end = &result["result"]["range"]["end"];
        assert_eq!(end["line"], 2);
        assert_eq!(end["character"], 13);
    }

    #[test]
    fn test_reference_macro_definition() {
        let text = r#"
macro foo(x) {
  print(x);
}
macro boo(x, y) {
  foo(x + y);
  foo(x - y);
  foo(x * y);
  foo(x / y);
}
"#;
        let json_content = document_content_setup(text, 1, 7);

        let result = encode_references(json_content);
        assert_eq!(result["result"].len(), 4);

        let start = &result["result"][0]["range"]["start"];
        assert_eq!(start["line"], 5);
        assert_eq!(start["character"], 2);

        let end = &result["result"][0]["range"]["end"];
        assert_eq!(end["line"], 5);
        assert_eq!(end["character"], 5);

        let start = &result["result"][3]["range"]["start"];
        assert_eq!(start["line"], 8);
        assert_eq!(start["character"], 2);

        let end = &result["result"][3]["range"]["end"];
        assert_eq!(end["line"], 8);
        assert_eq!(end["character"], 5);
    }

    #[test]
    fn test_reference_map_variable() {
        let text = r#"
fentry:rt2x00lib:rt2x00lib_config {
  @start[tid] = nsecs();
}

fexit:rt2x00lib:rt2x00lib_config {
  $duration = nsecs() - @start[tid];
  printf("%s took %u\n", probe(), $duration);
  delete(@start, tid);
}
"#;
        let json_content = document_content_setup(text, 8, 12);

        let result = encode_references(json_content);
        assert_eq!(result["result"].len(), 3);

        let start = &result["result"][0]["range"]["start"];
        assert_eq!(start["line"], 2);
        assert_eq!(start["character"], 2);

        let end = &result["result"][0]["range"]["end"];
        assert_eq!(end["line"], 2);
        assert_eq!(end["character"], 13);

        let start = &result["result"][1]["range"]["start"];
        assert_eq!(start["line"], 6);
        assert_eq!(start["character"], 24);

        let end = &result["result"][1]["range"]["end"];
        assert_eq!(end["line"], 6);
        assert_eq!(end["character"], 35);
    }
}
