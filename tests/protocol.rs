use std::{
    io::{BufRead, Cursor, Read, Write},
    process::{Command, Output, Stdio},
};

fn add_server_input(input: &mut Vec<u8>, body: &[u8]) {
    input.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    input.extend_from_slice(body);
}

fn run_server(input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bpftrace-ls"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn read_server_output(output: &[u8]) -> Vec<json::JsonValue> {
    let mut input = Cursor::new(output);
    let mut messages = Vec::new();

    loop {
        let mut content_length = None;
        loop {
            let mut line = String::new();
            let n = input.read_line(&mut line).unwrap();
            if n == 0 {
                return messages;
            }
            if line == "\r\n" || line == "\n" {
                break;
            }

            if let Some((name, value)) = line.split_once(':') {
                if name.trim().eq_ignore_ascii_case("Content-Length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
            }
        }

        let mut body = vec![0; content_length.expect("response has Content-Length")];
        input.read_exact(&mut body).unwrap();
        let body = String::from_utf8(body).unwrap();
        messages.push(json::parse(body.trim_end_matches("\r\n")).unwrap());
    }
}

#[test]
fn server_init_and_exit() {
    let mut input = Vec::new();
    let initialize = br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
    let initialized = br#"{"jsonrpc":"2.0","method":"initialized","params":{}}"#;
    let shutdown = br#"{"jsonrpc":"2.0","id":2,"method":"shutdown"}"#;
    let exit = br#"{"jsonrpc":"2.0","method":"exit"}"#;

    add_server_input(&mut input, initialize);
    add_server_input(&mut input, initialized);
    add_server_input(&mut input, shutdown);
    add_server_input(&mut input, exit);

    let output = run_server(&input);
    assert!(output.status.success());

    let responses = read_server_output(&output.stdout);
    assert!(responses
        .iter()
        .any(|message| message["id"].as_i32() == Some(1)));
    assert!(responses
        .iter()
        .any(|message| message["id"].as_i32() == Some(2)));
}

#[test]
fn server_parse_error_for_invalid_json() {
    let mut input = Vec::new();
    add_server_input(&mut input, b"{invalid json");
    add_server_input(&mut input, br#"{"jsonrpc":"2.0","method":"exit"}"#);

    let output = run_server(&input);
    assert!(output.status.success());

    let responses = read_server_output(&output.stdout);
    assert!(responses.iter().any(|message| {
        message["id"].is_null() && message["error"]["code"].as_i32() == Some(-32700)
    }));
}

#[test]
fn server_parse_error_for_no_body() {
    let mut input = Vec::new();
    add_server_input(&mut input, b"");
    add_server_input(&mut input, br#"{"jsonrpc":"2.0","method":"exit"}"#);

    let output = run_server(&input);
    assert!(output.status.success());

    let responses = read_server_output(&output.stdout);
    assert!(responses.iter().any(|message| {
        message["id"].is_null() && message["error"]["code"].as_i32() == Some(-32700)
    }));
}
