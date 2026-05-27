use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{Value, json};

#[test]
fn agent_lab_mcp_stdio_initialize_list_and_call_tool() {
    let exe = env!("CARGO_BIN_EXE_spa-agent-lab-mcp");
    let mut child = Command::new(exe)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("agent lab MCP binary should start");

    {
        let stdin = child.stdin.as_mut().expect("stdin should be piped");
        write_json_line(
            stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "agent-lab-test",
                        "version": "0.0.0"
                    }
                }
            }),
        );
        write_json_line(
            stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }),
        );
        write_json_line(
            stdin,
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "agent_lab_complete",
                    "arguments": {}
                }
            }),
        );
    }

    let output = child.wait_with_output().expect("child should exit cleanly");
    assert!(output.status.success());
    assert!(
        output.stderr.is_empty(),
        "stderr should not be needed for the happy path: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    let messages: Vec<Value> = stdout
        .lines()
        .map(|line| serde_json::from_str(line).expect("stdout line should be JSON-RPC"))
        .collect();

    assert_eq!(messages.len(), 3);
    assert_eq!(
        messages[0]["result"]["serverInfo"]["name"],
        "safety-protection-agent-lab-mcp"
    );
    assert!(
        messages[1]["result"]["tools"]
            .as_array()
            .expect("tools should be an array")
            .iter()
            .any(|tool| tool["name"] == "agent_lab_get_task")
    );
    assert_eq!(messages[2]["result"]["isError"], false);
    assert!(
        messages[2]["result"]["content"][0]["text"]
            .as_str()
            .expect("tool result text")
            .contains("Agent lab complete")
    );
}

fn write_json_line(stdin: &mut std::process::ChildStdin, value: Value) {
    writeln!(stdin, "{}", serde_json::to_string(&value).unwrap()).unwrap();
}
