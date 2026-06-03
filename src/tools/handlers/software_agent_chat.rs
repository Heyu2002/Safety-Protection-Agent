use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use tokio::io::AsyncWriteExt;

use crate::tools::{Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolSpec};

const TOOL_NAME: &str = "software_agent_chat";
const DEFAULT_TIMEOUT_MS: u64 = 30_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
const DEFAULT_RESPONSE_MAX_CHARS: usize = 12_000;
const MAX_RESPONSE_MAX_CHARS: usize = 60_000;

#[derive(Debug, Clone, Copy)]
pub struct SoftwareAgentChatTool;

#[async_trait]
impl ToolHandler for SoftwareAgentChatTool {
    fn name(&self) -> &'static str {
        TOOL_NAME
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Run an authorized conversation turn with a local CLI or software agent. Launches a process without a shell by default, sends user text through stdin or command placeholders, and returns the target agent output.",
            json!({
                "type": "object",
                "properties": {
                    "authorization_confirmed": {
                        "type": "boolean",
                        "description": "Must be true. Confirms the caller is authorized to run this local target agent command and send the provided user message."
                    },
                    "command": {
                        "type": "array",
                        "items": { "type": "string" },
                        "minItems": 1,
                        "description": "Executable and arguments for the target CLI/software agent. No shell is inserted. Arguments may include {{message}}, {{prompt}}, {{transcript}}, {{conversation_id}}, and {{turn}} placeholders."
                    },
                    "message": {
                        "type": "string",
                        "description": "Current user message to send to the target agent. Use this for a single turn."
                    },
                    "messages": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "role": {
                                    "type": "string",
                                    "enum": ["user", "assistant"]
                                },
                                "content": { "type": "string" }
                            },
                            "required": ["content"],
                            "additionalProperties": false
                        },
                        "description": "Optional prior transcript. When message is also supplied, it is appended as the latest user turn."
                    },
                    "stdin_template": {
                        "type": "string",
                        "description": "Optional stdin payload template. Defaults to {{message}} followed by newline unless the command already contains a message/transcript placeholder. Set to an empty string to send no stdin."
                    },
                    "conversation_id": {
                        "type": "string",
                        "description": "Optional caller-managed conversation label for the target agent."
                    },
                    "turn": {
                        "type": "integer",
                        "minimum": 1,
                        "default": 1
                    },
                    "working_dir": {
                        "type": "string",
                        "description": "Optional working directory for the target process."
                    },
                    "inherit_environment": {
                        "type": "boolean",
                        "default": true,
                        "description": "Whether the target process inherits the current environment. Set false for hermetic tests; provide environment explicitly if needed."
                    },
                    "environment": {
                        "type": "object",
                        "additionalProperties": { "type": "string" },
                        "description": "Optional environment variables to add or override. Values are not echoed in metadata."
                    },
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": 500,
                        "maximum": MAX_TIMEOUT_MS,
                        "default": DEFAULT_TIMEOUT_MS
                    },
                    "response_max_chars": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": MAX_RESPONSE_MAX_CHARS,
                        "default": DEFAULT_RESPONSE_MAX_CHARS
                    }
                },
                "required": ["authorization_confirmed", "command"],
                "additionalProperties": false
            }),
        )
    }

    async fn handle(&self, call: ToolCall) -> Result<ToolOutput> {
        let input: SoftwareAgentChatInput =
            serde_json::from_value(call.input).map_err(invalid_input(self.name()))?;
        let plan = input.into_plan(self.name())?;
        let rendered_command = render_command(&plan.command, &plan.context);
        let stdin_payload = render_template(&plan.stdin_template, &plan.context);
        let output = run_software_agent_process(&plan, &rendered_command, &stdin_payload).await?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = truncate(&stdout, plan.response_max_chars);
        let stderr = truncate(&stderr, plan.response_max_chars);
        let status_code = output.status.code();
        let content = format!(
            "software agent conversation complete\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status, stdout, stderr
        );

        Ok(ToolOutput::text(call.id, content).with_metadata(json!({
            "success": output.status.success(),
            "status_code": status_code,
            "conversation_id": plan.context.conversation_id,
            "turn": plan.context.turn,
            "program": rendered_command[0],
            "arg_count": rendered_command.len().saturating_sub(1),
            "stdin_chars": stdin_payload.chars().count(),
            "stdout_chars": stdout.chars().count(),
            "stderr_chars": stderr.chars().count(),
            "environment_keys": plan.environment.keys().cloned().collect::<Vec<_>>()
        })))
    }
}

#[derive(Debug, Deserialize)]
struct SoftwareAgentChatInput {
    authorization_confirmed: bool,
    command: Vec<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    messages: Vec<SoftwareAgentMessage>,
    #[serde(default)]
    stdin_template: Option<String>,
    #[serde(default)]
    conversation_id: Option<String>,
    #[serde(default = "default_turn")]
    turn: u64,
    #[serde(default)]
    working_dir: Option<PathBuf>,
    #[serde(default = "default_inherit_environment")]
    inherit_environment: bool,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_response_max_chars")]
    response_max_chars: usize,
}

#[derive(Debug, Deserialize)]
struct SoftwareAgentMessage {
    #[serde(default = "default_user_role")]
    role: String,
    content: String,
}

#[derive(Debug)]
struct SoftwareAgentChatPlan {
    command: Vec<String>,
    stdin_template: String,
    working_dir: Option<PathBuf>,
    inherit_environment: bool,
    environment: BTreeMap<String, String>,
    timeout_ms: u64,
    response_max_chars: usize,
    context: TemplateContext,
}

#[derive(Debug)]
struct TemplateContext {
    message: String,
    transcript: String,
    conversation_id: String,
    turn: u64,
}

impl SoftwareAgentChatInput {
    fn into_plan(self, tool: &str) -> Result<SoftwareAgentChatPlan> {
        if !self.authorization_confirmed {
            return Err(invalid(
                tool,
                "authorization_confirmed must be true for software agent chat",
            ));
        }
        if self.command.is_empty() || self.command[0].trim().is_empty() {
            return Err(invalid(tool, "command must include an executable"));
        }
        if self
            .command
            .iter()
            .any(|arg| arg.chars().any(|ch| ch == '\0'))
        {
            return Err(invalid(
                tool,
                "command arguments must not contain NUL bytes",
            ));
        }
        if self.timeout_ms < 500 || self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(invalid(
                tool,
                format!("timeout_ms must be between 500 and {MAX_TIMEOUT_MS}"),
            ));
        }
        if self.response_max_chars == 0 || self.response_max_chars > MAX_RESPONSE_MAX_CHARS {
            return Err(invalid(
                tool,
                format!("response_max_chars must be between 1 and {MAX_RESPONSE_MAX_CHARS}"),
            ));
        }

        let explicit_message = self
            .message
            .map(|message| message.trim_end_matches(['\r', '\n']).to_owned())
            .filter(|message| !message.trim().is_empty());
        if explicit_message.is_none() && self.messages.is_empty() {
            return Err(invalid(
                tool,
                "provide message or messages so there is user text to send",
            ));
        }

        validate_messages(tool, &self.messages)?;
        let message = explicit_message
            .clone()
            .or_else(|| {
                self.messages
                    .iter()
                    .rev()
                    .find(|message| message.role == "user")
                    .map(|message| message.content.clone())
            })
            .ok_or_else(|| {
                invalid(
                    tool,
                    "messages must include a user message when message is omitted",
                )
            })?;
        let transcript = render_transcript(&self.messages, explicit_message.as_deref());
        let conversation_id = self
            .conversation_id
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let stdin_template = self.stdin_template.unwrap_or_else(|| {
            if command_has_input_placeholder(&self.command) {
                String::new()
            } else if self.messages.is_empty() {
                "{{message}}\n".to_owned()
            } else {
                "{{transcript}}\n".to_owned()
            }
        });

        Ok(SoftwareAgentChatPlan {
            command: self.command,
            stdin_template,
            working_dir: self.working_dir,
            inherit_environment: self.inherit_environment,
            environment: self.environment,
            timeout_ms: self.timeout_ms,
            response_max_chars: self.response_max_chars,
            context: TemplateContext {
                message,
                transcript,
                conversation_id,
                turn: self.turn.max(1),
            },
        })
    }
}

async fn run_software_agent_process(
    plan: &SoftwareAgentChatPlan,
    rendered_command: &[String],
    stdin_payload: &str,
) -> Result<std::process::Output> {
    let mut command = tokio::process::Command::new(&rendered_command[0]);
    command.args(&rendered_command[1..]);
    if let Some(working_dir) = &plan.working_dir {
        command.current_dir(working_dir);
    }
    if !plan.inherit_environment {
        command.env_clear();
    }
    command.envs(&plan.environment);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = command.spawn().map_err(|error| ToolError::Execution {
        tool: TOOL_NAME.to_owned(),
        message: format!("failed to start target agent command: {error}"),
    })?;

    if let Some(mut stdin) = child.stdin.take()
        && !stdin_payload.is_empty()
    {
        stdin
            .write_all(stdin_payload.as_bytes())
            .await
            .map_err(|error| ToolError::Execution {
                tool: TOOL_NAME.to_owned(),
                message: format!("failed to write target agent stdin: {error}"),
            })?;
    }

    tokio::time::timeout(
        Duration::from_millis(plan.timeout_ms),
        child.wait_with_output(),
    )
    .await
    .map_err(|_| ToolError::Execution {
        tool: TOOL_NAME.to_owned(),
        message: format!("target agent command timed out after {}ms", plan.timeout_ms),
    })?
    .map_err(|error| ToolError::Execution {
        tool: TOOL_NAME.to_owned(),
        message: format!("failed to collect target agent output: {error}"),
    })
}

fn validate_messages(tool: &str, messages: &[SoftwareAgentMessage]) -> Result<()> {
    for message in messages {
        if !matches!(message.role.as_str(), "user" | "assistant") {
            return Err(invalid(tool, "messages role must be user or assistant"));
        }
        if message.content.trim().is_empty() {
            return Err(invalid(tool, "messages content must not be empty"));
        }
    }
    Ok(())
}

fn render_command(command: &[String], context: &TemplateContext) -> Vec<String> {
    command
        .iter()
        .map(|arg| render_template(arg, context))
        .collect()
}

fn render_template(template: &str, context: &TemplateContext) -> String {
    template
        .replace("{{message}}", &context.message)
        .replace("{{prompt}}", &context.message)
        .replace("{{transcript}}", &context.transcript)
        .replace("{{conversation_id}}", &context.conversation_id)
        .replace("{{turn}}", &context.turn.to_string())
}

fn command_has_input_placeholder(command: &[String]) -> bool {
    command.iter().any(|arg| {
        arg.contains("{{message}}") || arg.contains("{{prompt}}") || arg.contains("{{transcript}}")
    })
}

fn render_transcript(messages: &[SoftwareAgentMessage], message: Option<&str>) -> String {
    let mut lines = messages
        .iter()
        .map(|entry| format!("{}: {}", entry.role, entry.content.trim_end()))
        .collect::<Vec<_>>();
    if let Some(message) = message {
        lines.push(format!("user: {message}"));
    }
    lines.join("\n")
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let mut truncated = text.chars().take(max_chars).collect::<String>();
    truncated.push_str("\n[truncated]");
    truncated
}

fn default_turn() -> u64 {
    1
}

fn default_inherit_environment() -> bool {
    true
}

fn default_user_role() -> String {
    "user".to_owned()
}

fn default_timeout_ms() -> u64 {
    DEFAULT_TIMEOUT_MS
}

fn default_response_max_chars() -> usize {
    DEFAULT_RESPONSE_MAX_CHARS
}

fn invalid(tool: &str, message: impl Into<String>) -> ToolError {
    ToolError::InvalidInput {
        tool: tool.to_owned(),
        message: message.into(),
    }
}

fn invalid_input(tool: &'static str) -> impl FnOnce(serde_json::Error) -> ToolError {
    move |error| ToolError::InvalidInput {
        tool: tool.to_owned(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tools::ToolCall;

    #[tokio::test]
    async fn requires_authorization() {
        let result = SoftwareAgentChatTool
            .handle(ToolCall::new(
                TOOL_NAME,
                json!({
                    "authorization_confirmed": false,
                    "command": ["echo", "hello"],
                    "message": "hello"
                }),
            ))
            .await;

        assert!(matches!(result, Err(ToolError::InvalidInput { .. })));
    }

    #[tokio::test]
    async fn sends_message_to_stdin() {
        let output = SoftwareAgentChatTool
            .handle(ToolCall::new(
                TOOL_NAME,
                json!({
                    "authorization_confirmed": true,
                    "command": echo_stdin_command(),
                    "message": "hello-from-spa",
                    "timeout_ms": 5000
                }),
            ))
            .await
            .expect("echo command should run");

        assert!(output.content.contains("hello-from-spa"));
        assert_eq!(output.metadata.unwrap()["success"], true);
    }

    #[test]
    fn command_placeholder_disables_default_stdin() {
        let input = SoftwareAgentChatInput {
            authorization_confirmed: true,
            command: vec!["agent".to_owned(), "--prompt={{message}}".to_owned()],
            message: Some("hello".to_owned()),
            messages: Vec::new(),
            stdin_template: None,
            conversation_id: Some("conversation-1".to_owned()),
            turn: 2,
            working_dir: None,
            inherit_environment: true,
            environment: BTreeMap::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            response_max_chars: DEFAULT_RESPONSE_MAX_CHARS,
        };

        let plan = input.into_plan(TOOL_NAME).expect("plan should build");
        let command = render_command(&plan.command, &plan.context);

        assert_eq!(command[1], "--prompt=hello");
        assert_eq!(plan.stdin_template, "");
    }

    #[test]
    fn renders_transcript_when_messages_are_provided() {
        let input = SoftwareAgentChatInput {
            authorization_confirmed: true,
            command: vec!["agent".to_owned()],
            message: Some("current".to_owned()),
            messages: vec![
                SoftwareAgentMessage {
                    role: "user".to_owned(),
                    content: "first".to_owned(),
                },
                SoftwareAgentMessage {
                    role: "assistant".to_owned(),
                    content: "reply".to_owned(),
                },
            ],
            stdin_template: None,
            conversation_id: None,
            turn: 1,
            working_dir: None,
            inherit_environment: true,
            environment: BTreeMap::new(),
            timeout_ms: DEFAULT_TIMEOUT_MS,
            response_max_chars: DEFAULT_RESPONSE_MAX_CHARS,
        };

        let plan = input.into_plan(TOOL_NAME).expect("plan should build");
        let stdin = render_template(&plan.stdin_template, &plan.context);

        assert!(stdin.contains("user: first"));
        assert!(stdin.contains("assistant: reply"));
        assert!(stdin.contains("user: current"));
    }

    fn echo_stdin_command() -> Vec<String> {
        if cfg!(windows) {
            vec!["cmd.exe".to_owned(), "/C".to_owned(), "more".to_owned()]
        } else {
            vec!["sh".to_owned(), "-c".to_owned(), "cat".to_owned()]
        }
    }
}
