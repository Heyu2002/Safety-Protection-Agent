use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

use crate::llm::{CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError, Result};

pub struct CodexChatGptClient {
    http: Client,
    config: LlmConfig,
}

impl CodexChatGptClient {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl LlmClient for CodexChatGptClient {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let auth = CodexAuthDotJson::load()?;
        let tokens = auth.tokens.ok_or_else(|| LlmError::Provider {
            status: 0,
            body: "Codex auth.json does not contain ChatGPT tokens".to_string(),
        })?;

        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let mut instructions = Vec::new();
        let mut input = Vec::new();

        for message in &request.messages {
            match message.role.as_openai_role() {
                "system" => instructions.push(message.content.as_str()),
                role => input.push(json!({
                    "type": "message",
                    "role": role,
                    "content": [{
                        "type": "input_text",
                        "text": message.content,
                    }],
                })),
            }
        }

        let body = json!({
            "model": self.config.model,
            "instructions": instructions.join("\n\n"),
            "input": input,
            "tools": [],
            "tool_choice": "auto",
            "parallel_tool_calls": false,
            "store": false,
            "stream": true,
            "include": [],
        });

        let session_id = Uuid::new_v4().to_string();
        let thread_id = Uuid::new_v4().to_string();
        let mut request_builder = self
            .http
            .post(url)
            .bearer_auth(tokens.access_token)
            .header("Accept", "text/event-stream")
            .header("originator", "codex_cli_rs")
            .header("session-id", session_id)
            .header("thread-id", thread_id);

        if let Some(account_id) = tokens.account_id {
            request_builder = request_builder.header("ChatGPT-Account-ID", account_id);
        }

        let response = request_builder.json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LlmError::Provider {
                status,
                body: response.text().await?,
            });
        }

        let body = response.text().await?;
        let content = parse_sse_output_text(&body).ok_or(LlmError::EmptyResponse)?;

        Ok(CompletionResponse {
            content,
            model: self.config.model.to_owned(),
            usage: None,
        })
    }
}

#[derive(Debug, Deserialize)]
struct CodexAuthDotJson {
    tokens: Option<CodexTokens>,
}

impl CodexAuthDotJson {
    fn load() -> Result<Self> {
        let path = std::env::var("CODEX_AUTH_JSON")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| default_codex_home().join("auth.json"));
        let contents = std::fs::read_to_string(path).map_err(|err| LlmError::Provider {
            status: 0,
            body: format!("failed to read Codex auth.json: {err}"),
        })?;
        serde_json::from_str(&contents).map_err(|err| LlmError::Provider {
            status: 0,
            body: format!("failed to parse Codex auth.json: {err}"),
        })
    }
}

#[derive(Debug, Deserialize)]
struct CodexTokens {
    access_token: String,
    account_id: Option<String>,
}

fn default_codex_home() -> std::path::PathBuf {
    if let Ok(home) = std::env::var("CODEX_HOME") {
        return std::path::PathBuf::from(home);
    }
    if let Ok(user_profile) = std::env::var("USERPROFILE") {
        return std::path::PathBuf::from(user_profile).join(".codex");
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home).join(".codex");
    }
    std::path::PathBuf::from(".codex")
}

fn parse_sse_output_text(body: &str) -> Option<String> {
    let mut output = String::new();
    for line in body.lines() {
        let Some(data) = line.strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        collect_text_from_event(&value, &mut output);
    }

    if output.is_empty() {
        None
    } else {
        Some(output)
    }
}

fn collect_text_from_event(value: &Value, output: &mut String) {
    match value.get("type").and_then(Value::as_str) {
        Some("response.output_text.delta") => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                output.push_str(delta);
            }
        }
        Some("response.completed") => {
            if output.is_empty()
                && let Some(response) = value.get("response")
            {
                collect_text_from_response(response, output);
            }
        }
        _ => {}
    }
}

fn collect_text_from_response(response: &Value, output: &mut String) {
    let Some(items) = response.get("output").and_then(Value::as_array) else {
        return;
    };
    for item in items {
        let Some(parts) = item.get("content").and_then(Value::as_array) else {
            continue;
        };
        for part in parts {
            if let Some(text) = part.get("text").and_then(Value::as_str) {
                output.push_str(text);
            }
        }
    }
}
