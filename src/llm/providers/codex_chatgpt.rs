use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

use crate::llm::{
    AgentToolCall, AgentToolSpec, AgentTurnRequest, AgentTurnResponse, CompletionDeltaCallback,
    CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError, Result,
};

use super::sse::SseDecoder;

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
    fn supports_native_tools(&self) -> bool {
        true
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        self.complete_streaming(request, std::sync::Arc::new(|_| {}))
            .await
    }

    async fn complete_streaming(
        &self,
        request: CompletionRequest,
        on_delta: CompletionDeltaCallback,
    ) -> Result<CompletionResponse> {
        let auth = CodexAuthDotJson::load()?;
        let tokens = auth.tokens.ok_or_else(|| LlmError::Provider {
            status: 0,
            body: "Codex auth.json does not contain ChatGPT tokens".to_string(),
        })?;

        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let body = codex_responses_body(&self.config.model, &request);

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

        let content = read_responses_sse(response, on_delta).await?;

        Ok(CompletionResponse {
            content,
            model: self.config.model.to_owned(),
            usage: None,
        })
    }

    async fn complete_agent_turn(
        &self,
        request: AgentTurnRequest,
        on_delta: CompletionDeltaCallback,
    ) -> Result<AgentTurnResponse> {
        let auth = CodexAuthDotJson::load()?;
        let tokens = auth.tokens.ok_or_else(|| LlmError::Provider {
            status: 0,
            body: "Codex auth.json does not contain ChatGPT tokens".to_string(),
        })?;

        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let body = codex_agent_body(&self.config.model, &request);

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

        read_agent_responses_sse(response, self.config.model.to_owned(), on_delta).await
    }
}

fn codex_responses_body(model: &str, request: &CompletionRequest) -> Value {
    let mut instructions = Vec::new();
    let mut input = Vec::new();

    for message in &request.messages {
        match message.role.as_openai_role() {
            "system" => instructions.push(message.content.as_str()),
            role => input.push(json!({
                "type": "message",
                "role": role,
                "content": [{
                    "type": if role == "assistant" { "output_text" } else { "input_text" },
                    "text": message.content,
                }],
            })),
        }
    }

    json!({
        "model": model,
        "instructions": instructions.join("\n\n"),
        "input": input,
        "tools": [],
        "tool_choice": "auto",
        "parallel_tool_calls": false,
        "store": false,
        "stream": true,
        "include": [],
    })
}

fn codex_agent_body(model: &str, request: &AgentTurnRequest) -> Value {
    let (instructions, input) = codex_input(&request.messages, &request.input_items);
    let mut body = json!({
        "model": model,
        "instructions": instructions,
        "input": input,
        "tools": response_tools(&request.tools),
        "tool_choice": "auto",
        "parallel_tool_calls": false,
        "store": false,
        "stream": true,
        "include": [],
    });

    if let Some(temperature) = request.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(max_tokens) = request.max_tokens {
        body["max_output_tokens"] = json!(max_tokens);
    }

    body
}

fn codex_input(
    messages: &[crate::llm::ChatMessage],
    input_items: &[Value],
) -> (String, Vec<Value>) {
    let mut instructions = Vec::new();
    let mut input = Vec::new();

    for message in messages {
        match message.role.as_openai_role() {
            "system" => instructions.push(message.content.as_str()),
            role => input.push(json!({
                "type": "message",
                "role": role,
                "content": [{
                    "type": if role == "assistant" { "output_text" } else { "input_text" },
                    "text": message.content,
                }],
            })),
        }
    }

    input.extend(input_items.iter().cloned());
    (instructions.join("\n\n"), input)
}

fn response_tools(tools: &[AgentToolSpec]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "name": tool.name,
                "description": tool.description,
                "parameters": tool.input_schema,
            })
        })
        .collect()
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

async fn read_responses_sse(
    mut response: reqwest::Response,
    on_delta: CompletionDeltaCallback,
) -> Result<String> {
    let mut decoder = SseDecoder::default();
    let mut output = String::new();

    while let Some(chunk) = response.chunk().await? {
        for data in decoder.push(&String::from_utf8_lossy(&chunk)) {
            collect_text_from_sse_data(&data, &mut output, &on_delta);
        }
    }

    for data in decoder.finish() {
        collect_text_from_sse_data(&data, &mut output, &on_delta);
    }

    if output.is_empty() {
        Err(LlmError::EmptyResponse)
    } else {
        Ok(output)
    }
}

fn collect_text_from_sse_data(data: &str, output: &mut String, on_delta: &CompletionDeltaCallback) {
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(data.trim()) else {
        return;
    };
    collect_text_from_event(&value, output, on_delta);
}

fn collect_text_from_event(value: &Value, output: &mut String, on_delta: &CompletionDeltaCallback) {
    match value.get("type").and_then(Value::as_str) {
        Some("response.output_text.delta") => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                output.push_str(delta);
                on_delta(delta);
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

async fn read_agent_responses_sse(
    mut response: reqwest::Response,
    model: String,
    on_delta: CompletionDeltaCallback,
) -> Result<AgentTurnResponse> {
    let mut decoder = SseDecoder::default();
    let mut content = String::new();
    let mut output_items = Vec::new();
    let mut tool_calls = Vec::new();

    while let Some(chunk) = response.chunk().await? {
        for data in decoder.push(&String::from_utf8_lossy(&chunk)) {
            collect_agent_event(
                &data,
                &mut content,
                &mut output_items,
                &mut tool_calls,
                &on_delta,
            );
        }
    }

    for data in decoder.finish() {
        collect_agent_event(
            &data,
            &mut content,
            &mut output_items,
            &mut tool_calls,
            &on_delta,
        );
    }

    if content.is_empty() && tool_calls.is_empty() {
        Err(LlmError::EmptyResponse)
    } else {
        Ok(AgentTurnResponse {
            content,
            tool_calls,
            output_items,
            model,
            usage: None,
        })
    }
}

fn collect_agent_event(
    data: &str,
    content: &mut String,
    output_items: &mut Vec<Value>,
    tool_calls: &mut Vec<AgentToolCall>,
    on_delta: &CompletionDeltaCallback,
) {
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(data.trim()) else {
        return;
    };

    match value.get("type").and_then(Value::as_str) {
        Some("response.output_text.delta") => {
            if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                content.push_str(delta);
                on_delta(delta);
            }
        }
        Some("response.completed") => {
            if let Some(response) = value.get("response") {
                collect_response_items(response, output_items, tool_calls);
                if content.is_empty() {
                    collect_text_from_response(response, content);
                }
            }
        }
        _ => {}
    }
}

fn collect_response_items(
    response: &Value,
    output_items: &mut Vec<Value>,
    tool_calls: &mut Vec<AgentToolCall>,
) {
    let Some(items) = response.get("output").and_then(Value::as_array) else {
        return;
    };
    output_items.extend(items.iter().cloned());

    for item in items {
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            continue;
        }
        let Some(name) = item.get("name").and_then(Value::as_str) else {
            continue;
        };
        let call_id = item
            .get("call_id")
            .or_else(|| item.get("id"))
            .and_then(Value::as_str)
            .unwrap_or(name)
            .to_owned();
        let id = item
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or(&call_id)
            .to_owned();
        let input = parse_function_arguments(item.get("arguments"));
        tool_calls.push(AgentToolCall {
            id,
            call_id,
            name: name.to_owned(),
            input,
        });
    }
}

fn parse_function_arguments(arguments: Option<&Value>) -> Value {
    match arguments {
        Some(Value::String(raw)) => serde_json::from_str(raw).unwrap_or(Value::Null),
        Some(Value::Object(_)) => arguments.cloned().unwrap_or(Value::Null),
        Some(value) => value.clone(),
        None => Value::Null,
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
