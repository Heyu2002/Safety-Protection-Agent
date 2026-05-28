use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

use crate::llm::{
    AgentToolCall, AgentToolSpec, AgentToolTranscriptItem, AgentTurnRequest, AgentTurnResponse,
    CompletionDeltaCallback, CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError,
    Result,
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
    input_items: &[AgentToolTranscriptItem],
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

    input.extend(input_items.iter().map(codex_tool_transcript_item));
    (instructions.join("\n\n"), input)
}

fn codex_tool_transcript_item(item: &AgentToolTranscriptItem) -> Value {
    match item {
        AgentToolTranscriptItem::ToolCall {
            call_id,
            name,
            input,
        } => json!({
            "type": "function_call",
            "call_id": call_id,
            "name": name,
            "arguments": serde_json::to_string(input).unwrap_or_else(|_| "{}".to_owned()),
        }),
        AgentToolTranscriptItem::ToolResult { call_id, output } => json!({
            "type": "function_call_output",
            "call_id": call_id,
            "output": output,
        }),
    }
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
    let mut state = CodexAgentStreamState::default();

    while let Some(chunk) = response.chunk().await? {
        for data in decoder.push(&String::from_utf8_lossy(&chunk)) {
            state.collect_sse_data(&data, &on_delta);
        }
    }

    for data in decoder.finish() {
        state.collect_sse_data(&data, &on_delta);
    }

    state.into_response(model)
}

#[derive(Debug, Default)]
struct CodexAgentStreamState {
    content: String,
    output_items: Vec<AgentToolTranscriptItem>,
    tool_calls: Vec<AgentToolCall>,
    partial_tool_calls: Vec<PartialResponseToolCall>,
}

impl CodexAgentStreamState {
    fn collect_sse_data(&mut self, data: &str, on_delta: &CompletionDeltaCallback) {
        if data.trim().is_empty() || data.trim() == "[DONE]" {
            return;
        }
        let Ok(value) = serde_json::from_str::<Value>(data.trim()) else {
            return;
        };

        match value.get("type").and_then(Value::as_str) {
            Some("response.output_text.delta") => {
                if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                    self.content.push_str(delta);
                    on_delta(delta);
                }
            }
            Some("response.output_item.added") => {
                if let Some(item) = value.get("item") {
                    self.collect_function_call_item(item, false);
                }
            }
            Some("response.function_call_arguments.delta") => {
                if let Some(delta) = value.get("delta").and_then(Value::as_str) {
                    let item_id = value.get("item_id").and_then(Value::as_str);
                    self.append_function_call_arguments(item_id, delta);
                }
            }
            Some("response.function_call_arguments.done") => {
                let item_id = value.get("item_id").and_then(Value::as_str);
                if let Some(arguments) = value.get("arguments").and_then(Value::as_str) {
                    self.set_function_call_arguments(item_id, arguments);
                }
            }
            Some("response.output_item.done") => {
                if let Some(item) = value.get("item") {
                    self.collect_function_call_item(item, true);
                }
            }
            Some("response.completed") => {
                if let Some(response) = value.get("response") {
                    collect_response_items(response, &mut self.output_items, &mut self.tool_calls);
                    if self.content.is_empty() {
                        collect_text_from_response(response, &mut self.content);
                    }
                }
            }
            _ => {}
        }
    }

    fn collect_function_call_item(&mut self, item: &Value, finalize: bool) {
        if item.get("type").and_then(Value::as_str) != Some("function_call") {
            return;
        }

        let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
        let call_id = item
            .get("call_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let index = self.partial_tool_call_index(id, call_id);
        update_partial_tool_call_from_item(&mut self.partial_tool_calls[index], item);

        if finalize {
            self.finalize_partial_tool_call(index);
        }
    }

    fn append_function_call_arguments(&mut self, item_id: Option<&str>, delta: &str) {
        let index = self.partial_tool_call_index(item_id.unwrap_or_default(), "");
        self.partial_tool_calls[index].arguments.push_str(delta);
    }

    fn set_function_call_arguments(&mut self, item_id: Option<&str>, arguments: &str) {
        let index = self.partial_tool_call_index(item_id.unwrap_or_default(), "");
        self.partial_tool_calls[index].arguments = arguments.to_owned();
    }

    fn partial_tool_call_index(&mut self, id: &str, call_id: &str) -> usize {
        if id.is_empty()
            && call_id.is_empty()
            && let Some(index) = self.partial_tool_calls.len().checked_sub(1)
        {
            return index;
        }

        if let Some(index) = self.partial_tool_calls.iter().position(|partial| {
            (!id.is_empty() && partial.id == id)
                || (!call_id.is_empty() && partial.call_id == call_id)
        }) {
            return index;
        }

        self.partial_tool_calls.push(PartialResponseToolCall {
            id: id.to_owned(),
            call_id: call_id.to_owned(),
            ..PartialResponseToolCall::default()
        });
        self.partial_tool_calls.len() - 1
    }

    fn finalize_partial_tool_call(&mut self, index: usize) {
        let Some(partial) = self.partial_tool_calls.get_mut(index) else {
            return;
        };
        if partial.finalized {
            return;
        }
        let Some(tool_call) = partial.to_agent_tool_call() else {
            return;
        };
        partial.finalized = true;
        push_tool_call_if_absent(&mut self.output_items, &mut self.tool_calls, tool_call);
    }

    fn finalize_all_partial_tool_calls(&mut self) {
        for index in 0..self.partial_tool_calls.len() {
            self.finalize_partial_tool_call(index);
        }
    }

    fn into_response(mut self, model: String) -> Result<AgentTurnResponse> {
        self.finalize_all_partial_tool_calls();

        if self.content.is_empty() && self.tool_calls.is_empty() {
            Err(LlmError::EmptyResponse)
        } else {
            Ok(AgentTurnResponse {
                content: self.content,
                tool_calls: self.tool_calls,
                output_items: self.output_items,
                model,
                usage: None,
            })
        }
    }
}

#[derive(Debug, Default)]
struct PartialResponseToolCall {
    id: String,
    call_id: String,
    name: String,
    arguments: String,
    finalized: bool,
}

impl PartialResponseToolCall {
    fn to_agent_tool_call(&self) -> Option<AgentToolCall> {
        if self.name.is_empty() {
            return None;
        }
        let call_id = if self.call_id.is_empty() {
            if self.id.is_empty() {
                self.name.clone()
            } else {
                self.id.clone()
            }
        } else {
            self.call_id.clone()
        };
        let id = if self.id.is_empty() {
            call_id.clone()
        } else {
            self.id.clone()
        };
        Some(AgentToolCall {
            id,
            call_id,
            name: self.name.clone(),
            input: parse_function_arguments(Some(&Value::String(self.arguments.clone()))),
        })
    }
}

fn update_partial_tool_call_from_item(partial: &mut PartialResponseToolCall, item: &Value) {
    if let Some(id) = item.get("id").and_then(Value::as_str) {
        partial.id = id.to_owned();
    }
    if let Some(call_id) = item.get("call_id").and_then(Value::as_str) {
        partial.call_id = call_id.to_owned();
    }
    if let Some(name) = item.get("name").and_then(Value::as_str) {
        partial.name = name.to_owned();
    }
    if let Some(arguments) = item.get("arguments").and_then(Value::as_str) {
        partial.arguments = arguments.to_owned();
    }
}

fn push_tool_call_if_absent(
    output_items: &mut Vec<AgentToolTranscriptItem>,
    tool_calls: &mut Vec<AgentToolCall>,
    tool_call: AgentToolCall,
) {
    if tool_calls.iter().any(|existing| {
        existing.call_id == tool_call.call_id
            || (!tool_call.id.is_empty() && existing.id == tool_call.id)
    }) {
        return;
    }

    output_items.push(AgentToolTranscriptItem::tool_call(&tool_call));
    tool_calls.push(tool_call);
}

fn collect_response_items(
    response: &Value,
    output_items: &mut Vec<AgentToolTranscriptItem>,
    tool_calls: &mut Vec<AgentToolCall>,
) {
    let Some(items) = response.get("output").and_then(Value::as_array) else {
        return;
    };

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
        let tool_call = AgentToolCall {
            id,
            call_id,
            name: name.to_owned(),
            input,
        };
        push_tool_call_if_absent(output_items, tool_calls, tool_call);
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn response_transcript_keeps_only_tool_calls() {
        let response = json!({
            "output": [
                { "type": "reasoning", "id": "rs_not_persisted" },
                {
                    "type": "message",
                    "content": [{ "type": "output_text", "text": "thinking done" }]
                },
                {
                    "type": "function_call",
                    "id": "fc_1",
                    "call_id": "call_1",
                    "name": "echo",
                    "arguments": "{\"text\":\"hi\"}"
                }
            ]
        });
        let mut output_items = Vec::new();
        let mut tool_calls = Vec::new();

        collect_response_items(&response, &mut output_items, &mut tool_calls);

        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].call_id, "call_1");
        assert_eq!(tool_calls[0].name, "echo");
        assert_eq!(tool_calls[0].input, json!({ "text": "hi" }));
        assert_eq!(
            output_items,
            vec![AgentToolTranscriptItem::ToolCall {
                call_id: "call_1".to_owned(),
                name: "echo".to_owned(),
                input: json!({ "text": "hi" }),
            }]
        );
    }

    #[test]
    fn agent_stream_collects_output_item_tool_call() {
        let mut state = CodexAgentStreamState::default();
        let on_delta: CompletionDeltaCallback = std::sync::Arc::new(|_| {});

        state.collect_sse_data(
            r#"{"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"echo","arguments":"","status":"in_progress"}}"#,
            &on_delta,
        );
        state.collect_sse_data(
            &json!({
                "type": "response.function_call_arguments.delta",
                "item_id": "fc_1",
                "delta": "{\"text\""
            })
            .to_string(),
            &on_delta,
        );
        state.collect_sse_data(
            &json!({
                "type": "response.function_call_arguments.delta",
                "item_id": "fc_1",
                "delta": ":\"hi\"}"
            })
            .to_string(),
            &on_delta,
        );
        state.collect_sse_data(
            r#"{"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"text\":\"hi\"}"}"#,
            &on_delta,
        );
        state.collect_sse_data(
            r#"{"type":"response.output_item.done","item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"echo","arguments":"{\"text\":\"hi\"}","status":"completed"}}"#,
            &on_delta,
        );
        state.collect_sse_data(
            r#"{"type":"response.completed","response":{"output":[]}}"#,
            &on_delta,
        );

        let response = state
            .into_response("model".to_owned())
            .expect("streamed tool call should produce response");

        assert_eq!(response.content, "");
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].id, "fc_1");
        assert_eq!(response.tool_calls[0].call_id, "call_1");
        assert_eq!(response.tool_calls[0].name, "echo");
        assert_eq!(response.tool_calls[0].input, json!({"text":"hi"}));
        assert_eq!(
            response.output_items,
            vec![AgentToolTranscriptItem::ToolCall {
                call_id: "call_1".to_owned(),
                name: "echo".to_owned(),
                input: json!({"text":"hi"}),
            }]
        );
    }

    #[test]
    fn agent_stream_finalizes_function_call_when_done_item_is_missing() {
        let mut state = CodexAgentStreamState::default();
        let on_delta: CompletionDeltaCallback = std::sync::Arc::new(|_| {});

        state.collect_sse_data(
            r#"{"type":"response.output_item.added","item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"echo","arguments":"","status":"in_progress"}}"#,
            &on_delta,
        );
        state.collect_sse_data(
            &json!({
                "type": "response.function_call_arguments.delta",
                "item_id": "fc_1",
                "delta": "{\"text\":\"hi\"}"
            })
            .to_string(),
            &on_delta,
        );

        let response = state
            .into_response("model".to_owned())
            .expect("partial streamed tool call should be finalized");

        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].name, "echo");
        assert_eq!(response.tool_calls[0].input, json!({"text":"hi"}));
    }
}
