use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

use crate::llm::{
    AgentToolCall, AgentToolSpec, AgentTurnRequest, AgentTurnResponse, ChatUsage,
    CompletionDeltaCallback, CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError,
    Result,
};

use super::sse::SseDecoder;

pub struct OpenAiCompatibleClient {
    http: Client,
    config: LlmConfig,
}

impl OpenAiCompatibleClient {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl LlmClient for OpenAiCompatibleClient {
    fn supports_native_tools(&self) -> bool {
        true
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let body = chat_completions_body(&self.config.model, &request, false);

        let response = self
            .http
            .post(url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LlmError::Provider {
                status,
                body: response.text().await?,
            });
        }

        let output: OpenAiResponse = response.json().await?;
        let content = output
            .choices
            .into_iter()
            .next()
            .and_then(|choice| choice.message.content)
            .ok_or(LlmError::EmptyResponse)?;

        Ok(CompletionResponse {
            content,
            model: output.model,
            usage: output.usage.map(|usage| ChatUsage {
                input_tokens: usage.prompt_tokens,
                output_tokens: usage.completion_tokens,
            }),
        })
    }

    async fn complete_streaming(
        &self,
        request: CompletionRequest,
        on_delta: CompletionDeltaCallback,
    ) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let body = chat_completions_body(&self.config.model, &request, true);

        let response = self
            .http
            .post(url)
            .bearer_auth(api_key)
            .header("Accept", "text/event-stream")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LlmError::Provider {
                status,
                body: response.text().await?,
            });
        }

        let content = read_chat_completions_sse(response, on_delta).await?;

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
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));
        let body = chat_agent_body(&self.config.model, &request);

        let response = self
            .http
            .post(url)
            .bearer_auth(api_key)
            .header("Accept", "text/event-stream")
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LlmError::Provider {
                status,
                body: response.text().await?,
            });
        }

        read_agent_chat_sse(response, self.config.model.to_owned(), on_delta).await
    }
}

fn chat_completions_body(model: &str, request: &CompletionRequest, stream: bool) -> Value {
    let mut messages = Vec::with_capacity(request.messages.len());
    for message in &request.messages {
        messages.push(json!({
            "role": message.role.as_openai_role(),
            "content": message.content,
        }));
    }

    let mut body = json!({
        "model": model,
        "messages": messages,
    });

    if stream {
        body["stream"] = json!(true);
    }
    if let Some(temperature) = request.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(max_tokens) = request.max_tokens {
        body["max_tokens"] = json!(max_tokens);
    }

    body
}

fn chat_agent_body(model: &str, request: &AgentTurnRequest) -> Value {
    let mut body = json!({
        "model": model,
        "messages": chat_agent_messages(request),
        "tools": chat_tools(&request.tools),
        "tool_choice": "auto",
        "parallel_tool_calls": false,
        "stream": true,
    });

    if let Some(temperature) = request.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(max_tokens) = request.max_tokens {
        body["max_tokens"] = json!(max_tokens);
    }

    body
}

fn chat_agent_messages(request: &AgentTurnRequest) -> Vec<Value> {
    let mut messages = Vec::new();
    for message in &request.messages {
        messages.push(json!({
            "role": message.role.as_openai_role(),
            "content": message.content,
        }));
    }

    for item in &request.input_items {
        match item.get("type").and_then(Value::as_str) {
            Some("function_call") => messages.push(chat_assistant_tool_call_message(item)),
            Some("function_call_output") => messages.push(json!({
                "role": "tool",
                "tool_call_id": item.get("call_id").and_then(Value::as_str).unwrap_or_default(),
                "content": item.get("output").and_then(Value::as_str).unwrap_or_default(),
            })),
            _ => {}
        }
    }

    messages
}

fn chat_assistant_tool_call_message(item: &Value) -> Value {
    let call_id = item
        .get("call_id")
        .or_else(|| item.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let name = item.get("name").and_then(Value::as_str).unwrap_or_default();
    let arguments = item
        .get("arguments")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| "{}".to_owned());

    json!({
        "role": "assistant",
        "content": Value::Null,
        "tool_calls": [{
            "id": call_id,
            "type": "function",
            "function": {
                "name": name,
                "arguments": arguments,
            }
        }],
    })
}

fn chat_tools(tools: &[AgentToolSpec]) -> Vec<Value> {
    tools
        .iter()
        .map(|tool| {
            json!({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": tool.input_schema,
                }
            })
        })
        .collect()
}

async fn read_chat_completions_sse(
    mut response: reqwest::Response,
    on_delta: CompletionDeltaCallback,
) -> Result<String> {
    let mut decoder = SseDecoder::default();
    let mut output = String::new();

    while let Some(chunk) = response.chunk().await? {
        for data in decoder.push(&String::from_utf8_lossy(&chunk)) {
            collect_chat_delta_from_sse_data(&data, &mut output, &on_delta);
        }
    }

    for data in decoder.finish() {
        collect_chat_delta_from_sse_data(&data, &mut output, &on_delta);
    }

    if output.is_empty() {
        Err(LlmError::EmptyResponse)
    } else {
        Ok(output)
    }
}

fn collect_chat_delta_from_sse_data(
    data: &str,
    output: &mut String,
    on_delta: &CompletionDeltaCallback,
) {
    if data.trim().is_empty() || data.trim() == "[DONE]" {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(data.trim()) else {
        return;
    };

    let Some(choices) = value.get("choices").and_then(Value::as_array) else {
        return;
    };
    for choice in choices {
        if let Some(delta) = choice
            .get("delta")
            .and_then(|delta| delta.get("content"))
            .and_then(Value::as_str)
        {
            output.push_str(delta);
            on_delta(delta);
        }
    }
}

async fn read_agent_chat_sse(
    mut response: reqwest::Response,
    model: String,
    on_delta: CompletionDeltaCallback,
) -> Result<AgentTurnResponse> {
    let mut decoder = SseDecoder::default();
    let mut state = ChatAgentStreamState::default();

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
struct ChatAgentStreamState {
    content: String,
    tool_calls: Vec<PartialChatToolCall>,
    finish_reason: Option<String>,
}

impl ChatAgentStreamState {
    fn collect_sse_data(&mut self, data: &str, on_delta: &CompletionDeltaCallback) {
        if data.trim().is_empty() || data.trim() == "[DONE]" {
            return;
        }
        let Ok(value) = serde_json::from_str::<Value>(data.trim()) else {
            return;
        };
        let Some(choices) = value.get("choices").and_then(Value::as_array) else {
            return;
        };

        for choice in choices {
            if let Some(reason) = choice.get("finish_reason").and_then(Value::as_str) {
                self.finish_reason = Some(reason.to_owned());
            }

            let Some(delta) = choice.get("delta") else {
                continue;
            };
            if let Some(content_delta) = delta.get("content").and_then(Value::as_str) {
                self.content.push_str(content_delta);
                on_delta(content_delta);
            }
            if let Some(tool_deltas) = delta.get("tool_calls").and_then(Value::as_array) {
                self.collect_tool_call_deltas(tool_deltas);
            }
        }
    }

    fn collect_tool_call_deltas(&mut self, tool_deltas: &[Value]) {
        for delta in tool_deltas {
            let index = delta.get("index").and_then(Value::as_u64).unwrap_or(0) as usize;
            while self.tool_calls.len() <= index {
                self.tool_calls.push(PartialChatToolCall::default());
            }
            let partial = &mut self.tool_calls[index];
            if let Some(id) = delta.get("id").and_then(Value::as_str) {
                partial.id.push_str(id);
            }
            if let Some(function) = delta.get("function") {
                if let Some(name) = function.get("name").and_then(Value::as_str) {
                    partial.name.push_str(name);
                }
                if let Some(arguments) = function.get("arguments").and_then(Value::as_str) {
                    partial.arguments.push_str(arguments);
                }
            }
        }
    }

    fn into_response(mut self, model: String) -> Result<AgentTurnResponse> {
        merge_non_streaming_tool_calls_from_content(&mut self.content, &mut self.tool_calls);
        let tool_calls = self
            .tool_calls
            .into_iter()
            .filter_map(PartialChatToolCall::into_agent_tool_call)
            .collect::<Vec<_>>();
        let output_items = tool_calls
            .iter()
            .map(chat_tool_call_to_response_item)
            .collect::<Vec<_>>();

        if self.content.is_empty() && tool_calls.is_empty() {
            Err(LlmError::EmptyResponse)
        } else {
            Ok(AgentTurnResponse {
                content: self.content,
                tool_calls,
                output_items,
                model,
                usage: None,
            })
        }
    }
}

#[derive(Debug, Default)]
struct PartialChatToolCall {
    id: String,
    name: String,
    arguments: String,
}

impl PartialChatToolCall {
    fn into_agent_tool_call(self) -> Option<AgentToolCall> {
        if self.name.is_empty() {
            return None;
        }
        let call_id = if self.id.is_empty() {
            uuid::Uuid::new_v4().to_string()
        } else {
            self.id
        };
        let input = serde_json::from_str(&self.arguments).unwrap_or(Value::Null);
        Some(AgentToolCall {
            id: call_id.clone(),
            call_id,
            name: self.name,
            input,
        })
    }
}

fn chat_tool_call_to_response_item(tool_call: &AgentToolCall) -> Value {
    json!({
        "type": "function_call",
        "id": tool_call.id,
        "call_id": tool_call.call_id,
        "name": tool_call.name,
        "arguments": serde_json::to_string(&tool_call.input).unwrap_or_else(|_| "{}".to_owned()),
    })
}

fn merge_non_streaming_tool_calls_from_content(
    content: &mut String,
    tool_calls: &mut Vec<PartialChatToolCall>,
) {
    let Ok(value) = serde_json::from_str::<Value>(content.trim()) else {
        return;
    };
    let Some(calls) = value.get("tool_calls").and_then(Value::as_array) else {
        return;
    };
    for call in calls {
        let Some(function) = call.get("function") else {
            continue;
        };
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .unwrap_or("{}");
        tool_calls.push(PartialChatToolCall {
            id: call
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            name: name.to_owned(),
            arguments: arguments.to_owned(),
        });
    }
    if !tool_calls.is_empty() {
        content.clear();
    }
}

#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    model: String,
    choices: Vec<OpenAiChoice>,
    usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: Option<u32>,
    completion_tokens: Option<u32>,
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::json;

    use super::*;

    #[test]
    fn assembles_streamed_chat_tool_calls() {
        let mut state = ChatAgentStreamState::default();
        let deltas = Arc::new(Mutex::new(String::new()));
        let deltas_for_callback = Arc::clone(&deltas);
        let on_delta: CompletionDeltaCallback = Arc::new(move |delta| {
            deltas_for_callback
                .lock()
                .expect("delta mutex should not be poisoned")
                .push_str(delta);
        });

        state.collect_sse_data(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"database_risk_scan","arguments":"{\"url\":\"http://localhost"}}]}}]}"#,
            &on_delta,
        );
        state.collect_sse_data(
            r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"/test\",\"method\":\"GET\"}"}}]},"finish_reason":"tool_calls"}]}"#,
            &on_delta,
        );

        let response = state
            .into_response("model".to_owned())
            .expect("tool call response");

        assert_eq!(response.content, "");
        assert_eq!(response.tool_calls.len(), 1);
        assert_eq!(response.tool_calls[0].call_id, "call_1");
        assert_eq!(response.tool_calls[0].name, "database_risk_scan");
        assert_eq!(
            response.tool_calls[0].input,
            json!({"url":"http://localhost/test","method":"GET"})
        );
        assert_eq!(
            deltas
                .lock()
                .expect("delta mutex should not be poisoned")
                .as_str(),
            ""
        );
    }

    #[test]
    fn converts_function_outputs_back_to_chat_tool_messages() {
        let request = AgentTurnRequest::new(Vec::new(), Vec::new()).with_input_items(vec![
            json!({
                "type": "function_call",
                "call_id": "call_1",
                "name": "echo",
                "arguments": "{\"text\":\"hi\"}"
            }),
            json!({
                "type": "function_call_output",
                "call_id": "call_1",
                "output": "hi"
            }),
        ]);

        let messages = chat_agent_messages(&request);

        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "assistant");
        assert_eq!(messages[0]["tool_calls"][0]["id"], "call_1");
        assert_eq!(messages[1]["role"], "tool");
        assert_eq!(messages[1]["tool_call_id"], "call_1");
        assert_eq!(messages[1]["content"], "hi");
    }
}
