use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

use crate::llm::{
    AgentToolCall, AgentToolSpec, AgentToolTranscriptItem, AgentTurnRequest, AgentTurnResponse,
    ChatUsage, CompletionDeltaCallback, CompletionRequest, CompletionResponse, LlmClient,
    LlmConfig, LlmError, Result,
};

use super::sse::SseDecoder;

pub struct OpenAiResponsesClient {
    http: Client,
    config: LlmConfig,
}

impl OpenAiResponsesClient {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl LlmClient for OpenAiResponsesClient {
    fn supports_native_tools(&self) -> bool {
        true
    }

    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let body = responses_body(&self.config.model, &request, false);

        let response = self
            .http
            .post(url)
            .bearer_auth(api_key)
            .header("x-api-key", api_key)
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

        let output: ResponsesApiResponse = response.json().await?;
        let content = output.output_text().ok_or(LlmError::EmptyResponse)?;

        Ok(CompletionResponse {
            content,
            model: output.model.unwrap_or_else(|| self.config.model.to_owned()),
            usage: output.usage.map(|usage| ChatUsage {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
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
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let body = responses_body(&self.config.model, &request, true);

        let response = self
            .http
            .post(url)
            .bearer_auth(api_key)
            .header("x-api-key", api_key)
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
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!("{}/responses", base_url.trim_end_matches('/'));
        let body = responses_agent_body(&self.config.model, &request);

        let response = self
            .http
            .post(url)
            .bearer_auth(api_key)
            .header("x-api-key", api_key)
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

        read_agent_responses_sse(response, self.config.model.to_owned(), on_delta).await
    }
}

fn responses_body(model: &str, request: &CompletionRequest, stream: bool) -> Value {
    let mut input = Vec::with_capacity(request.messages.len());
    for message in &request.messages {
        input.push(json!({
            "role": message.role.as_openai_role(),
            "content": message.content,
        }));
    }

    let mut body = json!({
        "model": model,
        "input": input,
    });

    if stream {
        body["stream"] = json!(true);
    }
    if let Some(temperature) = request.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(max_tokens) = request.max_tokens {
        body["max_output_tokens"] = json!(max_tokens);
    }

    body
}

fn responses_agent_body(model: &str, request: &AgentTurnRequest) -> Value {
    let (instructions, input) = responses_input(&request.messages, &request.input_items);
    let mut body = json!({
        "model": model,
        "input": input,
        "tools": response_tools(&request.tools),
        "tool_choice": "auto",
        "parallel_tool_calls": false,
        "stream": true,
        "store": false,
    });

    if !instructions.is_empty() {
        body["instructions"] = json!(instructions);
    }
    if let Some(temperature) = request.temperature {
        body["temperature"] = json!(temperature);
    }
    if let Some(max_tokens) = request.max_tokens {
        body["max_output_tokens"] = json!(max_tokens);
    }

    body
}

fn responses_input(
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

    input.extend(input_items.iter().map(responses_tool_transcript_item));
    (instructions.join("\n\n"), input)
}

fn responses_tool_transcript_item(item: &AgentToolTranscriptItem) -> Value {
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
                collect_text_from_response_value(response, output);
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
    output_items: &mut Vec<AgentToolTranscriptItem>,
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
                    collect_text_from_response_value(response, content);
                }
            }
        }
        _ => {}
    }
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
        output_items.push(AgentToolTranscriptItem::tool_call(&tool_call));
        tool_calls.push(tool_call);
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

fn collect_text_from_response_value(response: &Value, output: &mut String) {
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

#[derive(Debug, Deserialize)]
struct ResponsesApiResponse {
    model: Option<String>,
    #[serde(default)]
    output_text: Option<String>,
    #[serde(default)]
    output: Vec<ResponseOutput>,
    usage: Option<ResponsesUsage>,
}

impl ResponsesApiResponse {
    fn output_text(&self) -> Option<String> {
        if let Some(output_text) = &self.output_text
            && !output_text.is_empty()
        {
            return Some(output_text.to_owned());
        }

        let mut parts = Vec::new();
        for item in &self.output {
            for part in &item.content {
                if let Some(text) = part.text.as_deref() {
                    parts.push(text);
                }
            }
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(""))
        }
    }
}

#[derive(Debug, Deserialize)]
struct ResponseOutput {
    #[serde(default)]
    content: Vec<ResponseContent>,
}

#[derive(Debug, Deserialize)]
struct ResponseContent {
    text: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResponsesUsage {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
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
}
