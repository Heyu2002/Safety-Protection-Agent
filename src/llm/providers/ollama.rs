use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use serde_json::json;

use crate::llm::{
    CompletionDeltaCallback, CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError,
    Result,
};

pub struct OllamaClient {
    http: Client,
    config: LlmConfig,
}

impl OllamaClient {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl LlmClient for OllamaClient {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let url = format!("{}/api/chat", base_url.trim_end_matches('/'));
        let body = ollama_chat_body(&self.config.model, &request, false);

        let response = self.http.post(url).json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LlmError::Provider {
                status,
                body: response.text().await?,
            });
        }

        let output: OllamaResponse = response.json().await?;
        let content = output.message.content;
        if content.is_empty() {
            return Err(LlmError::EmptyResponse);
        }

        Ok(CompletionResponse {
            content,
            model: self.config.model.to_owned(),
            usage: None,
        })
    }

    async fn complete_streaming(
        &self,
        request: CompletionRequest,
        on_delta: CompletionDeltaCallback,
    ) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let url = format!("{}/api/chat", base_url.trim_end_matches('/'));
        let body = ollama_chat_body(&self.config.model, &request, true);

        let response = self.http.post(url).json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LlmError::Provider {
                status,
                body: response.text().await?,
            });
        }

        let content = read_ollama_jsonl(response, on_delta).await?;

        Ok(CompletionResponse {
            content,
            model: self.config.model.to_owned(),
            usage: None,
        })
    }
}

fn ollama_chat_body(model: &str, request: &CompletionRequest, stream: bool) -> Value {
    let mut messages = Vec::with_capacity(request.messages.len());
    for message in &request.messages {
        messages.push(json!({
            "role": message.role.as_openai_role(),
            "content": message.content,
        }));
    }

    let mut options = json!({});
    if let Some(temperature) = request.temperature {
        options["temperature"] = json!(temperature);
    }
    if let Some(max_tokens) = request.max_tokens {
        options["num_predict"] = json!(max_tokens);
    }

    json!({
        "model": model,
        "messages": messages,
        "stream": stream,
        "options": options,
    })
}

async fn read_ollama_jsonl(
    mut response: reqwest::Response,
    on_delta: CompletionDeltaCallback,
) -> Result<String> {
    let mut buffer = String::new();
    let mut output = String::new();

    while let Some(chunk) = response.chunk().await? {
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(newline) = buffer.find('\n') {
            let line = buffer[..newline].trim().to_owned();
            buffer.drain(..=newline);
            collect_ollama_delta_from_line(&line, &mut output, &on_delta);
        }
    }

    let tail = buffer.trim().to_owned();
    collect_ollama_delta_from_line(&tail, &mut output, &on_delta);

    if output.is_empty() {
        Err(LlmError::EmptyResponse)
    } else {
        Ok(output)
    }
}

fn collect_ollama_delta_from_line(
    line: &str,
    output: &mut String,
    on_delta: &CompletionDeltaCallback,
) {
    if line.is_empty() {
        return;
    }
    let Ok(value) = serde_json::from_str::<Value>(line) else {
        return;
    };
    if let Some(delta) = value
        .get("message")
        .and_then(|message| message.get("content"))
        .and_then(Value::as_str)
    {
        output.push_str(delta);
        on_delta(delta);
    }
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(Debug, Deserialize)]
struct OllamaMessage {
    content: String,
}
