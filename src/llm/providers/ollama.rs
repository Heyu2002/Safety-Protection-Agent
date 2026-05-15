use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

use crate::llm::{CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError, Result};

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

        let response = self
            .http
            .post(url)
            .json(&json!({
                "model": self.config.model,
                "messages": messages,
                "stream": false,
                "options": options,
            }))
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(LlmError::Provider(response.text().await?));
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
}

#[derive(Debug, Deserialize)]
struct OllamaResponse {
    message: OllamaMessage,
}

#[derive(Debug, Deserialize)]
struct OllamaMessage {
    content: String,
}
