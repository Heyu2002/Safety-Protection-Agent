use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

use crate::llm::{
    ChatUsage, CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError, Result,
};

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
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!("{}/chat/completions", base_url.trim_end_matches('/'));

        let mut messages = Vec::with_capacity(request.messages.len());
        for message in &request.messages {
            messages.push(json!({
                "role": message.role.as_openai_role(),
                "content": message.content,
            }));
        }

        let mut body = json!({
            "model": self.config.model,
            "messages": messages,
        });

        if let Some(temperature) = request.temperature {
            body["temperature"] = json!(temperature);
        }
        if let Some(max_tokens) = request.max_tokens {
            body["max_tokens"] = json!(max_tokens);
        }

        let response = self
            .http
            .post(url)
            .bearer_auth(api_key)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(LlmError::Provider(response.text().await?));
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
