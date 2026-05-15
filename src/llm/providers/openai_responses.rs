use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

use crate::llm::{
    ChatUsage, CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError, Result,
};

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
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!("{}/responses", base_url.trim_end_matches('/'));

        let mut input = Vec::with_capacity(request.messages.len());
        for message in &request.messages {
            input.push(json!({
                "role": message.role.as_openai_role(),
                "content": message.content,
            }));
        }

        let mut body = json!({
            "model": self.config.model,
            "input": input,
        });

        if let Some(temperature) = request.temperature {
            body["temperature"] = json!(temperature);
        }
        if let Some(max_tokens) = request.max_tokens {
            body["max_output_tokens"] = json!(max_tokens);
        }

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
        if let Some(output_text) = &self.output_text {
            if !output_text.is_empty() {
                return Some(output_text.to_owned());
            }
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
