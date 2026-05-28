use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

use crate::llm::{
    ChatRole, ChatUsage, CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError,
    Result,
};

pub struct AnthropicClient {
    http: Client,
    config: LlmConfig,
}

impl AnthropicClient {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl LlmClient for AnthropicClient {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = anthropic_messages_url(base_url);

        let mut system_messages = Vec::new();
        let mut messages = Vec::with_capacity(request.messages.len());
        for message in &request.messages {
            if matches!(message.role, ChatRole::System) {
                system_messages.push(message.content.as_str());
            } else {
                messages.push(json!({
                    "role": message.role.as_anthropic_role(),
                    "content": message.content,
                }));
            }
        }
        let system = system_messages.join("\n\n");

        let mut body = json!({
            "model": self.config.model,
            "messages": messages,
            "max_tokens": request.max_tokens.unwrap_or(1024),
        });

        if !system.is_empty() {
            body["system"] = json!(system);
        }
        if let Some(temperature) = request.temperature {
            body["temperature"] = json!(temperature);
        }

        let response = self
            .http
            .post(url)
            .header("x-api-key", api_key)
            .header("anthropic-version", "2023-06-01")
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

        let output: AnthropicResponse = response.json().await?;
        let content = output
            .content
            .into_iter()
            .find_map(|part| match part {
                AnthropicContent::Text { text } => Some(text),
                AnthropicContent::Other => None,
            })
            .ok_or(LlmError::EmptyResponse)?;

        Ok(CompletionResponse {
            content,
            model: output.model,
            usage: output.usage.map(|usage| ChatUsage {
                input_tokens: usage.input_tokens,
                output_tokens: usage.output_tokens,
            }),
        })
    }
}

fn anthropic_messages_url(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    if base_url.ends_with("/v1") {
        format!("{base_url}/messages")
    } else {
        format!("{base_url}/v1/messages")
    }
}

#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    model: String,
    content: Vec<AnthropicContent>,
    usage: Option<AnthropicUsage>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
enum AnthropicContent {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(other)]
    Other,
}

#[derive(Debug, Deserialize)]
struct AnthropicUsage {
    input_tokens: Option<u32>,
    output_tokens: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anthropic_messages_url_accepts_root_relay_base_url() {
        assert_eq!(
            anthropic_messages_url("https://api.duojie.games"),
            "https://api.duojie.games/v1/messages"
        );
    }

    #[test]
    fn anthropic_messages_url_accepts_v1_base_url() {
        assert_eq!(
            anthropic_messages_url("https://api.anthropic.com/v1"),
            "https://api.anthropic.com/v1/messages"
        );
    }
}
