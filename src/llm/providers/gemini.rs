use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::json;

use crate::llm::{
    ChatRole, ChatUsage, CompletionRequest, CompletionResponse, LlmClient, LlmConfig, LlmError,
    Result,
};

pub struct GeminiClient {
    http: Client,
    config: LlmConfig,
}

impl GeminiClient {
    pub fn new(config: LlmConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
    }
}

#[async_trait]
impl LlmClient for GeminiClient {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse> {
        let base_url = self.config.base_url.as_deref().unwrap_or_default();
        let api_key = self.config.api_key.as_deref().unwrap_or_default();
        let url = format!(
            "{}/models/{}:generateContent?key={}",
            base_url.trim_end_matches('/'),
            self.config.model,
            api_key
        );

        let mut system_messages = Vec::new();
        let mut contents = Vec::with_capacity(request.messages.len());
        for message in &request.messages {
            if matches!(message.role, ChatRole::System) {
                system_messages.push(message.content.as_str());
            } else {
                contents.push(json!({
                    "role": match message.role {
                        ChatRole::Assistant => "model",
                        _ => "user",
                    },
                    "parts": [{ "text": message.content }],
                }));
            }
        }
        let system_instruction = system_messages.join("\n\n");

        let mut body = json!({
            "contents": contents,
        });

        if !system_instruction.is_empty() {
            body["systemInstruction"] = json!({
                "parts": [{ "text": system_instruction }]
            });
        }
        if request.temperature.is_some() || request.max_tokens.is_some() {
            body["generationConfig"] = json!({});
            if let Some(temperature) = request.temperature {
                body["generationConfig"]["temperature"] = json!(temperature);
            }
            if let Some(max_tokens) = request.max_tokens {
                body["generationConfig"]["maxOutputTokens"] = json!(max_tokens);
            }
        }

        let response = self.http.post(url).json(&body).send().await?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            return Err(LlmError::Provider {
                status,
                body: response.text().await?,
            });
        }

        let output: GeminiResponse = response.json().await?;
        let content = output
            .candidates
            .into_iter()
            .next()
            .and_then(|candidate| candidate.content.parts.into_iter().next())
            .map(|part| part.text)
            .ok_or(LlmError::EmptyResponse)?;

        Ok(CompletionResponse {
            content,
            model: self.config.model.to_owned(),
            usage: output.usage_metadata.map(|usage| ChatUsage {
                input_tokens: usage.prompt_token_count,
                output_tokens: usage.candidates_token_count,
            }),
        })
    }
}

#[derive(Debug, Deserialize)]
struct GeminiResponse {
    candidates: Vec<GeminiCandidate>,
    #[serde(rename = "usageMetadata")]
    usage_metadata: Option<GeminiUsage>,
}

#[derive(Debug, Deserialize)]
struct GeminiCandidate {
    content: GeminiContent,
}

#[derive(Debug, Deserialize)]
struct GeminiContent {
    parts: Vec<GeminiPart>,
}

#[derive(Debug, Deserialize)]
struct GeminiPart {
    text: String,
}

#[derive(Debug, Deserialize)]
struct GeminiUsage {
    #[serde(rename = "promptTokenCount")]
    prompt_token_count: Option<u32>,
    #[serde(rename = "candidatesTokenCount")]
    candidates_token_count: Option<u32>,
}
