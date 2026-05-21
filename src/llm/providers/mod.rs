mod anthropic;
mod codex_chatgpt;
mod gemini;
mod ollama;
mod openai_compatible;
mod openai_responses;
mod sse;

use super::{LlmClient, LlmConfig, ProviderKind, Result};

pub fn client_from_config(config: LlmConfig) -> Result<Box<dyn LlmClient>> {
    match config.provider {
        ProviderKind::OpenAi
        | ProviderKind::OpenAiCompatible
        | ProviderKind::Kimi
        | ProviderKind::Moonshot => Ok(Box::new(openai_compatible::OpenAiCompatibleClient::new(
            config,
        ))),
        ProviderKind::OpenAiResponses => Ok(Box::new(
            openai_responses::OpenAiResponsesClient::new(config),
        )),
        ProviderKind::CodexChatGpt => Ok(Box::new(codex_chatgpt::CodexChatGptClient::new(config))),
        ProviderKind::Anthropic => Ok(Box::new(anthropic::AnthropicClient::new(config))),
        ProviderKind::Gemini => Ok(Box::new(gemini::GeminiClient::new(config))),
        ProviderKind::Ollama => Ok(Box::new(ollama::OllamaClient::new(config))),
    }
}
