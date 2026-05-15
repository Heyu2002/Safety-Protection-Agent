mod anthropic;
mod gemini;
mod ollama;
mod openai_compatible;

use super::{LlmClient, LlmConfig, ProviderKind, Result};

pub fn client_from_config(config: LlmConfig) -> Result<Box<dyn LlmClient>> {
    match config.provider {
        ProviderKind::OpenAi | ProviderKind::OpenAiCompatible => Ok(Box::new(
            openai_compatible::OpenAiCompatibleClient::new(config),
        )),
        ProviderKind::Anthropic => Ok(Box::new(anthropic::AnthropicClient::new(config))),
        ProviderKind::Gemini => Ok(Box::new(gemini::GeminiClient::new(config))),
        ProviderKind::Ollama => Ok(Box::new(ollama::OllamaClient::new(config))),
    }
}
