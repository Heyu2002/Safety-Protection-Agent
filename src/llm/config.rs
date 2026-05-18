use super::error::{LlmError, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderKind {
    OpenAi,
    OpenAiCompatible,
    OpenAiResponses,
    CodexChatGpt,
    Kimi,
    Moonshot,
    Anthropic,
    Gemini,
    Ollama,
}

impl ProviderKind {
    fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "openai" => Ok(Self::OpenAi),
            "openai-compatible" | "compatible" => Ok(Self::OpenAiCompatible),
            "openai-responses" | "responses" => Ok(Self::OpenAiResponses),
            "codex-chatgpt" | "codex" | "chatgpt" => Ok(Self::CodexChatGpt),
            "kimi" | "kimi-code" | "kimi-cli" => Ok(Self::Kimi),
            "moonshot" | "kimi-platform" => Ok(Self::Moonshot),
            "anthropic" | "claude" => Ok(Self::Anthropic),
            "gemini" | "google" => Ok(Self::Gemini),
            "ollama" | "local" => Ok(Self::Ollama),
            other => Err(LlmError::UnsupportedProvider(other.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub provider: ProviderKind,
    pub api_key: Option<String>,
    pub base_url: Option<String>,
    pub model: String,
}

impl LlmConfig {
    pub fn from_env() -> Result<Self> {
        let provider = ProviderKind::parse(
            &std::env::var("LLM_PROVIDER").unwrap_or_else(|_| "openai".to_string()),
        )?;

        match provider {
            ProviderKind::OpenAi
            | ProviderKind::OpenAiCompatible
            | ProviderKind::OpenAiResponses => Ok(Self {
                provider,
                api_key: Some(required_env("OPENAI_API_KEY")?),
                base_url: Some(
                    std::env::var("OPENAI_BASE_URL")
                        .unwrap_or_else(|_| "https://api.openai.com/v1".to_string()),
                ),
                model: std::env::var("OPENAI_MODEL").unwrap_or_else(|_| "gpt-4.1-mini".to_string()),
            }),
            ProviderKind::CodexChatGpt => Ok(Self {
                provider,
                api_key: None,
                base_url: Some(
                    std::env::var("CODEX_CHATGPT_BASE_URL")
                        .unwrap_or_else(|_| "https://chatgpt.com/backend-api/codex".to_string()),
                ),
                model: std::env::var("CODEX_MODEL").unwrap_or_else(|_| "gpt-5.5".to_string()),
            }),
            ProviderKind::Kimi => Ok(Self {
                provider,
                api_key: Some(required_env("KIMI_API_KEY")?),
                base_url: Some(
                    std::env::var("KIMI_BASE_URL")
                        .unwrap_or_else(|_| "https://api.kimi.com/coding/v1".to_string()),
                ),
                model: std::env::var("KIMI_MODEL")
                    .unwrap_or_else(|_| "kimi-for-coding".to_string()),
            }),
            ProviderKind::Moonshot => Ok(Self {
                provider,
                api_key: Some(required_env("MOONSHOT_API_KEY")?),
                base_url: Some(
                    std::env::var("MOONSHOT_BASE_URL")
                        .unwrap_or_else(|_| "https://api.moonshot.cn/v1".to_string()),
                ),
                model: std::env::var("MOONSHOT_MODEL").unwrap_or_else(|_| "kimi-k2.6".to_string()),
            }),
            ProviderKind::Anthropic => Ok(Self {
                provider,
                api_key: Some(required_env("ANTHROPIC_API_KEY")?),
                base_url: Some(
                    std::env::var("ANTHROPIC_BASE_URL")
                        .unwrap_or_else(|_| "https://api.anthropic.com/v1".to_string()),
                ),
                model: std::env::var("ANTHROPIC_MODEL")
                    .unwrap_or_else(|_| "claude-3-5-sonnet-latest".to_string()),
            }),
            ProviderKind::Gemini => Ok(Self {
                provider,
                api_key: Some(required_env("GEMINI_API_KEY")?),
                base_url: Some(std::env::var("GEMINI_BASE_URL").unwrap_or_else(|_| {
                    "https://generativelanguage.googleapis.com/v1beta".to_string()
                })),
                model: std::env::var("GEMINI_MODEL")
                    .unwrap_or_else(|_| "gemini-1.5-flash".to_string()),
            }),
            ProviderKind::Ollama => Ok(Self {
                provider,
                api_key: None,
                base_url: Some(
                    std::env::var("OLLAMA_BASE_URL")
                        .unwrap_or_else(|_| "http://localhost:11434".to_string()),
                ),
                model: std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "llama3.1".to_string()),
            }),
        }
    }
}

fn required_env(name: &'static str) -> Result<String> {
    std::env::var(name).map_err(|_| LlmError::MissingEnv(name))
}
