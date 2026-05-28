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
            "openai-compatible"
            | "openai-completions"
            | "openai-chat-completions"
            | "chat-completions"
            | "compatible" => Ok(Self::OpenAiCompatible),
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
                api_key: Some(required_env_any(&["LLM_API_KEY", "OPENAI_API_KEY"])?),
                base_url: Some(
                    optional_env_any(&["LLM_BASE_URL", "OPENAI_BASE_URL"])
                        .unwrap_or_else(|| "https://api.openai.com/v1".to_string()),
                ),
                model: optional_env_any(&["LLM_MODEL", "OPENAI_MODEL"])
                    .unwrap_or_else(|| "gpt-4.1-mini".to_string()),
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
                api_key: Some(required_env_any(&["LLM_API_KEY", "ANTHROPIC_API_KEY"])?),
                base_url: Some(
                    optional_env_any(&["LLM_BASE_URL", "ANTHROPIC_BASE_URL"])
                        .unwrap_or_else(|| "https://api.anthropic.com/v1".to_string()),
                ),
                model: optional_env_any(&["LLM_MODEL", "ANTHROPIC_MODEL"])
                    .unwrap_or_else(|| "claude-3-5-sonnet-latest".to_string()),
            }),
            ProviderKind::Gemini => Ok(Self {
                provider,
                api_key: Some(required_env_any(&["LLM_API_KEY", "GEMINI_API_KEY"])?),
                base_url: Some(
                    optional_env_any(&["LLM_BASE_URL", "GEMINI_BASE_URL"]).unwrap_or_else(|| {
                        "https://generativelanguage.googleapis.com/v1beta".to_string()
                    }),
                ),
                model: optional_env_any(&["LLM_MODEL", "GEMINI_MODEL"])
                    .unwrap_or_else(|| "gemini-1.5-flash".to_string()),
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
    optional_env_any(&[name]).ok_or(LlmError::MissingEnv(name))
}

fn required_env_any(names: &[&'static str]) -> Result<String> {
    optional_env_any(names).ok_or(LlmError::MissingEnv(names[0]))
}

fn optional_env_any(names: &[&'static str]) -> Option<String> {
    names.iter().find_map(|name| {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn openai_provider_accepts_generic_relay_env() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        unsafe {
            clear_llm_env();
            std::env::set_var("LLM_PROVIDER", "openai-responses");
            std::env::set_var("LLM_API_KEY", "relay-key");
            std::env::set_var("LLM_MODEL", "gpt-5.4");
            std::env::set_var("LLM_BASE_URL", "https://api.duojie.games/v1");
        }

        let config = LlmConfig::from_env().expect("config should load");

        assert_eq!(config.provider, ProviderKind::OpenAiResponses);
        assert_eq!(config.api_key.as_deref(), Some("relay-key"));
        assert_eq!(config.model, "gpt-5.4");
        assert_eq!(
            config.base_url.as_deref(),
            Some("https://api.duojie.games/v1")
        );

        unsafe {
            clear_llm_env();
        }
    }

    #[test]
    fn openai_provider_prefers_generic_relay_env_over_provider_specific_env() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        unsafe {
            clear_llm_env();
            std::env::set_var("LLM_PROVIDER", "openai-completions");
            std::env::set_var("LLM_API_KEY", "relay-key");
            std::env::set_var("LLM_MODEL", "relay-model");
            std::env::set_var("LLM_BASE_URL", "https://relay.example.com/v1");
            std::env::set_var("OPENAI_API_KEY", "stale-openai-key");
            std::env::set_var("OPENAI_MODEL", "stale-openai-model");
            std::env::set_var("OPENAI_BASE_URL", "https://stale.example.com/v1");
        }

        let config = LlmConfig::from_env().expect("config should load");

        assert_eq!(config.provider, ProviderKind::OpenAiCompatible);
        assert_eq!(config.api_key.as_deref(), Some("relay-key"));
        assert_eq!(config.model, "relay-model");
        assert_eq!(
            config.base_url.as_deref(),
            Some("https://relay.example.com/v1")
        );

        unsafe {
            clear_llm_env();
        }
    }

    #[test]
    fn anthropic_provider_accepts_generic_relay_env() {
        let _guard = ENV_LOCK.lock().expect("env lock should not be poisoned");
        unsafe {
            clear_llm_env();
            std::env::set_var("LLM_PROVIDER", "anthropic");
            std::env::set_var("LLM_API_KEY", "relay-key");
            std::env::set_var("LLM_MODEL", "glm-5");
            std::env::set_var("LLM_BASE_URL", "https://api.duojie.games");
        }

        let config = LlmConfig::from_env().expect("config should load");

        assert_eq!(config.provider, ProviderKind::Anthropic);
        assert_eq!(config.api_key.as_deref(), Some("relay-key"));
        assert_eq!(config.model, "glm-5");
        assert_eq!(config.base_url.as_deref(), Some("https://api.duojie.games"));

        unsafe {
            clear_llm_env();
        }
    }

    unsafe fn clear_llm_env() {
        for name in [
            "LLM_PROVIDER",
            "LLM_API_KEY",
            "LLM_MODEL",
            "LLM_BASE_URL",
            "OPENAI_API_KEY",
            "OPENAI_MODEL",
            "OPENAI_BASE_URL",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_MODEL",
            "ANTHROPIC_BASE_URL",
            "GEMINI_API_KEY",
            "GEMINI_MODEL",
            "GEMINI_BASE_URL",
        ] {
            unsafe {
                std::env::remove_var(name);
            }
        }
    }
}
