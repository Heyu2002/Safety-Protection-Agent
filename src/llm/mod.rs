mod config;
mod error;
mod providers;
mod types;

pub use config::{LlmConfig, ProviderKind};
pub use error::{LlmError, Result};
pub use types::{ChatMessage, ChatRole, ChatUsage, CompletionRequest, CompletionResponse};

use async_trait::async_trait;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;
}

pub fn client_from_env() -> Result<Box<dyn LlmClient>> {
    let config = LlmConfig::from_env()?;
    client_from_config(config)
}

pub fn client_from_config(config: LlmConfig) -> Result<Box<dyn LlmClient>> {
    providers::client_from_config(config)
}
