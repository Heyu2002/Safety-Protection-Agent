mod config;
mod error;
mod providers;
mod types;

pub use config::{LlmConfig, ProviderKind};
pub use error::{LlmError, Result};
pub use types::{
    AgentToolCall, AgentToolSpec, AgentToolTranscriptItem, AgentTurnRequest, AgentTurnResponse,
    ChatMessage, ChatRole, ChatUsage, CompletionRequest, CompletionResponse,
};

use async_trait::async_trait;
use std::sync::Arc;

pub type CompletionDeltaCallback = Arc<dyn Fn(&str) + Send + Sync>;

#[async_trait]
pub trait LlmClient: Send + Sync {
    async fn complete(&self, request: CompletionRequest) -> Result<CompletionResponse>;

    fn supports_native_tools(&self) -> bool {
        false
    }

    async fn complete_streaming(
        &self,
        request: CompletionRequest,
        on_delta: CompletionDeltaCallback,
    ) -> Result<CompletionResponse> {
        let response = self.complete(request).await?;
        if !response.content.is_empty() {
            on_delta(&response.content);
        }
        Ok(response)
    }

    async fn complete_agent_turn(
        &self,
        _request: AgentTurnRequest,
        _on_delta: CompletionDeltaCallback,
    ) -> Result<AgentTurnResponse> {
        Err(LlmError::UnsupportedNativeTools)
    }

    fn should_retry_without_temperature(&self, error: &LlmError) -> bool {
        matches!(
            error,
            LlmError::Provider { body, .. }
                if body.to_ascii_lowercase().contains("unsupported parameter")
                    && body.to_ascii_lowercase().contains("temperature")
        )
    }
}

pub fn client_from_env() -> Result<Box<dyn LlmClient>> {
    let config = LlmConfig::from_env()?;
    client_from_config(config)
}

pub fn client_from_config(config: LlmConfig) -> Result<Box<dyn LlmClient>> {
    providers::client_from_config(config)
}
