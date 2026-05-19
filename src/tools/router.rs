use std::sync::Arc;

use super::{Result, ToolCall, ToolOutput, ToolProgressCallback, ToolRegistry};

#[derive(Clone)]
pub struct ToolRouter {
    registry: ToolRegistry,
}

impl ToolRouter {
    pub fn new(registry: ToolRegistry) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &ToolRegistry {
        &self.registry
    }

    pub async fn route(&self, call: ToolCall) -> Result<ToolOutput> {
        self.registry.dispatch(call).await
    }

    pub async fn route_with_progress<F>(&self, call: ToolCall, progress: F) -> Result<ToolOutput>
    where
        F: Fn(super::ToolProgress) + Send + Sync + 'static,
    {
        self.registry
            .dispatch_with_progress(call, Arc::new(progress) as ToolProgressCallback)
            .await
    }
}
