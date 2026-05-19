use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

use super::{
    DatabaseRiskScanTool, EchoTool, HttpLoadTestTool, Result, ToolCall, ToolError, ToolOutput,
    ToolProgressCallback, ToolSpec,
};

#[async_trait]
pub trait ToolHandler: Send + Sync {
    fn name(&self) -> &'static str;

    fn spec(&self) -> ToolSpec;

    fn supports_parallel_calls(&self) -> bool {
        false
    }

    async fn handle(&self, call: ToolCall) -> Result<ToolOutput>;

    async fn handle_with_progress(
        &self,
        call: ToolCall,
        _progress: ToolProgressCallback,
    ) -> Result<ToolOutput> {
        self.handle(call).await
    }
}

#[derive(Clone, Default)]
pub struct ToolRegistry {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
}

impl ToolRegistry {
    pub fn builder() -> ToolRegistryBuilder {
        ToolRegistryBuilder::default()
    }

    pub fn empty() -> Self {
        Self::default()
    }

    pub fn with_builtins() -> Result<Self> {
        Self::builder()
            .register(EchoTool)?
            .register(HttpLoadTestTool)?
            .register(DatabaseRiskScanTool)
            .map(ToolRegistryBuilder::build)
    }

    pub fn has(&self, name: &str) -> bool {
        self.handlers.contains_key(name)
    }

    pub fn spec(&self, name: &str) -> Option<ToolSpec> {
        self.handlers.get(name).map(|handler| handler.spec())
    }

    pub fn specs(&self) -> Vec<ToolSpec> {
        let mut specs: Vec<_> = self
            .handlers
            .values()
            .map(|handler| handler.spec())
            .collect();
        specs.sort_by(|left, right| left.name.cmp(&right.name));
        specs
    }

    pub fn supports_parallel_calls(&self, name: &str) -> Option<bool> {
        self.handlers
            .get(name)
            .map(|handler| handler.supports_parallel_calls())
    }

    pub async fn dispatch(&self, call: ToolCall) -> Result<ToolOutput> {
        let handler = self
            .handlers
            .get(&call.name)
            .ok_or_else(|| ToolError::UnknownTool(call.name.clone()))?;

        handler.handle(call).await
    }

    pub async fn dispatch_with_progress(
        &self,
        call: ToolCall,
        progress: ToolProgressCallback,
    ) -> Result<ToolOutput> {
        let handler = self
            .handlers
            .get(&call.name)
            .ok_or_else(|| ToolError::UnknownTool(call.name.clone()))?;

        handler.handle_with_progress(call, progress).await
    }
}

#[derive(Default)]
pub struct ToolRegistryBuilder {
    handlers: HashMap<String, Arc<dyn ToolHandler>>,
}

impl ToolRegistryBuilder {
    pub fn register_boxed(mut self, handler: Box<dyn ToolHandler>) -> Result<Self> {
        let name = handler.name().to_owned();
        if self.handlers.contains_key(&name) {
            return Err(ToolError::DuplicateTool(name));
        }

        self.handlers.insert(name, Arc::from(handler));
        Ok(self)
    }

    pub fn register<T>(mut self, handler: T) -> Result<Self>
    where
        T: ToolHandler + 'static,
    {
        let name = handler.name().to_owned();
        if self.handlers.contains_key(&name) {
            return Err(ToolError::DuplicateTool(name));
        }

        self.handlers.insert(name, Arc::new(handler));
        Ok(self)
    }

    pub fn build(self) -> ToolRegistry {
        ToolRegistry {
            handlers: self.handlers,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::tools::EchoTool;

    #[tokio::test]
    async fn dispatches_registered_tool() {
        let registry = ToolRegistry::builder()
            .register(EchoTool)
            .expect("echo should register")
            .build();

        let output = registry
            .dispatch(ToolCall::new("echo", json!({ "text": "hello" })))
            .await
            .expect("echo should run");

        assert_eq!(output.content, "hello");
    }

    #[test]
    fn rejects_duplicate_tool_names() {
        let result = ToolRegistry::builder()
            .register(EchoTool)
            .expect("first echo should register")
            .register(EchoTool);

        assert!(matches!(result, Err(ToolError::DuplicateTool(name)) if name == "echo"));
    }

    #[tokio::test]
    async fn reports_unknown_tool() {
        let registry = ToolRegistry::empty();
        let result = registry.dispatch(ToolCall::new("missing", json!({}))).await;

        assert!(matches!(result, Err(ToolError::UnknownTool(name)) if name == "missing"));
    }
}
