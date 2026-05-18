use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;

use super::{Result, ToolCall, ToolError, ToolHandler, ToolOutput, ToolSpec};

pub fn built_in_tools() -> Vec<Box<dyn ToolHandler>> {
    vec![Box::new(EchoTool)]
}

#[derive(Debug, Clone, Copy)]
pub struct EchoTool;

#[async_trait]
impl ToolHandler for EchoTool {
    fn name(&self) -> &'static str {
        "echo"
    }

    fn spec(&self) -> ToolSpec {
        ToolSpec::new(
            self.name(),
            "Return the provided text. Useful for validating tool-call plumbing.",
            json!({
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to return."
                    }
                },
                "required": ["text"],
                "additionalProperties": false
            }),
        )
    }

    async fn handle(&self, call: ToolCall) -> Result<ToolOutput> {
        let input: EchoInput =
            serde_json::from_value(call.input).map_err(|error| ToolError::InvalidInput {
                tool: self.name().to_owned(),
                message: error.to_string(),
            })?;

        Ok(ToolOutput::text(call.id, input.text))
    }
}

#[derive(Debug, Deserialize)]
struct EchoInput {
    text: String,
}
