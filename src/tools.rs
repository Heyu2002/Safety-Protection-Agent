mod builtins;
mod error;
mod registry;
mod types;

pub use builtins::{EchoTool, built_in_tools};
pub use error::{Result, ToolError};
pub use registry::{ToolHandler, ToolRegistry, ToolRegistryBuilder};
pub use types::{ToolCall, ToolOutput, ToolSpec};
