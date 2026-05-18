use thiserror::Error;

pub type Result<T> = std::result::Result<T, ToolError>;

#[derive(Debug, Error)]
pub enum ToolError {
    #[error("tool is already registered: {0}")]
    DuplicateTool(String),

    #[error("unknown tool: {0}")]
    UnknownTool(String),

    #[error("invalid input for tool {tool}: {message}")]
    InvalidInput { tool: String, message: String },

    #[error("tool {tool} failed: {message}")]
    Execution { tool: String, message: String },
}
