use thiserror::Error;

pub type Result<T> = std::result::Result<T, LlmError>;

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),

    #[error("unsupported LLM provider: {0}")]
    UnsupportedProvider(String),

    #[error("LLM provider does not support native tool calls")]
    UnsupportedNativeTools,

    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("provider returned an error: status={status}, body={body}")]
    Provider { status: u16, body: String },

    #[error("provider response did not contain text output")]
    EmptyResponse,
}
