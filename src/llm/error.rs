use thiserror::Error;

pub type Result<T> = std::result::Result<T, LlmError>;

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("missing required environment variable: {0}")]
    MissingEnv(&'static str),

    #[error("unsupported LLM provider: {0}")]
    UnsupportedProvider(String),

    #[error("request failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("provider returned an error: {0}")]
    Provider(String),

    #[error("provider response did not contain text output")]
    EmptyResponse,
}
