use thiserror::Error;

#[derive(Debug, Error)]
pub enum NoctisError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("YAML parse error in {file}: {source}")]
    Yaml {
        file: String,
        source: serde_yaml::Error,
    },

    #[error("Include cycle detected: {0}")]
    IncludeCycle(String),

    #[error("Include not found: {0}")]
    IncludeNotFound(String),

    #[error("Step '{step}' in test '{test}': {message}")]
    StepError {
        test: String,
        step: String,
        message: String,
    },

    #[error("Expression error in step '{step}': {message}")]
    ExprError {
        step: String,
        message: String,
    },

    #[error("HTTP check failed: {0}")]
    Http(#[from] reqwest::Error),

    #[error("TCP check failed: {0}")]
    Tcp(String),

    #[error("TLS check failed: {0}")]
    Tls(String),

    #[error("SSH check failed: {0}")]
    Ssh(String),

    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),

    #[error("Missing required field '{field}' for action '{action}' in step '{step}'")]
    MissingField {
        field: &'static str,
        action: &'static str,
        step: String,
    },

    #[error("OOB server error: {0}")]
    Oob(String),

    #[error("Template error: {0}")]
    Template(String),
}

pub type Result<T> = std::result::Result<T, NoctisError>;
