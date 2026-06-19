pub mod http;
pub mod ssh;
pub mod tcp;
pub mod tls;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    pub matched: bool,
    pub captures: Vec<String>,
}
