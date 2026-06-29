use std::collections::HashMap;
use std::time::Duration;

use indexmap::IndexMap;
use reqwest::{header::HeaderMap, redirect::Policy, Client, Method};
use serde::{Deserialize, Serialize};

use crate::error::{NoctisError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
    pub duration_ms: u64,
    pub url: String,
}

pub struct HttpCheck {
    client: Client,
}

impl HttpCheck {
    pub fn new(follow_redirects: bool, tls_insecure: bool, timeout_secs: u64) -> Result<Self> {
        let redirect = if follow_redirects {
            Policy::limited(10)
        } else {
            Policy::none()
        };

        let client = Client::builder()
            .redirect(redirect)
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(tls_insecure)
            .build()
            .map_err(NoctisError::Http)?;

        Ok(Self { client })
    }

    pub async fn run(
        &self,
        method: &str,
        url: &str,
        headers: &IndexMap<String, String>,
        body: Option<&str>,
    ) -> Result<HttpResult> {
        let method = Method::from_bytes(method.as_bytes()).map_err(|_| NoctisError::StepError {
            test: String::new(),
            step: String::new(),
            message: format!("invalid HTTP method: {method}"),
        })?;

        let mut req = self.client.request(method, url);

        let mut header_map = HeaderMap::new();
        for (k, v) in headers {
            if let (Ok(name), Ok(value)) = (
                reqwest::header::HeaderName::from_bytes(k.as_bytes()),
                reqwest::header::HeaderValue::from_str(v),
            ) {
                header_map.insert(name, value);
            }
        }
        req = req.headers(header_map);

        if let Some(b) = body {
            req = req.body(b.to_string());
        }

        let start = std::time::Instant::now();
        let resp = req.send().await.map_err(NoctisError::Http)?;
        let duration_ms = start.elapsed().as_millis() as u64;

        let status = resp.status().as_u16();
        let url_final = resp.url().to_string();

        let mut resp_headers = HashMap::new();
        for (k, v) in resp.headers() {
            resp_headers.insert(k.to_string(), v.to_str().unwrap_or("<binary>").to_string());
        }

        let body = resp.text().await.map_err(NoctisError::Http)?;

        Ok(HttpResult {
            status,
            headers: resp_headers,
            body,
            duration_ms,
            url: url_final,
        })
    }
}
