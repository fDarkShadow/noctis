use serde::Serialize;

use super::models::WebhookEvent;

/// Fire-and-forget webhook POST.
/// Logs errors but never propagates them — a webhook failure must never affect scan execution.
pub async fn send<T: Serialize>(client: &reqwest::Client, url: &str, event: &str, data: &T) {
    let payload = WebhookEvent {
        event,
        timestamp: chrono::Utc::now(),
        data,
    };

    match client
        .post(url)
        .json(&payload)
        .timeout(std::time::Duration::from_secs(5))
        .send()
        .await
    {
        Ok(resp) if !resp.status().is_success() => {
            tracing::warn!(event, url, status = %resp.status(), "webhook non-2xx");
        }
        Err(e) => {
            tracing::warn!(event, url, "webhook failed: {e}");
        }
        Ok(_) => {
            tracing::debug!(event, url, "webhook sent");
        }
    }
}
