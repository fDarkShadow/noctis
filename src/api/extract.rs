use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::Json;
use serde::de::DeserializeOwned;
use validator::Validate;

use super::models::ApiError;

/// Axum extractor that deserialises the JSON body then validates with `validator`.
///
/// Returns 422 with `ApiError` if the body is malformed or validation constraints fail.
pub struct Valid<T>(pub T);

impl<S, T> FromRequest<S> for Valid<T>
where
    T: DeserializeOwned + Validate + Send + 'static,
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ApiError>);

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let value = Json::<T>::from_request(req, state)
            .await
            .map_err(|e| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(ApiError {
                        error: "invalid_body",
                        detail: Some(serde_json::Value::String(e.to_string())),
                    }),
                )
            })?
            .0;

        value.validate().map_err(|e| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ApiError {
                    error: "validation_failed",
                    detail: serde_json::to_value(e).ok(),
                }),
            )
        })?;

        Ok(Valid(value))
    }
}
