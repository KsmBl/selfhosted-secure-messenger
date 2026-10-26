//! API errors rendered as RFC 9457 problem details.

use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use ssm_proto::api::Problem;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub kind: &'static str,
    pub detail: Option<String>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, kind: &'static str) -> Self {
        Self { status, kind, detail: None }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad-request").with_detail(detail)
    }

    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized")
    }

    pub fn forbidden(kind: &'static str) -> Self {
        Self::new(StatusCode::FORBIDDEN, kind)
    }

    pub fn not_found() -> Self {
        Self::new(StatusCode::NOT_FOUND, "not-found")
    }

    pub fn conflict(kind: &'static str) -> Self {
        Self::new(StatusCode::CONFLICT, kind)
    }

    pub fn too_many_requests() -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "rate-limited")
    }

    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal")
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "database error");
        Self::internal()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = Problem {
            kind: format!("urn:ssm:problem:{}", self.kind),
            title: self.status.canonical_reason().unwrap_or("error").to_owned(),
            status: self.status.as_u16(),
            detail: self.detail,
        };
        let body = serde_json::to_vec(&problem).unwrap_or_default();
        (self.status, [(header::CONTENT_TYPE, "application/problem+json")], body).into_response()
    }
}
