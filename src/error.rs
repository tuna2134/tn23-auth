use anyhow::Error;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ResponseAPIError {
    status: u16,
    message: String,
}

#[derive(Debug)]
pub struct APIError {
    pub status: StatusCode,
    pub message: String,
}

impl APIError {
    /// 401 Unauthorized
    pub fn unauthorized(message: &str) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: message.to_string(),
        }
    }

    /// 404 Not Found
    pub fn not_found(message: &str) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }

    /// 400 Bad Request
    pub fn bad_request(message: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    /// 500 Internal Server Error
    pub fn internal_server_error(message: &str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.to_string(),
        }
    }
}

impl IntoResponse for APIError {
    fn into_response(self) -> Response {
        let response = Json(ResponseAPIError {
            status: self.status.as_u16(),
            message: self.message,
        });
        (self.status, response).into_response()
    }
}

impl<E> From<E> for APIError
where
    E: Into<Error>,
{
    fn from(error: E) -> Self {
        let error = error.into();
        tracing::error!("{}", error);
        APIError::internal_server_error(&error.to_string())
    }
}

pub type APIResult<T> = Result<T, APIError>;
