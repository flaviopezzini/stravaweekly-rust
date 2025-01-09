use axum::response::{Html, IntoResponse};
use tokio::fs;

pub async fn serve_static_file(path: String) -> impl axum::response::IntoResponse {
    match fs::read_to_string(path).await {
        Ok(contents) => Html(contents).into_response(),
        Err(_) => (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "File not found").into_response(),
    }
}
