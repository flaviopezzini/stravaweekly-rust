use axum::response::IntoResponse;

use crate::serve_static::serve_static_file;

#[axum::debug_handler]
pub async fn show_index(
) -> impl IntoResponse {
    serve_static_file("static/list_activities.html".into()).await
}
