use axum::response::Html;
use axum::{extract::State, response::IntoResponse};
use axum::http::HeaderMap;

use crate::activity_list::show_activity_list;
use crate::app_state::AppState;
use crate::cookie_manager::is_authenticated;

#[axum::debug_handler]
pub async fn show_index(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if is_authenticated(app_state, headers).await {
        show_activity_list().await.into_response()
    } else {
        show_not_logged_in().await.into_response()
    }
}

async fn show_not_logged_in() -> impl IntoResponse {
    Html("You're not logged in.\nClick <a href='/auth/strava'>here</a> to do so.".to_owned())
}
