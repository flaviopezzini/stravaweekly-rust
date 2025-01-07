use axum::response::Html;
use axum::{extract::State, response::IntoResponse};
use axum::http::HeaderMap;

use crate::app_state::AppState;
use crate::strava_api::strava_auth::is_authenticated;

#[axum::debug_handler]
pub async fn show_index(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if is_authenticated(app_state, headers).await {
        Html(format!(
            "Hey! You're logged in!\nClick <a href='/logout'>here</a> to log out",
        ))
    } else {
        Html("You're not logged in.\nClick <a href='/auth/strava'>here</a> to do so.".to_owned())
    }
}
