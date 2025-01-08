use axum::response::Html;
use axum::{extract::State, response::IntoResponse};
use axum::http::HeaderMap;

use askama_axum::Template;

use crate::activity_list::show_activity_list;
use crate::app_state::AppState;
use crate::cookie_manager::is_authenticated;

#[axum::debug_handler]
pub async fn show_index(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let response = if is_authenticated(app_state, headers).await {
        show_activity_list().await
    } else {
        show_not_logged_in().await
    };

    Html(response)
}

#[derive(Template)]
#[template(path = "not_authenticated.html")]
struct NotAuthenticatedTemplate;

async fn show_not_logged_in() -> String {
    let template = NotAuthenticatedTemplate;
    template.render()
        .unwrap_or_else(|_| {
            "An error occurred while rendering the template.".to_owned()
        })
}
