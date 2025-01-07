use axum::{routing::get, Router};

use crate::app_state::AppState;
use crate::index::show_index;
use crate::strava_api::strava_routes::{
    redirect_to_strava_login_page,
    handle_login_authorized,
    logout
};

pub fn setup_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(show_index))
        .route("/auth/strava", get(redirect_to_strava_login_page))
        .route("/auth/authorized", get(handle_login_authorized))
        .route("/logout", get(logout))
        .with_state(app_state)
}
