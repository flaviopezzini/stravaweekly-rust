use axum::{routing::get, Router};

use crate::activity_list::list_athlete_activities;
use crate::app_state::AppState;
use crate::index::show_index;
use crate::strava_api::strava_routes::{
    handle_login_authorized, logout, redirect_to_strava_login_page,
};

pub async fn setup_router(app_state: AppState) -> Router {
    Router::new()
        .route("/", get(show_index))
        .route("/auth/strava", get(redirect_to_strava_login_page))
        .route("/auth/authorized", get(handle_login_authorized))
        .route("/logout", get(logout))
        .route("/athlete/activities", get(list_athlete_activities))
        .with_state(app_state)
}
