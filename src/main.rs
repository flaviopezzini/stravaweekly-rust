use crate::strava_api::http_calls::StravaClient;
use app_config::AppConfig;
use app_state::AppState;
use router_setup::setup_router;

mod activity_list;
mod app_config;
mod app_state;
mod cookie_manager;
mod domain;
mod index;
mod router_setup;
mod secret_value;
mod serve_static;
mod strava_api;
mod tokens;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    dotenvy::dotenv().ok();

    let app_config = AppConfig::new();

    let strava_client =
        StravaClient::new(app_config.clone()).expect("Error configuring Strava Oauth2 Client");
    let app_state = AppState::new(app_config, strava_client);

    let app = setup_router(app_state).await;

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind TcpListener");

    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .await
        .expect("Unable to start Axum server");
}
