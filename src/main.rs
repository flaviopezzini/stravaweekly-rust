use app_config::AppConfig;
use app_state::AppState;
use router_setup::setup_router;
use crate::strava_api::strava_auth::AuthClient;

mod app_config;
mod app_error;
mod app_session;
mod app_state;
mod cookie_manager;
mod domain;
mod index;
mod router_setup;
mod secret_value;
mod session_data;
mod strava_api;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app_config = AppConfig::new();

    let auth_client = AuthClient::new(app_config.clone()).expect("Error configuring Oauth2 Client");
    let app_state = AppState::new(app_config, auth_client);

    let app = setup_router(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind TcpListener");

    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .await
        .expect("Unable to start Axum server");
}
