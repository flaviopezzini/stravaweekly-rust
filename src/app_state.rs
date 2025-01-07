use crate::{app_config::AppConfig, app_session::AppSession, strava_api::strava_auth::AuthClient};

#[derive(Clone)]
pub struct AppState {
    pub app_config: AppConfig,
    pub sessions: AppSession,
    pub auth_client: AuthClient,
}

impl AppState {
    pub fn new(app_config: AppConfig, auth_client: AuthClient) -> Self {
        Self {
            app_config,
            sessions: AppSession::new(),
            auth_client,
        }
    }
}
