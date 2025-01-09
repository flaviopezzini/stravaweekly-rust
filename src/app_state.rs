use crate::{app_config::AppConfig, strava_api::http_calls::StravaClient};

#[derive(Clone)]
pub struct AppState {
    pub app_config: AppConfig,
    pub strava_client: StravaClient,
}

impl AppState {
    pub fn new(app_config: AppConfig, strava_client: StravaClient) -> Self {
        Self {
            app_config,
            strava_client,
        }
    }
}
