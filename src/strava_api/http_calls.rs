use chrono::{DateTime, FixedOffset, NaiveDate, TimeZone};
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl
};

use reqwest::{Client, Url};

use anyhow::Context;
use serde::Deserialize;

use crate::{app_config::AppConfig, domain::AuthResponse, session_data::MyRefreshToken};

#[derive(Clone)]
pub struct StravaClient {
    app_config: AppConfig,
    oauth_client: BasicClient,
}

const STRAVA_URL: &str = "https://www.strava.com";

#[derive(Deserialize)]
pub struct ActivityListPayload {

}

impl StravaClient {
    pub fn new(app_config: AppConfig) -> Result<Self, anyhow::Error> {
        Ok(
            Self {
                app_config: app_config.clone(),
                oauth_client: BasicClient::new(
                    ClientId::new(app_config.client_id.expose_secret()),
                    Some(ClientSecret::new(app_config.client_secret.expose_secret())),
                    AuthUrl::new(app_config.auth_url.clone()).context("failed to create new authorization server URL")?,
                    Some(TokenUrl::new(app_config.token_url.clone()).context("failed to create new token endpoint URL")?),
                )
                .set_redirect_uri(
                    RedirectUrl::new(app_config.redirect_url.clone()).context("failed to create new redirection URL")?,
                )
            }
        )
    }

    pub fn get_auth_url(&self) -> (Url, CsrfToken) {
        let (auth_url, csrf_state) = self
            .oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("activity:read_all".to_owned()))
            .url();
        (auth_url, csrf_state)
    }

    pub async fn fetch_token(
        &self,
        code: String,
    ) -> Result<AuthResponse, anyhow::Error> {
        let client = Client::new();

        let token_response = client
            .post(format!("{}/oauth/token", STRAVA_URL))
            .form(&[
                ("client_id", &self.app_config.client_id.expose_secret()),
                ("client_secret", &self.app_config.client_secret.expose_secret()),
                ("code", &code),
                ("grant_type", &"authorization_code".to_string()),
            ])
            .send()
            .await
            .context("Failed to exchange code for tokens")?
            .json::<AuthResponse>()
            .await
            .context("Failed to parse fetch token response")?;

        Ok(token_response)
    }

    pub async fn refresh_tokens(
        &self,
        app_config: &AppConfig,
        refresh_token: MyRefreshToken,
    ) -> Result<AuthResponse, anyhow::Error> {
        let client = Client::new();

        let token_response = client
            .post(format!("{}/oauth/token", STRAVA_URL))
            .form(&[
                ("client_id", &app_config.client_id.expose_secret()),
                ("client_secret", &app_config.client_secret.expose_secret()),
                ("grant_type", &"refresh_token".to_string()),
                ("refresh_token", &refresh_token.value.expose_secret()),
            ])
            .send()
            .await
            .context("Failed to send token refresh request")?
            .json::<AuthResponse>()
            .await
            .context("Failed to parse token refresh response")?;

        Ok(token_response)
    }

    pub async fn list_athlete_activities(
        user_timezone_offset_in_hours: i32,
        start_date: NaiveDate,
        end_date: NaiveDate
    ) -> Result<ActivityListPayload, anyhow::Error> {
        let client = Client::new();

        let start_date_time = start_date.and_hms_opt(0, 0, 0).unwrap();
        let end_date_time = end_date.and_hms_opt(0, 0, 0).unwrap();

        let user_zone_offset = FixedOffset::east_opt(user_timezone_offset_in_hours * 3600).unwrap();

        // Convert start_date and end_date to DateTime with the user's timezone
        let zoned_start: DateTime<FixedOffset> =
            user_zone_offset.from_local_datetime(&start_date_time).unwrap();
        let zoned_end: DateTime<FixedOffset> =
            user_zone_offset.from_local_datetime(&end_date_time).unwrap();

        // Convert the DateTime to Unix timestamps (seconds since epoch)
        let before = zoned_end.timestamp(); // End time
        let after = zoned_start.timestamp(); // Start time

        let token_response = client
            .get(
                format!("{}/api/v3/athlete/activities?before={}&after={}", STRAVA_URL, before, after)
            )
            .send()
            .await
            .context("Failed to send list activity request")?
            .json::<ActivityListPayload>()
            .await
            .context("Failed to parse list activity response")?;

        Ok(token_response)
    }
}
