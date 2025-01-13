use chrono::{DateTime, FixedOffset, NaiveDateTime, TimeZone};

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};

use reqwest::{Client, Url};

use anyhow::Context;

use crate::tokens::MyCsrfToken;
use crate::{
    app_config::AppConfig, domain::AuthResponse, secret_value::SecretValue, tokens::MyRefreshToken,
};

#[derive(Clone)]
pub struct StravaClient {
    app_config: AppConfig,
}

const STRAVA_URL: &str = "https://www.strava.com";

impl StravaClient {
    pub fn new(app_config: AppConfig) -> Result<Self, anyhow::Error> {
        Ok(Self {
            app_config: app_config.clone(),
        })
    }

    pub fn get_auth_url(&self) -> (Url, MyCsrfToken) {
        let csrf_token = MyCsrfToken::new_random();

        let mut url = Url::parse("https://www.strava.com/oauth/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("client_id", &self.app_config.client_id.expose_secret())
            .append_pair("redirect_uri", &self.app_config.redirect_url)
            .append_pair("response_type", "code")
            .append_pair("scope", "activity:read_all")
            .append_pair("state", csrf_token.secret());

        (url, csrf_token)
    }

    pub async fn fetch_token(&self, code: String) -> Result<AuthResponse, anyhow::Error> {
        let client = Client::new();

        let token_response = client
            .post(format!("{}/oauth/token", STRAVA_URL))
            .form(&[
                ("client_id", &self.app_config.client_id.expose_secret()),
                (
                    "client_secret",
                    &self.app_config.client_secret.expose_secret(),
                ),
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
                ("refresh_token", &refresh_token.value),
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
        jwt_token: SecretValue,
        user_timezone_offset_in_hours: i32,
        start_date_time: NaiveDateTime,
        end_date_time: NaiveDateTime,
    ) -> Result<String, anyhow::Error> {
        let client = Client::new();

        let user_zone_offset = FixedOffset::east_opt(user_timezone_offset_in_hours * 3600).unwrap();

        // Convert start_date and end_date to DateTime with the user's timezone
        let zoned_start: DateTime<FixedOffset> = user_zone_offset
            .from_local_datetime(&start_date_time)
            .unwrap();
        let zoned_end: DateTime<FixedOffset> = user_zone_offset
            .from_local_datetime(&end_date_time)
            .unwrap();

        // Convert the DateTime to Unix timestamps (seconds since epoch)
        let before = zoned_end.timestamp(); // End time
        let after = zoned_start.timestamp(); // Start time

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", jwt_token.expose_secret()))?,
        );

        let token_response = client
            .get(format!(
                "{}/api/v3/athlete/activities?before={}&after={}",
                STRAVA_URL, before, after
            ))
            .headers(headers)
            .send()
            .await
            .context("Failed to send list activity request")?;

        Ok(token_response.text().await?)
    }
}
