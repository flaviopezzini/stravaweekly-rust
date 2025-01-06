use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl
};

use reqwest::{Client, Url};

use anyhow::Context;

use crate::{app_config::AppConfig, domain::AuthResponse};

#[derive(Clone)]
pub struct AuthClient {
    app_config: AppConfig,
    oauth_client: BasicClient,
}

impl AuthClient {
    pub fn new(app_config: AppConfig) -> Result<Self, anyhow::Error> {
        Ok(
            Self {
                app_config: app_config.clone(),
                oauth_client: BasicClient::new(
                    ClientId::new(app_config.client_id.clone()),
                    Some(ClientSecret::new(app_config.get_secret())),
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
            .post("https://www.strava.com/oauth/token")
            .form(&[
                ("client_id", &self.app_config.client_id),
                ("client_secret", &self.app_config.get_secret()),
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
        refresh_token: String,
    ) -> Result<AuthResponse, anyhow::Error> {
        let client = Client::new();

        let token_response = client
            .post("https://www.strava.com/oauth/token")
            .form(&[
                ("client_id", &app_config.client_id),
                ("client_secret", &app_config.get_secret()),
                ("grant_type", &"refresh_token".to_string()),
                ("refresh_token", &refresh_token),
            ])
            .send()
            .await
            .context("Failed to send token refresh request")?
            .json::<AuthResponse>()
            .await
            .context("Failed to parse token refresh response")?;

        Ok(token_response)
    }
}
