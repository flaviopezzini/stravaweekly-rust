use http::HeaderMap;
use oauth2::{
    basic::BasicClient, AuthUrl, ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenUrl
};

use reqwest::{Client, Url};

use anyhow::Context;

use crate::{app_config::AppConfig, app_session::SessionId, app_state::AppState, cookie_manager::get_session_id_cookie, domain::AuthResponse, session_data::{AuthorizedSessionData, MyRefreshToken, SessionData}};

#[derive(Clone)]
pub struct AuthClient {
    app_config: AppConfig,
    oauth_client: BasicClient,
}

const STRAVA_URL: &str = "https://www.strava.com";

impl AuthClient {
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
}

pub async fn is_authenticated(app_state: AppState, headers: HeaderMap) -> bool {
    let session_id: SessionId;
    if let Some(s_id) = get_session_id_cookie(headers) {
        session_id = s_id;
    } else {
        tracing::debug!("No session ID cookie");
        return false;
    }

    let session_data: SessionData;
    if let Some(data) = app_state.sessions.get(session_id.clone()) {
        session_data = data;
    } else {
        tracing::debug!("No session data stored");
        return false;
    }

    match session_data {
        SessionData::NotYetAuthorized(_) => return false,
        SessionData::Authorized(data) => {
            if data.access_token.is_valid() {
                return true;
            } else if let Ok(new_tokens) = app_state.auth_client
                    .refresh_tokens(&app_state.app_config, data.refresh_token).await {

                    let new_session_data =
                        AuthorizedSessionData::refresh_tokens(new_tokens);

                    app_state.sessions.update(session_id, new_session_data);
                    return true;
            }
        },
    };
    false
}
