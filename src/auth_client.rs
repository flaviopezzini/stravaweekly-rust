use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AuthUrl, AuthorizationCode,
    ClientId, ClientSecret, CsrfToken, RedirectUrl, Scope, TokenResponse, TokenUrl,
};

use reqwest::Url;

use anyhow::Context;

use crate::{app_config::AppConfig, domain::AuthTokens};

#[derive(Clone, Debug)]
pub struct AuthClient {
    oauth_client: BasicClient,
}

impl AuthClient {
    pub fn new(app_config: &AppConfig) -> Result<Self, anyhow::Error> {
        Ok(
            Self {
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
        client_id: String,
        client_secret: String,
    ) -> Result<AuthTokens, anyhow::Error> {
        let token_response = self
            .oauth_client
            .exchange_code(AuthorizationCode::new(code))
            .add_extra_param("client_id", client_id)
            .add_extra_param("client_secret", client_secret)
            .request_async(async_http_client)
            .await
            .context("failed in sending request to authorization server")?;

        Ok(
            AuthTokens::new(
                token_response.access_token().clone(),
                token_response.refresh_token().cloned()
            )
        )
    }
}
