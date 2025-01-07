use chrono::Utc;
use oauth2::CsrfToken;

use crate::{domain::AuthResponse, secret_value::SecretValue};

#[derive(Clone)]
pub enum SessionData {
    NotYetAuthorized(NotYetAuthorizedSessionData),
    Authorized(AuthorizedSessionData),
}

#[derive(Clone)]
pub struct MyCsrfToken(CsrfToken);
impl MyCsrfToken {
    pub fn match_csrf(&self, request_csrf_state: CsrfToken) -> bool {
        self.0.secret() == request_csrf_state.secret()
    }
}

#[derive(Clone)]
pub struct MyAccessToken {
    value: SecretValue,
    expires_at: u64,
}
impl MyAccessToken {
    pub fn new(value: String, expires_at: u64) -> Self {
        Self {
            value: SecretValue::new(value),
            expires_at,
        }
    }

    pub fn is_valid(&self) -> bool {
        Utc::now().timestamp() as u64 > self.expires_at
    }
}

#[derive(Clone)]
pub struct MyRefreshToken{
    pub value: SecretValue
}
impl MyRefreshToken {
    pub fn new(value: String) -> Self {
        Self {
            value: SecretValue::new(value)
        }
    }
}

#[derive(Clone)]
pub struct NotYetAuthorizedSessionData {
    pub csrf_token: MyCsrfToken,
}
impl NotYetAuthorizedSessionData {
    pub fn new(csrf_token: CsrfToken) -> Self {
        Self {
            csrf_token: MyCsrfToken(csrf_token)
        }
    }
}

#[derive(Clone)]
pub struct AuthorizedSessionData {
    pub access_token: MyAccessToken,
    pub refresh_token: MyRefreshToken,
    created_at: i64,
}

impl AuthorizedSessionData {
    pub fn new(
        auth_response: AuthResponse,
    ) -> Self {
        Self {
            access_token: MyAccessToken::new(auth_response.access_token, auth_response.expires_at),
            refresh_token: MyRefreshToken::new(auth_response.refresh_token),
            created_at: Utc::now().timestamp()
        }
    }

    pub fn refresh_tokens(
        auth_response: AuthResponse
    ) -> Self {
        Self::new(auth_response)
    }

}
