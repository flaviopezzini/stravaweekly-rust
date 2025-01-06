use chrono::Utc;
use oauth2::CsrfToken;

use crate::domain::AuthResponse;

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
    pub access_token: String,
    pub expires_at: u64,
    pub refresh_token: String,
    created_at: i64,
}

impl AuthorizedSessionData {
    pub fn new(
        auth_response: AuthResponse,
    ) -> Self {
        Self {
            access_token: auth_response.access_token,
            expires_at: auth_response.expires_at,
            refresh_token: auth_response.refresh_token,
            created_at: Utc::now().timestamp()
        }
    }

    pub fn refresh_tokens(
        previous: AuthorizedSessionData,
        auth_tokens: AuthResponse
    ) -> Self {
        Self {
            access_token: auth_tokens.access_token,
            refresh_token: auth_tokens.refresh_token,
            created_at: Utc::now().timestamp(),
            ..previous
        }
    }

    pub fn is_access_token_valid(&self) -> bool {
        Utc::now().timestamp() as u64 > self.expires_at
    }

}
