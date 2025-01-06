use oauth2::{AccessToken, RefreshToken};
use serde::{Deserialize, Serialize};

// The user data we'll get back from Strava
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StravaUser {
    pub id: i32,
    pub username: String,
}

impl StravaUser {
    pub fn new(id: i32, username: String) -> Self {
        Self {
            id,
            username,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct AuthTokens {
    pub access: AccessToken,
    pub refresh: Option<RefreshToken>,
}

impl AuthTokens {
    pub fn new(access: AccessToken, refresh: Option<RefreshToken>) -> Self {
        Self {
            access,
            refresh,
        }
    }
}
