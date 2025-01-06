use chrono::Utc;
use oauth2::{AccessToken, RefreshToken};

use crate::domain::StravaUser;

// Session data we store server-side
#[derive(Clone, Debug)]
pub struct SessionData {
    pub user: StravaUser,
    pub access_token: AccessToken,
    pub refresh_token: Option<RefreshToken>,
    created_at: i64,
}

impl SessionData {
    pub fn new(access_token: AccessToken, refresh_token: Option<RefreshToken>, user: StravaUser) -> Self {
        SessionData {
            user,
            access_token,
            refresh_token,
            created_at: Utc::now().timestamp()
        }
    }

    pub fn is_active(&self) -> bool {
        Utc::now().timestamp() - self.created_at < 3600
    }
}
