use chrono::Utc;
use oauth2::CsrfToken;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct MyCsrfToken(pub CsrfToken);
impl MyCsrfToken {
    pub fn match_csrf(&self, request_csrf_state: CsrfToken) -> bool {
        self.0.secret() == request_csrf_state.secret()
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

}

#[derive(Clone, Serialize, Deserialize)]
pub struct MyJwtToken {
    pub value: String,
    expires_at: u64,
}
impl MyJwtToken {
    pub fn new(value: String, expires_at: u64) -> Self {
        Self {
            value,
            expires_at,
        }
    }

    pub fn is_valid(&self) -> bool {
        Utc::now().timestamp() as u64 > self.expires_at
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MyRefreshToken{
    pub value: String
}
impl MyRefreshToken {
    pub fn new(value: String) -> Self {
        Self {
            value
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

}
