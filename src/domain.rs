use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
}
