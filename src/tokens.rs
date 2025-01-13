use chrono::Utc;
use serde::{Deserialize, Serialize};
use rand::{thread_rng, Rng};
use base64::{Engine as _, engine::general_purpose::URL_SAFE};

#[derive(Clone, Serialize, Deserialize)]
pub struct MyCsrfToken(String);
impl MyCsrfToken {
    pub fn match_csrf(&self, request_csrf_state: MyCsrfToken) -> bool {
        self.secret() == request_csrf_state.secret()
    }

    pub fn new_random() -> Self {
        // Generate 32 random bytes
        let mut rng = thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes);

        let token = URL_SAFE.encode(bytes);
        MyCsrfToken(token)
    }

    pub fn cookie_name() -> &'static str {
        "s890dsjnnasdf89dsfsdau8f90sdfjsdfj"
    }

    pub fn secret(&self) -> &str {
        &self.0
    }

    pub(crate) fn from_state(state: String) -> Self {
        Self(state)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MyAccessToken {
    pub value: String,
    expires_at: u64,
}
impl MyAccessToken {
    pub fn new(value: String, expires_at: u64) -> Self {
        Self { value, expires_at }
    }

    pub fn is_valid(&self) -> bool {
        Utc::now().timestamp() as u64 > self.expires_at
    }

    pub fn cookie_name() -> &'static str {
        "sfd809sdf809saf809sdfads949sdoskase894jlksjf"
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MyRefreshToken {
    pub value: String,
}
impl MyRefreshToken {
    pub fn new(value: String) -> Self {
        Self { value }
    }

    pub fn cookie_name() -> &'static str {
        "d78wgfuoijdwsfjsdfjdslkfjsadlkfn0989sdfhsdf"
    }
}
