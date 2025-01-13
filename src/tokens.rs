use chrono::Utc;
use oauth2::CsrfToken;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct MyCsrfToken(pub CsrfToken);
impl MyCsrfToken {
    pub fn match_csrf(&self, request_csrf_state: CsrfToken) -> bool {
        self.0.secret() == request_csrf_state.secret()
    }

    pub fn cookie_name() -> &'static str {
        "s890dsjnnasdf89dsfsdau8f90sdfjsdfj"
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
