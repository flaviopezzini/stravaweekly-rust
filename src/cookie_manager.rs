use axum::http::{header::SET_COOKIE, HeaderMap};

use crate::app_session::SessionId;

pub fn write_session_cookie(value: SessionId) -> HeaderMap {
    let cookie = format!(
        "session={}; SameSite=Lax; Path=/; HttpOnly; Secure",
        value
    );

    write_cookie(cookie)
}

pub fn remove_session_cookie() -> HeaderMap {
    let cookie = "session=; SameSite=Lax; Path=/; HttpOnly; Max-Age=0";
    write_cookie(cookie.to_string())
}

fn write_cookie(value: String) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, value.parse().unwrap());

    headers
}

pub fn get_session_id_cookie(headers: HeaderMap) -> Option<SessionId> {
    if let Some(cookie) = headers.get(http::header::COOKIE) {
        if let Ok(cookie_str) = cookie.to_str() {
            if let Some(session_cookie) = cookie_str
                .split(';')
                .find(|s| s.trim().starts_with("session="))
            {
                let session_id = &session_cookie.trim()["session=".len()..];
                if let Ok(session_id) = SessionId::try_from(session_id.to_string()) {
                    return Some(session_id);
                } else {
                    tracing::debug!("Error deserializing the session id cookie");
                }
            }
        }
    }

    None
}
