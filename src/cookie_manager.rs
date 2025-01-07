use axum::http::{header::SET_COOKIE, HeaderMap};

use crate::{app_session::SessionId, app_state::AppState, session_data::{AuthorizedSessionData, SessionData}};

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

pub async fn is_authenticated(app_state: AppState, headers: HeaderMap) -> bool {
    let session_id: SessionId;
    if let Some(s_id) = get_session_id_cookie(headers) {
        session_id = s_id;
    } else {
        tracing::debug!("No session ID cookie");
        return false;
    }

    let session_data: SessionData;
    if let Some(data) = app_state.sessions.get(session_id.clone()) {
        session_data = data;
    } else {
        tracing::debug!("No session data stored");
        return false;
    }

    match session_data {
        SessionData::NotYetAuthorized(_) => return false,
        SessionData::Authorized(data) => {
            if data.access_token.is_valid() {
                return true;
            } else if let Ok(new_tokens) = app_state.strava_client
                    .refresh_tokens(&app_state.app_config, data.refresh_token).await {

                    let new_session_data =
                        AuthorizedSessionData::refresh_tokens(new_tokens);

                    app_state.sessions.update(session_id, new_session_data);
                    return true;
            }
        },
    };
    false
}
