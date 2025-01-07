use axum::{extract::{Query, State}, response::{IntoResponse, Redirect}};
use axum::http::HeaderMap;
use oauth2::CsrfToken;
use serde::Deserialize;

use crate::{
    app_error::AppError, app_session::SessionId, app_state::AppState,
    cookie_manager::{get_session_id_cookie, remove_session_cookie, write_session_cookie},
    session_data::{AuthorizedSessionData, SessionData}
};

#[axum::debug_handler]
pub async fn redirect_to_strava_login_page(State(app_state): State<AppState>) -> impl IntoResponse {
    let (auth_url, csrf_state) = app_state.strava_client.get_auth_url();

    let session_id = SessionId::new();

    app_state.sessions.add(session_id.clone(), csrf_state);
    let headers = write_session_cookie(session_id);

    (headers, Redirect::to(auth_url.as_ref()))
}

#[axum::debug_handler]
pub async fn logout(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(session_id) = get_session_id_cookie(headers) {
        app_state.sessions.remove(session_id);
    }
    let headers = remove_session_cookie();

    (headers, Redirect::to("/"))
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[axum::debug_handler]
pub async fn handle_login_authorized(
    Query(query): Query<AuthRequest>,
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, AppError> {
    let request_csrf_state = CsrfToken::new(query.state);

    let session_id: SessionId;
    if let Some(s_id) = get_session_id_cookie(headers) {
        session_id = s_id;
    } else {
        return Err(AppError::new("There was no session id cookie"));
    }

    let session_data: SessionData;
    if let Some(data) = app_state.sessions.get(session_id.clone()) {
        session_data = data;
    } else {
        return Err(AppError::new(format!("No session data for session id {:?}", session_id)));
    }

    let not_yet_authorized_session_data = match session_data {
        SessionData::NotYetAuthorized(data) => data,
        SessionData::Authorized(_) => {
            return Err(AppError::new("Expected not authorized, but was authorized"));
        }
    };

    if !not_yet_authorized_session_data.csrf_token.match_csrf(request_csrf_state) {
        return Err(AppError::new("CSRF token mismatch"));
    }

    let auth_tokens = app_state.strava_client
        .fetch_token(query.code.clone())
        .await?;

    let authorized_session_data = AuthorizedSessionData::new(auth_tokens);
    app_state.sessions.update(session_id.clone(), authorized_session_data);

    Ok(Redirect::to("/"))
}
