use anyhow::{Context, Result};
use app_config::AppConfig;
use app_session::SessionId;
use app_state::AppState;
use auth_client::AuthClient;
use axum::{
    debug_handler,
    extract::{Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Router,
};
use http::StatusCode;
use oauth2::CsrfToken;
use serde::Deserialize;
use session_data::{AuthorizedSessionData, SessionData};

mod app_config;
mod app_session;
mod app_state;
mod auth_client;
mod domain;
mod session_data;

async fn is_authenticated(app_state: AppState, headers: HeaderMap) -> bool {
    let session_id: SessionId;
    if let Some(s_id) = get_session_id_cookie(headers) {
        session_id = s_id;
    } else {
        return false;
    }

    let session_data: SessionData;
    if let Some(data) = app_state.sessions.get(session_id.clone()) {
        session_data = data;
    } else {
        return false;
    }

    match session_data {
        SessionData::NotYetAuthorized(_) => return false,
        SessionData::Authorized(data) => {
            if data.is_access_token_valid() {
                return true;
            } else {
                if let Ok(new_tokens) = app_state.auth_client
                    .refresh_tokens(&app_state.app_config, data.refresh_token.to_string()).await {

                    let new_session_data =
                        AuthorizedSessionData::refresh_tokens(data.to_owned(), new_tokens);

                    app_state.sessions.update(session_id, new_session_data);
                    return true;
                }
            }
        },
    };
    false
}

async fn index(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if is_authenticated(app_state, headers).await {
        Html(format!(
            "Hey! You're logged in!\nClick <a href='/logout'>here</a> to log out",
        ))
    } else {
        Html("You're not logged in.\nClick <a href='/auth/strava'>here</a> to do so.".to_owned())
    }
}

#[debug_handler]
async fn strava_auth(State(app_state): State<AppState>) -> impl IntoResponse {
    let (auth_url, csrf_state) = app_state.auth_client.get_auth_url();
    app_state.sessions.add(csrf_state);
    Redirect::to(auth_url.as_ref())
}

fn get_session_id_cookie(headers: HeaderMap) -> Option<SessionId> {
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

async fn logout(
    State(app_state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if let Some(session_id) = get_session_id_cookie(headers) {
        app_state.sessions.remove(session_id);
    }

    let headers = remove_session_cookie();

    (headers, Redirect::to("/"))
}

fn write_session_cookie(value: SessionId) -> HeaderMap {
    let cookie = format!(
        "session={}; SameSite=Lax; Path=/; HttpOnly; Secure",
        value.to_string()
    );

    write_cookie(cookie)
}

fn remove_session_cookie() -> HeaderMap {
    let cookie = "session=; SameSite=Lax; Path=/; HttpOnly; Max-Age=0";
    write_cookie(cookie.to_string())
}

fn write_cookie(value: String) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, value.parse().unwrap());

    headers
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

#[debug_handler]
async fn login_authorized(
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

    let not_yet_authorized_session_data;
    match session_data {
        SessionData::NotYetAuthorized(data) => not_yet_authorized_session_data = data,
        SessionData::Authorized(_) => {
            return Err(AppError::new("Expected not authorized, but was authorized"));
        }
    }

    if !not_yet_authorized_session_data.csrf_token.match_csrf(request_csrf_state) {
        return Err(AppError::new("CSRF token mismatch"));
    }

    let auth_tokens = app_state.auth_client
        .fetch_token(query.code.clone())
        .await?;

    let authorized_session_data = AuthorizedSessionData::new(auth_tokens);
    app_state.sessions.update(session_id.clone(), authorized_session_data);
    let headers = write_session_cookie(session_id);

    Ok((headers, Redirect::to("/")))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app_config = AppConfig::new();

    let auth_client = AuthClient::new(app_config.clone()).expect("Error configuring Oauth2 Client");
    let app_state = AppState::new(app_config, auth_client);

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/strava", get(strava_auth))
        .route("/auth/authorized", get(login_authorized))
        .route("/logout", get(logout))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .expect("Failed to bind TcpListener");

    tracing::debug!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app)
        .await
        .expect("Unable to start Axum server");
}

#[derive(Debug)]
struct AppError(anyhow::Error);

impl AppError {
    fn new(message: impl Into<String>) -> Self {
        Self(anyhow::anyhow!(message.into()))
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.0);
        (StatusCode::INTERNAL_SERVER_ERROR, self.0.to_string()).into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
