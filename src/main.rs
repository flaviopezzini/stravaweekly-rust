use anyhow::{Context, Result};
use app_config::AppConfig;
use auth_client::AuthClient;
use axum::{
    debug_handler,
    extract::{Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    Extension, Router,
};
use dashmap::DashMap;
use domain::{AuthTokens, StravaUser};
use http::StatusCode;
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, AuthUrl, AuthorizationCode,
    ClientId, ClientSecret, CsrfToken, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl,
};
use reqwest::{Client, Url};
use serde::Deserialize;
use session_data::SessionData;
use std::{env, sync::Arc, time::{SystemTime, UNIX_EPOCH}};
use tokio::sync::Mutex;
use uuid::Uuid;

mod app_config;
mod auth_client;
mod domain;
mod session_data;

#[derive(Clone)]
struct AppState {
    sessions: Arc<DashMap<String, SessionData>>,
    auth_client: AuthClient,
    inner: Arc<Mutex<AppStateInner>>,
}

struct AppStateInner {
    csrf_state: Option<CsrfToken>,
}

impl AppState {
    fn new(auth_client: AuthClient) -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
            auth_client,
            inner: Arc::new(Mutex::new(AppStateInner { csrf_state: None })),
        }
    }

    async fn set_csrf_state(&self, new_csrf_state: CsrfToken) {
        let mut lock = self.inner.lock().await;
        lock.csrf_state = Some(new_csrf_state);
    }

    async fn match_csrf(&self, request_csrf_state: CsrfToken) -> bool {
        let lock = self.inner.lock().await;
        lock.csrf_state
            .as_ref()
            .map_or(false, |v| request_csrf_state.secret() == v.secret())
    }
}

async fn is_authenticated(session: &Option<SessionData>) -> bool {
    if let Some(session_data) = session.as_ref() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        todo!("Pending token expiration check");
        if session_data.is_active() { // Example: if less than 1 hour has passed
            return true;
        }

        // If access token expired, try to use refresh token
        if let Some(refresh_token) = &session_data.refresh_token {
            if let Ok(new_tokens) = refresh_tokens(refresh_token).await {
                // Here you would need to update the session with new tokens
                return true;
            }
        }
    }
    false
}

async fn refresh_tokens(refresh_token: &RefreshToken) -> Result<AuthTokens, anyhow::Error> {
    let client = Client::new();

    let client_id = env::var("CLIENT_ID").context("Missing CLIENT_ID!")?;
    let client_secret = env::var("CLIENT_SECRET").context("Missing CLIENT_SECRET!")?;

    let token_response = client
        .post("https://www.strava.com/oauth/token")
        .form(&[
            ("client_id", &client_id),
            ("client_secret", &client_secret),
            ("grant_type", &"refresh_token".to_string()),
            ("refresh_token", refresh_token.secret()),
        ])
        .send()
        .await
        .context("Failed to send token refresh request")?
        .json::<AuthTokens>()
        .await
        .context("Failed to parse token refresh response")?;

    Ok(token_response)
}

async fn index(Extension(session): Extension<Option<SessionData>>) -> impl IntoResponse {
    if is_authenticated(&session).await {
        Html(format!(
            "Hey {}! You're logged in!\nClick <a href='/logout'>here</a> to log out",
            session.as_ref().unwrap().user.username
        ))
    } else {
        Html("You're not logged in.\nClick <a href='/auth/strava'>here</a> to do so.".to_owned())
    }
}

#[debug_handler]
async fn strava_auth(State(app_state): State<AppState>) -> impl IntoResponse {
    let (auth_url, csrf_state) = app_state.auth_client.get_auth_url();
    app_state.set_csrf_state(csrf_state).await;
    Redirect::to(auth_url.as_ref())
}

async fn logout(
    State(app_state): State<AppState>,
    Extension(_session): Extension<Option<SessionData>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Remove session from DashMap if it exists
    if let Some(cookie) = headers.get(http::header::COOKIE) {
        if let Ok(cookie_str) = cookie.to_str() {
            if let Some(session_cookie) = cookie_str
                .split(';')
                .find(|s| s.trim().starts_with("session="))
            {
                let session_id = &session_cookie.trim()["session=".len()..];
                app_state.sessions.remove(session_id);
            }
        }
    }

    // Clear the cookie
    let cookie = "session=; SameSite=Lax; Path=/; HttpOnly; Max-Age=0";
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    (headers, Redirect::to("/"))
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
) -> Result<impl IntoResponse, AppError> {
    let client_id = env::var("CLIENT_ID").context("Missing CLIENT_ID!")?;
    let client_secret = env::var("CLIENT_SECRET").context("Missing CLIENT_SECRET!")?;

    let request_csrf_state = CsrfToken::new(query.state);

    if !app_state.match_csrf(request_csrf_state).await {
        tracing::warn!("CSRF token mismatch");
        return Err(AppError::new("CSRF token mismatch"));
    }

    let auth_tokens = app_state.auth_client
        .fetch_token(query.code.clone(), client_id, client_secret)
        .await?;

    // Fetch user data from Strava
    let client = reqwest::Client::new();
    let user: StravaUser = client
        .get("https://www.strava.com/api/v3/athlete")
        .bearer_auth(auth_tokens.access.secret())
        .send()
        .await
        .context("failed in sending request to Strava API")?
        .json()
        .await
        .context("failed to deserialize response as JSON")?;

    // Generate a new session ID
    let session_id = Uuid::new_v4().to_string();

    // Store session data
    let session_data = SessionData::new(auth_tokens.access, auth_tokens.refresh, user);

    app_state.sessions.insert(session_id.clone(), session_data);

    // Set secure cookie with session ID
    let cookie = format!(
        "session={}; SameSite=Lax; Path=/; HttpOnly; Secure",
        session_id
    );
    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie.parse().unwrap());

    Ok((headers, Redirect::to("/")))
}

async fn session_middleware(
    State(app_state): State<AppState>,
    headers: HeaderMap,
    mut request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> Response {
    let session = headers
        .get(http::header::COOKIE)
        .and_then(|cookie| cookie.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str
                .split(';')
                .find(|s| s.trim().starts_with("session="))
        })
        .and_then(|session_cookie| {
            let session_id = &session_cookie.trim()["session=".len()..];
            app_state.sessions.get(session_id).map(|r| r.clone())
        });

    request.extensions_mut().insert(session);
    next.run(request).await
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app_config = AppConfig::new();

    let auth_client = AuthClient::new(app_config).expect("Error configuring Oauth2 Client");
    let app_state = AppState::new(auth_client);

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/strava", get(strava_auth))
        .route("/auth/authorized", get(login_authorized))
        .route("/logout", get(logout))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            session_middleware,
        ))
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
