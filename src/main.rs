use anyhow::{Context, Result};
use async_session::{MemoryStore, Session, SessionStore};
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    http::{header::SET_COOKIE, HeaderMap},
    response::{Html, IntoResponse, Redirect, Response},
    routing::get,
    debug_handler,
    RequestPartsExt, Router,
};
use axum_extra::{headers, typed_header::TypedHeaderRejectionReason, TypedHeader};

use http::{header, request::Parts, StatusCode};
use oauth2::{
    basic::BasicClient, reqwest::async_http_client, AccessToken, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, RedirectUrl, RefreshToken, Scope, TokenResponse, TokenUrl
};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc};
use tokio::{runtime::Handle, sync::Mutex};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

static COOKIE_NAME: &str = "SESSION";

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rust_strava_weekly=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // `MemoryStore` is just used as an example. Don't use this in production.
    let store = MemoryStore::new();
    let oauth_client = oauth_client().unwrap();

    let app_state = AppState::new(store, oauth_client);

    let app = Router::new()
        .route("/", get(index))
        .route("/auth/strava", get(strava_auth))
        .route("/auth/authorized", get(login_authorized))
        .route("/logout", get(logout))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .context("failed to bind TcpListener")
        .unwrap();

    tracing::debug!(
        "listening on {}",
        listener
            .local_addr()
            .context("failed to return local address")
            .unwrap()
    );

    axum::serve(listener, app).await.unwrap();
}

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<AppStateInner>>,
}
struct AppStateInner {
    store: MemoryStore,
    oauth_client: BasicClient,
    csrf_state: Option<CsrfToken>,
}

impl AppState {
    fn new(store: MemoryStore, oauth_client: BasicClient) -> Self {
        Self {
            inner: Arc::new(
                Mutex::new(
                    AppStateInner {
                        store,
                        oauth_client,
                        csrf_state: None,
                    }
                )
            )
        }
    }

    // fn get_store(&self) -> MemoryStore {
    //     // Try to get the store from the cache, or initialize it if not already set
    //     self.store_cache
    //         .get_or_init(|| {
    //             // Access `clone_store` synchronously by awaiting it in a `tokio::runtime::Handle`
    //             let store = tokio::runtime::Handle::current()
    //                 .block_on(self.clone_store());
    //             store
    //         })
    //         .clone() // Return a clone of the cached store
    // }

    async fn clone_store(&self) -> MemoryStore {
        let lock = self.inner.lock().await;
        lock.store.clone()
    }

    async fn clone_client(&self) -> BasicClient {
        let lock = self.inner.lock().await;
        lock.oauth_client.clone()
    }

    async fn set_csrf_state(&mut self, new_csrf_state: CsrfToken) {
        let mut lock = self.inner.lock().await;
        lock.csrf_state = Some(new_csrf_state);
    }

    async fn get_auth_url(&self) -> (Url, CsrfToken) {
        let lock = self.inner.lock().await;
        let (auth_url, csrf_state) = lock.oauth_client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new(
                "activity:read_all".to_string(),
            ))
            .url();
        (auth_url, csrf_state)
    }

    async fn match_csrf(&self, request_csrf_state: CsrfToken) -> bool {
        let lock = self.inner.lock().await;
        if let Some(v) = lock.csrf_state.as_ref() {
            request_csrf_state.secret() == v.secret()
        } else {
            false
        }
    }

    async fn fetch_token(
        &self,
        code: String,
        client_id: String,
        client_secret: String) -> Result<AuthTokens, anyhow::Error> {
        let lock = self.inner.lock().await;
        let token_response = lock.oauth_client
            .exchange_code(AuthorizationCode::new(code))
            .add_extra_param("client_id", client_id)
            .add_extra_param("client_secret", client_secret)
            .request_async(async_http_client)
            .await
            .context("failed in sending request request to authorization server")?;

        Ok(AuthTokens {
            access: token_response.access_token().clone(),
            refresh: token_response.refresh_token().map(|t| t.clone()),
        })
    }

    async fn store_session(&self, session: Session) -> Result<String, anyhow::Error> {
        let lock = self.inner.lock().await;
        let val: String = lock.store
            .store_session(session)
            .await
            .context("failed to store session")?
            .context("unexpected error retrieving cookie value")?;

        Ok(val)
    }

}

impl FromRef<AppState> for MemoryStore {
    fn from_ref(state: &AppState) -> Self {
        Handle::current().block_on(state.clone_store())
    }
}

impl FromRef<AppState> for BasicClient {
    fn from_ref(state: &AppState) -> Self {
        Handle::current().block_on(state.clone_client())
    }
}

fn oauth_client() -> Result<BasicClient, AppError> {
    // Environment variables (* = required):
    // *"CLIENT_ID"     "REPLACE_ME";
    // *"CLIENT_SECRET" "REPLACE_ME";
    //  "REDIRECT_URL"  "http://127.0.0.1:3000/auth/authorized";

    let client_id = env::var("CLIENT_ID").context("Missing CLIENT_ID!")?;
    let client_secret = env::var("CLIENT_SECRET").context("Missing CLIENT_SECRET!")?;
    let redirect_url = env::var("REDIRECT_URL")
        .unwrap_or_else(|_| "http://127.0.0.1:3000/auth/authorized".to_string());

    let auth_url = env::var("AUTH_URL").unwrap_or_else(|_| {
        "http://www.strava.com/oauth/authorize".to_string()
    });

    let token_url = env::var("TOKEN_URL")
        .unwrap_or_else(|_| "https://www.strava.com/oauth/token".to_string());

    Ok(BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        AuthUrl::new(auth_url).context("failed to create new authorization server URL")?,
        Some(TokenUrl::new(token_url).context("failed to create new token endpoint URL")?),
    )
    .set_redirect_uri(
        RedirectUrl::new(redirect_url).context("failed to create new redirection URL")?,
    ))
}

// The user data we'll get back from Strava.
// https://developers.strava.com/docs/reference/#api-Athletes-getLoggedInAthlete
#[derive(Debug, Serialize, Deserialize)]
struct User {
    id: i32,
    username: String,
}

// Session is optional
async fn index(user: Option<User>) -> impl IntoResponse {
    match user {
        Some(_) => Html(
            "Hey! You're logged in!\nClick <a href='/logout'>here</a> to log out"
        ),
        None => Html("You're not logged in.\n Click <a href='/auth/strava'>here</a> to do so."),
    }
}

#[debug_handler]
async fn strava_auth(State(mut app_state): State<AppState>) -> impl IntoResponse {
    let (auth_url, csrf_state) = app_state.get_auth_url().await;

    app_state.set_csrf_state(csrf_state).await;

    // Redirect to Strava's oauth service
    Redirect::to(auth_url.as_ref())
}

async fn logout(
    State(store): State<MemoryStore>,
    TypedHeader(cookies): TypedHeader<headers::Cookie>,
) -> Result<impl IntoResponse, AppError> {
    let cookie = cookies
        .get(COOKIE_NAME)
        .context("unexpected error getting cookie name")?;

    let session = match store
        .load_session(cookie.to_string())
        .await
        .context("failed to load session")?
    {
        Some(s) => s,
        // No session active, just redirect
        None => return Ok(Redirect::to("/")),
    };

    store
        .destroy_session(session)
        .await
        .context("failed to destroy session")?;

    Ok(Redirect::to("/"))
}

#[derive(Debug, Deserialize)]
struct AuthRequest {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize)]
struct AuthTokens {
    access: AccessToken,
    refresh: Option<RefreshToken>,
}

#[debug_handler]
async fn login_authorized(
    Query(query): Query<AuthRequest>,
    State(app_state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
    // Get an auth token
    let client_id = env::var("CLIENT_ID").context("Missing CLIENT_ID!")?;
    let client_secret = env::var("CLIENT_SECRET").context("Missing CLIENT_SECRET!")?;

    let request_csrf_state = CsrfToken::new(query.state.to_string());

    if !app_state.match_csrf(request_csrf_state).await {
        tracing::warn!("CSRF token mismatch");
        panic!("CSRF token mismatch");
    }

    let auth_tokens = app_state.fetch_token(query.code.clone(), client_id, client_secret).await?;

    // Fetch user data from Strava
    let client = reqwest::Client::new();
    let user_data: User = client
        .get("https://www.strava.com/api/v3/athlete")
        .bearer_auth(auth_tokens.access.secret())
        .send()
        .await
        .context("failed in sending request to target Url")?
        .json::<User>()
        .await
        .context("failed to deserialize response as JSON")?;

    // Create a new session filled with user data
    let mut session = Session::new();
    session
        .insert("user", &user_data)
        .context("failed in inserting serialized value into session")?;

    // Store session and get corresponding cookie
    let cookie = app_state.store_session(session).await?;

    // Build the cookie
    let cookie = format!("{COOKIE_NAME}={cookie}; SameSite=Lax; Path=/");

    // Set cookie
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        cookie.parse().context("failed to parse cookie")?,
    );

    Ok((headers, Redirect::to("/")))
}

struct AuthRedirect;

impl IntoResponse for AuthRedirect {
    fn into_response(self) -> Response {
        Redirect::temporary("/auth/strava").into_response()
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for User
where
    MemoryStore: FromRef<S>,
    S: Send + Sync,
{
    // If anything goes wrong or no session is found, redirect to the auth page
    type Rejection = AuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let store = MemoryStore::from_ref(state);

        let cookies = parts
            .extract::<TypedHeader<headers::Cookie>>()
            .await
            .map_err(|e| match *e.name() {
                header::COOKIE => match e.reason() {
                    TypedHeaderRejectionReason::Missing => AuthRedirect,
                    _ => panic!("unexpected error getting Cookie header(s): {e}"),
                },
                _ => panic!("unexpected error getting cookies: {e}"),
            })?;
        let session_cookie = cookies.get(COOKIE_NAME).ok_or(AuthRedirect)?;

        let session = store
            .load_session(session_cookie.to_string())
            .await
            .unwrap()
            .ok_or(AuthRedirect)?;

        let user = session.get::<User>("user").ok_or(AuthRedirect)?;

        Ok(user)
    }
}

// Use anyhow, define error and enable '?'
// For a simplified example of using anyhow in axum check /examples/anyhow-error-response
#[derive(Debug)]
struct AppError(anyhow::Error);

// Tell axum how to convert `AppError` into a response.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        tracing::error!("Application error: {:#}", self.0);

        (StatusCode::INTERNAL_SERVER_ERROR, "Something went wrong").into_response()
    }
}

// This enables using `?` on functions that return `Result<_, anyhow::Error>` to turn them into
// `Result<_, AppError>`. That way you don't need to do that manually.
impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}
