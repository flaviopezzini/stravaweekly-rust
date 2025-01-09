use axum::{extract::{Query, State}, response::{IntoResponse, Redirect}};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use oauth2::CsrfToken;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    cookie_manager::{get_secure_cookie, set_secure_cookie, CSRF_COOKIE, JWT_COOKIE, REFRESH_COOKIE},
    tokens::{
        MyCsrfToken, MyJwtToken, MyRefreshToken
    }
};

#[axum::debug_handler]
pub async fn redirect_to_strava_login_page(
    State(app_state): State<AppState>,
    cookies: CookieJar,
) -> impl IntoResponse {
    let (auth_url, csrf_state) = app_state.strava_client.get_auth_url();

    let csrf_state = MyCsrfToken(csrf_state);

    let cookie_value = match csrf_state.to_bytes() {
        Ok(value) => value,
        Err(err) => {
            tracing::debug!("Error encoding the csrf token: {}", err);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    };

    let cookies = match set_secure_cookie(
        cookies,
        CSRF_COOKIE.into(),
        &cookie_value
    ).await {
        Ok(val) => val,
        Err(err) => {
            tracing::debug!("Error writing the csrf token: {}", err);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    };

    (cookies, Redirect::to(auth_url.as_ref())).into_response()
}

#[axum::debug_handler]
pub async fn logout(
    cookies: CookieJar,
) -> impl IntoResponse {
    let updated_cookies = cookies.remove(Cookie::from(CSRF_COOKIE));
    let updated_cookies = updated_cookies.remove(Cookie::from(JWT_COOKIE));
    let updated_cookies = updated_cookies.remove(Cookie::from(REFRESH_COOKIE));

    (updated_cookies, Redirect::to("/"))
}

#[derive(Debug, Deserialize)]
pub struct AuthRequest {
    code: String,
    state: String,
}

#[axum::debug_handler]
pub async fn handle_login_authorized(
    State(app_state): State<AppState>,
    cookies: CookieJar,
    Query(query): Query<AuthRequest>,
) -> impl IntoResponse {
    let request_csrf_state = CsrfToken::new(query.state);

    let csrf_cookie = get_secure_cookie(
        cookies.clone(),
        CSRF_COOKIE
    );

    let csrf_token_cookie = if let Some(cookie_bytes) = csrf_cookie {
        match MyCsrfToken::from_bytes(&cookie_bytes) {
            Ok(val) => val,
            Err(e) => {
                tracing::debug!("Error decoding the csrf token: {}", e);
                return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    } else {
        tracing::debug!("No csrf token");
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };

    if !csrf_token_cookie.match_csrf(request_csrf_state) {
        tracing::debug!("CSRF token mismatch");
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let auth_tokens = match app_state.strava_client
        .fetch_token(query.code.clone())
        .await {
            Ok(val) => val,
            Err(e) => {
                tracing::debug!("Error fetching the token: {}", e);
                return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
    };

    let my_jwt_token = MyJwtToken::new(auth_tokens.access_token, auth_tokens.expires_at);
    let jwt_token_value = match my_jwt_token.to_bytes() {
        Ok(val) => val,
        Err(e) => {
            tracing::debug!("Error enconding the JWT token: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let updated_cookies = match set_secure_cookie(
        cookies,
        JWT_COOKIE.into(),
        &jwt_token_value,
    ).await {
        Ok(val) => val,
        Err(e) => {
            tracing::debug!("Error storing JWT cookie: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let my_refresh_token = MyRefreshToken::new(auth_tokens.refresh_token);
    let refresh_token_value = match my_refresh_token.to_bytes() {
        Ok(val) => val,
        Err(e) => {
            tracing::debug!("Error enconding the Refresh token: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    let updated_cookies = match set_secure_cookie(
        updated_cookies,
        JWT_COOKIE.into(),
        &refresh_token_value,
    ).await {
        Ok(val) => val,
        Err(e) => {
            tracing::debug!("Error storing JWT cookie: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    (updated_cookies, Redirect::to("/")).into_response()
}
