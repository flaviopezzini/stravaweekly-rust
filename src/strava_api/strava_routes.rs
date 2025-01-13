use axum::{
    extract::{Query, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::{cookie::Cookie, CookieJar};
use oauth2::CsrfToken;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    cookie_manager::{
        decode_cookie, encode_cookie, get_secure_cookie, set_auth_cookies, set_lax_cookie,
    },
    tokens::{MyAccessToken, MyCsrfToken, MyRefreshToken},
};

#[axum::debug_handler]
pub async fn redirect_to_strava_login_page(
    State(app_state): State<AppState>,
    cookies: CookieJar,
) -> impl IntoResponse {
    let (auth_url, csrf_state) = app_state.strava_client.get_auth_url();

    let csrf_state = MyCsrfToken(csrf_state);

    let cookie_value = match encode_cookie(csrf_state) {
        Ok(value) => value,
        Err(err) => {
            tracing::debug!("Error encoding the csrf token: {}", err);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let cookies = set_lax_cookie(cookies, MyCsrfToken::cookie_name().into(), cookie_value).await;

    (cookies, Redirect::to(auth_url.as_ref())).into_response()
}

#[axum::debug_handler]
pub async fn logout(cookies: CookieJar) -> impl IntoResponse {
    let updated_cookies = cookies.remove(Cookie::from(MyCsrfToken::cookie_name()));
    let updated_cookies = updated_cookies.remove(Cookie::from(MyAccessToken::cookie_name()));
    let updated_cookies = updated_cookies.remove(Cookie::from(MyRefreshToken::cookie_name()));

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

    let csrf_cookie = get_secure_cookie(cookies.clone(), MyCsrfToken::cookie_name());

    let csrf_token_cookie = if let Some(csrf_cookie) = csrf_cookie {
        match decode_cookie::<MyCsrfToken>(&csrf_cookie) {
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

    let auth_response = match app_state
        .strava_client
        .fetch_token(query.code.clone())
        .await
    {
        Ok(val) => val,
        Err(e) => {
            tracing::debug!("Error fetching the token: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let updated_cookies = match set_auth_cookies(cookies, auth_response).await {
        Ok(updated_cookies) => updated_cookies,
        Err(e) => {
            tracing::debug!("Error setting the auth tokens: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    (updated_cookies, Redirect::to("/")).into_response()
}
