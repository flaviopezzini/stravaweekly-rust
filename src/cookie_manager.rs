use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::prelude::*;
use serde::Serialize;

use crate::{
    app_state::AppState,
    domain::AuthResponse,
    secret_value::SecretValue,
    tokens::{MyAccessToken, MyRefreshToken},
};

pub async fn set_lax_cookie(cookies: CookieJar, name: String, value: String) -> CookieJar {
    set_cookie(cookies, name, value, SameSite::Lax).await
}
pub async fn set_strict_cookie(cookies: CookieJar, name: String, value: String) -> CookieJar {
    set_cookie(cookies, name, value, SameSite::Strict).await
}
async fn set_cookie(cookies: CookieJar, name: String, value: String, same_site: SameSite) -> CookieJar {
    let cookie = Cookie::build((name, value))
        .http_only(true)
        //.secure(true) TODO put back
        .same_site(same_site)
        .path("/")
        .build();

    cookies.add(cookie)
}

pub fn get_secure_cookie(cookies: CookieJar, name: &str) -> Option<String> {
    cookies.get(name).map(|cookie| cookie.value().into())
}

pub fn encode_cookie<T: Serialize>(value: T) -> Result<String, anyhow::Error> {
    let value = serde_json::to_string(&value)?;
    Ok(BASE64_STANDARD.encode(value))
}

pub fn decode_cookie<T: serde::de::DeserializeOwned>(value: &str) -> Result<T, anyhow::Error> {
    let decoded = BASE64_STANDARD.decode(value.as_bytes())?;
    Ok(serde_json::from_slice(&decoded).unwrap())
}

pub async fn set_auth_cookies(
    cookies: CookieJar,
    auth_response: AuthResponse,
) -> Result<CookieJar, anyhow::Error> {
    let access_token = MyAccessToken::new(auth_response.access_token, auth_response.expires_at);
    let access_token = encode_cookie(access_token)?;
    let with_access_token =
        set_strict_cookie(cookies, MyAccessToken::cookie_name().into(), access_token).await;

    let my_refresh_token = MyRefreshToken::new(auth_response.refresh_token);
    let refresh_token_value = encode_cookie(my_refresh_token)?;
    let with_refresh_token = set_strict_cookie(
        with_access_token,
        MyRefreshToken::cookie_name().into(),
        refresh_token_value,
    )
    .await;

    Ok(with_refresh_token)
}

pub struct FetchAccessTokenResult {
    pub access_token: SecretValue,
    pub cookies: CookieJar,
}

pub async fn get_valid_access_token(
    app_state: AppState,
    cookies: CookieJar,
) -> Option<FetchAccessTokenResult> {
    let access_token = fetch_from_access_token(cookies.clone());

    if let Some(access_token) = access_token {
        return Some(FetchAccessTokenResult {
            access_token: SecretValue::new(access_token),
            cookies,
        });
    } else {
        let refresh_result = fetch_from_refreshing_tokens(app_state, cookies).await;
        if let Some(refresh_result) = refresh_result {
            return Some(refresh_result);
        }
    }

    None
}

fn fetch_from_access_token(cookies: CookieJar) -> Option<String> {
    let access_cookie = get_secure_cookie(cookies.clone(), MyAccessToken::cookie_name());
    if let Some(access_cookie) = access_cookie {
        match decode_cookie::<MyAccessToken>(&access_cookie) {
            Ok(access_token) => {
                if access_token.is_valid() {
                    return Some(access_token.value);
                }
            }
            Err(err) => {
                tracing::debug!("Error encoding access token from cookie {}", err);
            }
        }
    }

    None
}

async fn fetch_from_refreshing_tokens(
    app_state: AppState,
    cookies: CookieJar,
) -> Option<FetchAccessTokenResult> {
    let refresh_cookie = get_secure_cookie(cookies.clone(), MyRefreshToken::cookie_name());
    if let Some(refresh_cookie) = refresh_cookie {
        match decode_cookie::<MyRefreshToken>(&refresh_cookie) {
            Ok(refresh_token) => {
                if let Ok(auth_response) = app_state
                    .strava_client
                    .refresh_tokens(&app_state.app_config, refresh_token)
                    .await
                {
                    match set_auth_cookies(cookies, auth_response.clone()).await {
                        Ok(updated_cookies) => {
                            return Some(FetchAccessTokenResult {
                                access_token: SecretValue::new(auth_response.access_token),
                                cookies: updated_cookies,
                            });
                        }
                        Err(e) => {
                            tracing::debug!("Error setting the auth tokens: {}", e);
                        }
                    };
                }
            }
            Err(err) => {
                tracing::debug!("Error decoding refresh token from cookie {}", err);
            }
        }
    }

    None
}
