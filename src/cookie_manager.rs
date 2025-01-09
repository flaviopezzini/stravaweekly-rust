use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};

use crate::{
    app_state::AppState,
    secret_value::SecretValue,
    tokens::{MyJwtToken, MyRefreshToken}
};

pub async fn set_secure_cookie(
    cookies: CookieJar,
    name: String,
    value: &[u8]) -> Result<CookieJar, anyhow::Error> {
    let value = String::from_utf8(value.into())?;

    let cookie = Cookie::build((name, value))
        .http_only(true)
        //.secure(true) TODO put back
        .same_site(SameSite::Strict)
        .build();

    Ok(cookies.add(cookie))
}

pub fn get_secure_cookie(cookies: CookieJar, name: &str) -> Option<Vec<u8>> {
    cookies.iter().for_each(|c|println!("Cookie name:{} value:{}", c.name(), c.value()));

    if let Some(cookie) = cookies.get(name) {
        Some(cookie.value().as_bytes().into())
    } else {
        None
    }
}

pub const CSRF_COOKIE: &str = "s890dsjnnasdf89dsfsdau8f90sdfjsdfj";
pub const JWT_COOKIE: &str = "sfd809sdf809saf809sdfads949sdoskase894jlksjf";
pub const REFRESH_COOKIE: &str = "d78wgfuoijdwsfjsdfjdslkfjsadlkfn0989sdfhsdf";

pub struct ValidJwtResult {
    pub jwt: SecretValue,
    pub cookies: CookieJar,
}

pub async fn get_valid_jwt_token(app_state: AppState, cookies: CookieJar) -> Option<ValidJwtResult> {
    let jwt_cookie = get_secure_cookie(
        cookies.clone(),
        JWT_COOKIE
    );
    if let Some(jwt_cookie_bytes) = jwt_cookie {
        match MyJwtToken::from_bytes(&jwt_cookie_bytes) {
            Ok(jwt_cookie) => {
                if jwt_cookie.is_valid() {
                    return Some(
                        ValidJwtResult {
                            jwt: SecretValue::new(jwt_cookie.value),
                            cookies: cookies.clone()
                        }
                    )
                } else {
                    return None;
                }
            },
            Err(err) => {
                tracing::debug!("Error converting jwt cookie from bytes to struct {}", err);
                return None;
            }
        }
    } else {
        let refresh_cookie = get_secure_cookie(
            cookies.clone(),
            REFRESH_COOKIE
        );
        if let Some(refresh_cookie_bytes) = refresh_cookie {
            match MyRefreshToken::from_bytes(&refresh_cookie_bytes) {
                Ok(refresh_token) => {
                    if let Ok(new_tokens) = app_state.strava_client
                            .refresh_tokens(&app_state.app_config, refresh_token).await {
                        let with_jwt_added = match set_secure_cookie(
                            cookies.clone(),
                            JWT_COOKIE.into(),
                            new_tokens.access_token.as_bytes()
                        ).await {
                            Ok(value) => value,
                            Err(e) => {
                                tracing::debug!("Error adding JWT cookie: {}", e);
                                return None;
                            }
                        };
                        let with_refresh_added = match set_secure_cookie(
                            with_jwt_added,
                            REFRESH_COOKIE.into(),
                            new_tokens.refresh_token.as_bytes()
                        ).await {
                            Ok(value) => value,
                            Err(e) => {
                                tracing::debug!("Error adding Refresh cookie: {}", e);
                                return None;
                            }
                        };

                        return Some(
                            ValidJwtResult {
                                jwt: SecretValue::new(new_tokens.access_token),
                                cookies: with_refresh_added
                            }
                        );
                    } else {
                        return None;
                    }
                },
                Err(err) => {
                    tracing::debug!("Error converting refresh cookie from bytes to struct {}", err);
                    return None;
                }
            }
        } else {
            return None;
        }
    }
}
