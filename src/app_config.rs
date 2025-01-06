use std::env;

pub struct AppConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub auth_url: String,
    pub token_url: String,
}

impl AppConfig {
    pub fn new() -> Self {
        let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
        let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
        let redirect_url = env::var("REDIRECT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3000/auth/authorized".to_owned());

        let auth_url =
            env::var("AUTH_URL").unwrap_or_else(|_| "http://www.strava.com/oauth/authorize".to_owned());

        let token_url =
            env::var("TOKEN_URL").unwrap_or_else(|_| "https://www.strava.com/oauth/token".to_owned());

        Self {
            client_id,
            client_secret,
            redirect_url,
            auth_url,
            token_url,
        }
    }
}
