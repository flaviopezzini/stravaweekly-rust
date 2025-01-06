use std::env;

use secrecy::{ExposeSecret, SecretBox};

pub struct AppConfig {
    pub client_id: String,
    client_secret: SecretBox<String>,
    pub redirect_url: String,
    pub auth_url: String,
    pub token_url: String,
}

impl Clone for AppConfig {
    fn clone(&self) -> Self {
        Self {
            client_id: self.client_id.clone(),
            redirect_url: self.redirect_url.clone(),
            auth_url: self.auth_url.clone(),
            token_url: self.token_url.clone(),
            client_secret: SecretBox::new(Box::new(self.client_secret.expose_secret().into())),
        }
    }
}

impl AppConfig {
    pub fn new() -> Self {
        let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
        let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");
        let client_secret = SecretBox::new(Box::new(client_secret));

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

    pub fn get_secret(&self) -> String {
        self.client_secret.expose_secret().into()
    }
}
