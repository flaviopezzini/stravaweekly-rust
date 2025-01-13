use std::env;

use crate::secret_value::SecretValue;

#[derive(Clone)]
pub struct AppConfig {
    pub client_id: SecretValue,
    pub client_secret: SecretValue,
    pub redirect_url: String,
}

impl AppConfig {
    pub fn new() -> Self {
        let client_id = env::var("CLIENT_ID").expect("Missing CLIENT_ID!");
        let client_secret = env::var("CLIENT_SECRET").expect("Missing CLIENT_SECRET!");

        let redirect_url = env::var("REDIRECT_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3000/auth/authorized".to_owned());

        Self {
            client_id: SecretValue::new(client_id),
            client_secret: SecretValue::new(client_secret),
            redirect_url,
        }
    }
}
