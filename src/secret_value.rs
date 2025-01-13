use secrecy::{ExposeSecret, SecretBox};

pub struct SecretValue {
    value: SecretBox<String>,
}

impl SecretValue {
    pub fn new(value: String) -> Self {
        Self {
            value: SecretBox::new(Box::new(value)),
        }
    }

    pub fn expose_secret(&self) -> String {
        self.value.expose_secret().into()
    }
}

impl Clone for SecretValue {
    fn clone(&self) -> Self {
        Self {
            value: SecretBox::new(Box::new(self.value.expose_secret().into())),
        }
    }
}
