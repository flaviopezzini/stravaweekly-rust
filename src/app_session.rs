use std::sync::Arc;
use std::convert::TryFrom;

use dashmap::DashMap;
use oauth2::CsrfToken;
use uuid::Uuid;

use crate::session_data::{AuthorizedSessionData, NotYetAuthorizedSessionData, SessionData};

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct SessionId(Uuid);
impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl TryFrom<String> for SessionId {
    type Error = uuid::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let uuid = Uuid::parse_str(&value)?;
        Ok(Self(uuid))
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone)]
pub struct AppSession {
    session_data: Arc<DashMap<SessionId, SessionData>>,
}

impl AppSession {
    pub fn new() -> Self {
        Self {
            session_data: Arc::new(DashMap::new()),
        }
    }

    pub fn add(&self, session_id: SessionId, csrf_token: CsrfToken) {
        let not_yet = NotYetAuthorizedSessionData::new(csrf_token);
        let session_data = SessionData::NotYetAuthorized(not_yet);
        self.session_data.insert(session_id.clone(), session_data);
    }

    pub fn get(&self, session_id: SessionId) -> Option<SessionData> {
        self.session_data.get(&session_id).map(|r| r.value().clone())
    }

    pub fn update(&self, session_id: SessionId, session_data: AuthorizedSessionData) {
        let session_data = SessionData::Authorized(session_data);
        self.session_data.insert(session_id.clone(), session_data);
    }

    pub fn remove(&self, session_id: SessionId) {
        self.session_data.remove(&session_id);
    }
}
