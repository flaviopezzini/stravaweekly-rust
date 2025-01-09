use axum::{
    extract::{Query, State},
    response::IntoResponse, Json,
    http::StatusCode
};
use axum_extra::extract::cookie::CookieJar;
use chrono::NaiveDateTime;
use serde::Deserialize;

use crate::{
    app_state::AppState,
    cookie_manager::get_valid_jwt_token,
    strava_api::http_calls::StravaClient
};

#[derive(Deserialize)]
pub struct ListAthleteActivitiesParams {
    user_timezone_offset_in_hours: i32,
    start_date: NaiveDateTime,
    end_date: NaiveDateTime,
}

pub async fn list_athlete_activities(
    State(app_state): State<AppState>,
    cookies: CookieJar,
    Query(params): Query<ListAthleteActivitiesParams>,
) -> impl IntoResponse {
    if let Some(jwt_result) = get_valid_jwt_token(app_state, cookies).await {
        match StravaClient::list_athlete_activities(
            jwt_result.jwt,
            params.user_timezone_offset_in_hours,
            params.start_date,
            params.end_date
        ).await {
            Ok(json_payload) => {
                (jwt_result.cookies, Json(json_payload).into_response()).into_response()
            },
            Err(e) => {
                tracing::debug!("Error fetching activities: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }

    } else {
        StatusCode::UNAUTHORIZED.into_response()
    }
}
