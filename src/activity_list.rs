use askama_axum::Template;
use axum::response::{Html, IntoResponse};
use chrono::NaiveDate;

use crate::{app_error::AppError, strava_api::http_calls::{ActivityListPayload, StravaClient}};

struct Activity {
    date: String,
    name: String,
    mi: String,
    km: String,
    duration: String,
    avg_mi: String,
    avg_km: String,
    elevation_gain: String,
}

#[derive(Template)]
#[template(path = "activity_list.html")]
struct ActivityListTemplate {
    list: Vec<Activity>,
    total_time: String,
    total_km: String,
    total_mi: String,
}

impl ActivityListTemplate {
    pub fn new(payload: ActivityListPayload) -> Self {
        Self {
            list: vec!(),
            total_time: "".to_string(),
            total_km: "".to_string(),
            total_mi: "".to_string(),
        }
    }

}

pub async fn show_activity_list() -> impl IntoResponse {
    let user_timezone_offset_in_hours = 3;
    let start_date = NaiveDate::from_ymd_opt(2024, 4, 1).unwrap();
    let end_date = NaiveDate::from_ymd_opt(2024, 4, 7).unwrap();
    match StravaClient::list_athlete_activities(
        user_timezone_offset_in_hours,
        start_date,
        end_date
    ).await {
        Ok(list) => {
            let template = ActivityListTemplate::new(list);
            template.render()
                .unwrap_or_else(|_| {
                    "An error occurred while rendering the template.".to_owned()
                })
        },
        Err(e) => {
            tracing::debug!("Error fetching activities: {}", e);
            return "Error fetching the list of activities".to_owned();
        }
    }
}
