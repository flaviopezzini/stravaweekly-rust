use askama_axum::Template;
use axum::response::{Html, IntoResponse};
use chrono::NaiveDate;

use crate::{app_error::AppError, strava_api::http_calls::{ActivityListResponse, ActivityResponse, StravaClient}};

#[derive(Template)]
#[template(path = "activity_list.html")]
struct ActivityListTemplate {
    list: Vec<ActivityResponse>,
    total_time_in_seconds: u32,
    total_distance_in_meters: u32,
}

const KILOMETER: u32 = 1000;
const MILE: u32 = 1609;
const MILLISECONDS_IN_A_SECOND: u32 = 1000;
const METER_TO_FEET_RATIO: f32 = 3.28084;

impl ActivityListTemplate {
    pub fn new(response: ActivityListResponse) -> Self {
        let mut total_time_in_seconds: u32 = 0;
        let mut total_distance_in_meters: u32 = 0;

        for activity in &response.list {
            total_time_in_seconds += activity.duration_in_seconds();
            total_distance_in_meters += activity.distance;
        }

        Self {
            list: response.list,
            total_time_in_seconds,
            total_distance_in_meters,
        }
    }

    fn total_time(&self) -> String {
        let total_seconds = self.total_time_in_seconds;

        let hours = total_seconds / 3600;
        let minutes = (total_seconds % 3600) / 60;
        let seconds = total_seconds % 60;
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }

    fn total_in_km(&self) -> f32 {
        self.total_distance_in_meters as f32 / KILOMETER as f32
    }

    fn total_in_mi(&self) -> f32 {
        self.total_distance_in_meters as f32 / MILE as f32
    }

}

pub async fn show_activity_list() -> String {
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
