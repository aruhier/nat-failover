use chrono::Utc;
use gethostname::gethostname;
use log::{debug, error};
use reqwest::Client;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;

#[derive(Default, Serialize, Debug)]
pub struct Alert {
    pub labels: HashMap<String, String>,

    pub annotations: HashMap<String, String>,

    #[serde(rename = "startsAt")]
    pub starts_at: Option<String>,

    #[serde(rename = "endsAt")]
    pub ends_at: Option<String>,
}

impl Alert {
    pub fn new() -> Self {
        let alertname = format!("NAT enabled on {:?}", gethostname());

        Self {
            labels: HashMap::from([("alertname".into(), alertname)]),
            annotations: HashMap::from([(
                "description".into(),
                "NAT enabled as fallback for routing problem".into(),
            )]),
            starts_at: None,
            ends_at: None,
        }
    }

    pub async fn trigger(&mut self, url: &str) {
        if self.starts_at.is_none() {
            self.starts_at = Some(Utc::now().to_rfc3339());
        }
        debug!("Sending alert.");
        post_alert(url, &self).await;
    }

    pub async fn resolve(&mut self, url: &str) {
        // Only resolve the alert if it was triggered.
        if self.starts_at.is_none() {
            return;
        }

        debug!("Resolving the alert.");
        self.ends_at = Some(Utc::now().to_rfc3339());
        post_alert(url, self).await;

        self.starts_at = None;
        self.ends_at = None;
    }
}

pub async fn post_alert(url: &str, alert: &Alert) {
    let alerts = vec![alert];
    debug!("Posting alerts {:?}", alerts);

    let res = match Client::new()
        .post(format!("{}/api/v1/alerts", url))
        .json(&alerts)
        .timeout(Duration::from_secs(10))
        .send()
        .await
    {
        Ok(res) => res,
        Err(err) => return error!("Error posting the alert: {}", err),
    };

    match res.error_for_status() {
        Ok(text) => debug!("Alertmanager response: {}", text.text().await.unwrap()),
        Err(err) => error!("Alertmanager returned an error: {}", err),
    }
}
