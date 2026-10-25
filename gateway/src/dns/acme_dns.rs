//! acme-dns: challenge names are CNAMEs to an account on an acme-dns server,
//! so the main DNS zone's credentials never live on the gateway.
use super::{ChallengeRecord, Propagation, Settings};
use reqwest::Client;
use serde_json::json;
use std::time::Duration;

pub struct AcmeDns {
    pub settings: Settings,
    client: Client,
}

impl AcmeDns {
    pub fn new(settings: Settings) -> Result<Self, String> {
        let server = url::Url::parse(settings.get("server")).map_err(|_| {
            "Enter the acme-dns server as a URL, for example https://auth.example.net."
        })?;
        if !["https", "http"].contains(&server.scheme())
            || server.host_str().is_none()
            || !server.username().is_empty()
            || server.query().is_some()
        {
            return Err(
                "Enter the acme-dns server as an http:// or https:// URL without credentials."
                    .into(),
            );
        }
        if !settings
            .get("subdomain")
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || settings.get("subdomain").len() > 63
        {
            return Err(
                "Enter the acme-dns subdomain from the registration response, without a domain."
                    .into(),
            );
        }
        Ok(Self {
            client: Client::builder()
                .timeout(Duration::from_secs(20))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| "Could not initialize DNS client.")?,
            settings,
        })
    }
    pub fn zone(&self) -> String {
        self.settings.get("subdomain").to_ascii_lowercase()
    }
    pub async fn check_delegation(
        &self,
        record: &ChallengeRecord,
        propagation: &Propagation,
    ) -> Result<(), String> {
        let target = propagation.cname(&record.name).await?;
        if target.is_some_and(|target| target.starts_with(&format!("{}.", self.zone()))) {
            return Ok(());
        }
        Err(format!(
            "{} is not delegated to acme-dns. Add a CNAME record pointing it to {}.<your acme-dns domain>, wait for it to appear in public DNS, and retry.",
            record.name,
            self.zone()
        ))
    }
    pub async fn present(&self, record: &ChallengeRecord) -> Result<(), String> {
        let response = self
            .client
            .post(format!(
                "{}/update",
                self.settings.get("server").trim_end_matches('/')
            ))
            .header("X-Api-User", self.settings.get("username"))
            .header("X-Api-Key", self.settings.get("password"))
            .json(&json!({"subdomain":self.zone(),"txt":record.value}))
            .send()
            .await
            .map_err(|_| "Could not reach the acme-dns server.".to_owned())?;
        if !response.status().is_success() {
            return Err(format!(
                "The acme-dns server rejected the update (HTTP {}). Check the username, password, and subdomain.",
                response.status().as_u16()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        extract::State,
        http::HeaderMap,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::Value;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn updates_the_account_and_requires_the_cname() {
        let seen = Arc::new(Mutex::new(Vec::<Value>::new()));
        let app = Router::new()
            .route(
                "/update",
                post(
                    |State(seen): State<Arc<Mutex<Vec<Value>>>>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        if headers["x-api-user"] != "user" || headers["x-api-key"] != "pass" {
                            return axum::http::StatusCode::UNAUTHORIZED;
                        }
                        seen.lock().unwrap().push(body);
                        axum::http::StatusCode::OK
                    },
                ),
            )
            .route(
                "/dns-query",
                get(|uri: axum::http::Uri| async move {
                    let delegated = uri.query().unwrap_or("").contains("good.example");
                    Json(if delegated {
                        json!({"Status":0,"Answer":[{"type":5,"data":"abc-123.auth.example.net."}]})
                    } else {
                        json!({"Status":0,"Answer":[]})
                    })
                }),
            )
            .with_state(seen.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut settings = Settings {
            provider: "acme-dns".into(),
            credentials: [
                ("server", base.as_str()),
                ("username", "user"),
                ("password", "pass"),
                ("subdomain", "abc-123"),
            ]
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        };
        let provider = super::super::Provider::new(&mut settings, None).unwrap();
        let propagation = Propagation::new(format!("{base}/dns-query")).unwrap();
        let record = ChallengeRecord {
            zone: provider.zone_for("good.example").await.unwrap(),
            name: "_acme-challenge.good.example".into(),
            value: "challenge-value".into(),
            comment: String::new(),
        };
        provider
            .check_delegation(&record, &propagation)
            .await
            .unwrap();
        let missing = ChallengeRecord {
            name: "_acme-challenge.bad.example".into(),
            ..record.clone()
        };
        assert!(provider
            .check_delegation(&missing, &propagation)
            .await
            .unwrap_err()
            .contains("CNAME"));
        provider.present(&record).await.unwrap();
        assert_eq!(
            seen.lock().unwrap()[0],
            json!({"subdomain":"abc-123","txt":"challenge-value"})
        );
        provider.cleanup(&record).await.unwrap();
        assert_eq!(provider.name_limit(), 2);

        settings
            .credentials
            .insert("password".into(), "wrong".into());
        let wrong = super::super::Provider::new(&mut settings, None).unwrap();
        assert!(!wrong.present(&record).await.unwrap_err().contains("wrong"));
        settings
            .credentials
            .insert("server".into(), "ftp://auth.example.net".into());
        assert!(super::super::Provider::new(&mut settings, None).is_err());
    }
}
