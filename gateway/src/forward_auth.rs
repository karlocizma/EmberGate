//! Per-route authorization delegated to a trusted HTTP service. Never fail open.
use pingora::{http::RequestHeader, Result};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, time::Duration};
use tokio::sync::Semaphore;
use url::Url;

pub const IDENTITY_HEADERS: &[&str] = &[
    "remote-user",
    "remote-name",
    "remote-email",
    "remote-groups",
    "x-auth-request-user",
    "x-auth-request-email",
    "x-auth-request-groups",
    "x-auth-request-preferred-username",
];
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardAuth {
    pub url: String,
    pub timeout_seconds: u64,
    pub sign_in_url: Option<String>,
    pub request_headers: Vec<String>,
    pub response_headers: Vec<String>,
}
impl Default for ForwardAuth {
    fn default() -> Self {
        Self {
            url: String::new(),
            timeout_seconds: 5,
            sign_in_url: None,
            request_headers: vec!["cookie".into(), "authorization".into()],
            response_headers: vec![
                "remote-user".into(),
                "remote-name".into(),
                "remote-email".into(),
                "remote-groups".into(),
            ],
        }
    }
}
fn destination(value: &str, query: bool) -> std::result::Result<Url, String> {
    let url =
        Url::parse(value).map_err(|_| "Enter an absolute HTTP or HTTPS authentication URL.")?;
    if value.len() > 2048
        || !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || (!query && url.query().is_some())
        || value.chars().any(char::is_control)
    {
        return Err("Authentication URLs cannot contain credentials, fragments, or control characters; check endpoints cannot have query strings.".into());
    }
    Ok(url)
}
fn reserved(name: &str) -> bool {
    matches!(
        name,
        "host"
            | "connection"
            | "content-length"
            | "content-type"
            | "transfer-encoding"
            | "te"
            | "trailer"
            | "upgrade"
            | "keep-alive"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "set-cookie"
            | "forwarded"
            | "x-original-url"
            | "x-forwarded-uri"
            | "x-forwarded-host"
            | "x-forwarded-method"
            | "x-forwarded-for"
            | "x-forwarded-proto"
            | "x-real-ip"
    )
}
impl ForwardAuth {
    pub fn validate(&mut self) -> std::result::Result<(), String> {
        self.url = destination(self.url.trim(), false)?.to_string();
        if !(1..=30).contains(&self.timeout_seconds) {
            return Err("Authentication timeout must be 1–30 seconds.".into());
        }
        if let Some(sign_in) = &self.sign_in_url {
            self.sign_in_url = Some(destination(sign_in.trim(), true)?.to_string());
        }
        for (names, response) in [
            (&mut self.request_headers, false),
            (&mut self.response_headers, true),
        ] {
            if names.len() > 16 {
                return Err("Use at most 16 authentication headers per list.".into());
            }
            let mut seen = HashSet::new();
            for name in names.iter_mut() {
                *name = name.trim().to_ascii_lowercase();
                if name.len() > 128
                    || HeaderName::from_bytes(name.as_bytes()).is_err()
                    || reserved(name)
                    || (response
                        && matches!(
                            name.as_str(),
                            "cookie"
                                | "authorization"
                                | "location"
                                | "www-authenticate"
                                | "cache-control"
                                | "content-encoding"
                        ))
                    || !seen.insert(name.clone())
                {
                    return Err("Use unique, non-reserved authentication header names.".into());
                }
            }
        }
        Ok(())
    }
}

pub enum Decision {
    Allow(Vec<(HeaderName, HeaderValue)>),
    Deny(u16, Option<String>),
    Unavailable,
}
fn original(request: &RequestHeader, https: bool) -> Option<String> {
    let authority = crate::cache::request_authority(request)?;
    let path = request.uri.path_and_query().map_or("/", |p| p.as_str());
    let value = format!(
        "{}://{}{}",
        if https { "https" } else { "http" },
        authority,
        path
    );
    let url = Url::parse(&value).ok()?;
    if !url.username().is_empty() || url.password().is_some() {
        return None;
    }
    Some(value)
}
fn login_location(policy: &ForwardAuth, original: &str) -> Option<String> {
    let mut url = Url::parse(policy.sign_in_url.as_deref()?).ok()?;
    let query: Vec<(String, String)> = url
        .query_pairs()
        .filter(|(key, _)| key != "rd")
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    url.set_query(None);
    url.query_pairs_mut()
        .extend_pairs(query)
        .append_pair("rd", original);
    Some(url.to_string())
}
pub async fn check(
    policy: &ForwardAuth,
    request: &RequestHeader,
    identity: &crate::policy::Identity,
    trust: &crate::trust::Trust,
) -> Decision {
    // Rebuilt only when the private CA bundle changes.
    static CLIENT: std::sync::Mutex<Option<(u64, reqwest::Client)>> = std::sync::Mutex::new(None);
    static CAPACITY: Semaphore = Semaphore::const_new(64);
    let Ok(_permit) = CAPACITY.try_acquire() else {
        return Decision::Unavailable;
    };
    let generation = trust.generation();
    let client = {
        let mut cached = CLIENT.lock().unwrap();
        match cached.as_ref().filter(|(built, _)| *built == generation) {
            Some((_, client)) => client.clone(),
            None => {
                let Ok(client) = trust
                    .reqwest(reqwest::Client::builder())
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_secs(3))
                    .pool_max_idle_per_host(8)
                    .build()
                else {
                    return Decision::Unavailable;
                };
                *cached = Some((generation, client.clone()));
                client
            }
        }
    };
    let Some(original) = original(request, identity.https) else {
        return Decision::Unavailable;
    };
    let Some(authority) = crate::cache::request_authority(request) else {
        return Decision::Unavailable;
    };
    let mut headers = HeaderMap::new();
    let mut bytes = 0;
    for name in &policy.request_headers {
        for value in request.headers.get_all(name).iter() {
            bytes += value.as_bytes().len();
            if bytes > 32768 {
                return Decision::Unavailable;
            }
            let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                return Decision::Unavailable;
            };
            headers.append(name, value.clone());
        }
    }
    for (name, value) in [
        ("x-original-url", original.clone()),
        ("x-forwarded-method", request.method.to_string()),
        ("x-forwarded-host", authority.to_string()),
        (
            "x-forwarded-proto",
            if identity.https {
                "https".into()
            } else {
                "http".into()
            },
        ),
        (
            "x-forwarded-uri",
            request
                .uri
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_string(),
        ),
    ] {
        let Ok(value) = HeaderValue::from_str(&value) else {
            return Decision::Unavailable;
        };
        headers.insert(HeaderName::from_static(name), value);
    }
    if let Some(ip) = identity.client {
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&ip.to_string()).unwrap(),
        );
    }
    let response = client
        .get(&policy.url)
        .headers(headers)
        .timeout(Duration::from_secs(policy.timeout_seconds))
        .send()
        .await;
    let Ok(response) = response else {
        return Decision::Unavailable;
    };
    if response.status().is_success() {
        let mut identity = Vec::new();
        let mut bytes = 0;
        for name in &policy.response_headers {
            for value in response.headers().get_all(name).iter() {
                bytes += value.as_bytes().len();
                if value.as_bytes().len() > 8192 || bytes > 32768 {
                    return Decision::Unavailable;
                }
                let Ok(name) = HeaderName::from_bytes(name.as_bytes()) else {
                    return Decision::Unavailable;
                };
                identity.push((name, value.clone()));
            }
        }
        Decision::Allow(identity)
    } else if response.status().as_u16() == 401 {
        let location = if matches!(request.method.as_str(), "GET" | "HEAD") {
            login_location(policy, &original)
        } else {
            None
        };
        Decision::Deny(if location.is_some() { 303 } else { 401 }, location)
    } else if response.status().as_u16() == 403 {
        Decision::Deny(403, None)
    } else {
        Decision::Unavailable
    }
}
pub fn apply(
    policy: &ForwardAuth,
    headers: &[(HeaderName, HeaderValue)],
    request: &mut RequestHeader,
) -> Result<()> {
    for name in IDENTITY_HEADERS
        .iter()
        .copied()
        .chain(policy.response_headers.iter().map(String::as_str))
    {
        request.remove_header(name);
    }
    for (name, value) in headers {
        request.append_header(name.clone(), value.clone())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn policies_reject_unsafe_urls_headers_and_timeouts() {
        let mut policy = ForwardAuth {
            url: "http://127.0.0.1:9000/check".into(),
            ..Default::default()
        };
        assert!(policy.validate().is_ok());
        for url in [
            "file:///secret",
            "http://user:password@host/check",
            "https://host/check?token=secret",
            "https://host/#fragment",
        ] {
            let mut bad = policy.clone();
            bad.url = url.into();
            assert!(bad.validate().is_err());
        }
        for name in [
            "Host",
            "Content-Length",
            "X-Forwarded-For",
            "Set-Cookie",
            "invalid header",
        ] {
            let mut bad = policy.clone();
            bad.response_headers = vec![name.into()];
            assert!(bad.validate().is_err());
        }
        let mut bad = policy.clone();
        bad.timeout_seconds = 0;
        assert!(bad.validate().is_err());
    }
    #[test]
    fn identity_headers_are_replaced_after_routing_and_login_return_is_encoded() {
        let policy = ForwardAuth {
            url: "http://auth.test/check".into(),
            sign_in_url: Some("https://login.test/?rd=old&theme=dark".into()),
            ..Default::default()
        };
        let mut req = RequestHeader::build("GET", b"/", None).unwrap();
        req.insert_header("Remote-User", "forged").unwrap();
        req.insert_header("X-Auth-Request-User", "forged").unwrap();
        apply(
            &policy,
            &[(
                HeaderName::from_static("remote-user"),
                HeaderValue::from_static("verified"),
            )],
            &mut req,
        )
        .unwrap();
        assert_eq!(req.headers["remote-user"], "verified");
        assert!(!req.headers.contains_key("x-auth-request-user"));
        let location =
            Url::parse(&login_location(&policy, "https://app.test/a?x=1&y=2").unwrap()).unwrap();
        let pairs: Vec<_> = location.query_pairs().collect();
        assert_eq!(pairs.iter().filter(|(key, _)| key == "rd").count(), 1);
        assert!(pairs
            .iter()
            .any(|(key, value)| key == "rd" && value == "https://app.test/a?x=1&y=2"));
    }
}
