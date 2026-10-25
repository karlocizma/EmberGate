//! CrowdSec remediation settings: the ban message, and captcha decisions
//! answered with a Cloudflare Turnstile challenge. Without a configured
//! provider, captcha decisions are handled as bans.
use crate::state::Shared;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

const SETTINGS: &str = "crowdsec_remediation";
const SECRET: &str = "crowdsec_captcha_secret";
pub const PATH: &str = "/.well-known/embergate/captcha";
pub const COOKIE: &str = "embergate_captcha";
/// How long a solved challenge lets a visitor through.
const PASS_SECONDS: u64 = 3600;
const VERIFY_URL: &str = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const DEFAULT_BAN: &str = "Your address was blocked by this site's threat protection. If you think this is a mistake, contact the site owner.";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    #[default]
    None,
    Turnstile,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub ban_message: String,
    #[serde(default)]
    pub provider: Provider,
    #[serde(default)]
    pub site_key: String,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            ban_message: DEFAULT_BAN.into(),
            provider: Provider::None,
            site_key: String::new(),
        }
    }
}
impl Settings {
    fn validate(&self) -> Result<(), String> {
        let message = self.ban_message.trim();
        if message.is_empty()
            || message.chars().count() > 500
            || message.chars().any(|c| c.is_control() && c != '\n')
        {
            return Err("Enter a ban message of up to 500 characters.".into());
        }
        if self.provider == Provider::Turnstile && !key_like(&self.site_key) {
            return Err("Enter the Turnstile site key from your Cloudflare dashboard.".into());
        }
        if self.provider == Provider::None && !self.site_key.is_empty() {
            return Err("Remove the site key, or choose Cloudflare Turnstile.".into());
        }
        Ok(())
    }
}
fn key_like(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

/// Live settings with the provider secret, which never leaves the server.
#[derive(Default)]
pub struct Remediation {
    pub settings: Settings,
    secret: String,
    /// Signs pass cookies; random per process, so a restart asks again.
    signing_key: [u8; 32],
}
impl Remediation {
    fn new(settings: Settings, secret: String) -> Self {
        let mut signing_key = [0u8; 32];
        openssl::rand::rand_bytes(&mut signing_key).expect("random signing key");
        Self {
            settings,
            secret,
            signing_key,
        }
    }
    /// Whether captcha decisions get a challenge instead of a ban.
    pub fn challenges(&self) -> bool {
        self.settings.provider == Provider::Turnstile && !self.secret.is_empty()
    }
    fn signature(&self, ip: &str, expires: u64) -> String {
        let key = openssl::pkey::PKey::hmac(&self.signing_key).expect("HMAC key");
        let mut signer =
            openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).expect("HMAC");
        signer
            .update(format!("{ip}|{expires}").as_bytes())
            .expect("HMAC");
        signer
            .sign_to_vec()
            .expect("HMAC")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
    /// A pass cookie value for `ip`, valid for an hour.
    pub fn pass(&self, ip: &str, now: u64) -> String {
        let expires = now + PASS_SECONDS;
        format!("{expires}.{}", self.signature(ip, expires))
    }
    pub fn passes(&self, cookie: Option<&str>, ip: &str, now: u64) -> bool {
        let Some((expires, signature)) = cookie.and_then(|c| c.split_once('.')) else {
            return false;
        };
        let Ok(expires) = expires.parse::<u64>() else {
            return false;
        };
        // memcmp::eq requires equal lengths, so check the length first.
        expires > now
            && expires <= now + PASS_SECONDS
            && signature.len() == 64
            && openssl::memcmp::eq(self.signature(ip, expires).as_bytes(), signature.as_bytes())
    }
    /// Asks Turnstile whether `token` was solved by `ip`.
    pub async fn verify(&self, token: &str, ip: &str) -> bool {
        if token.is_empty() || token.len() > 2048 {
            return false;
        }
        let url =
            std::env::var("GATEWAY_TURNSTILE_VERIFY_URL").unwrap_or_else(|_| VERIFY_URL.into());
        let Ok(client) = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()
        else {
            return false;
        };
        let response = client
            .post(url)
            .form(&[
                ("secret", self.secret.as_str()),
                ("response", token),
                ("remoteip", ip),
            ])
            .send()
            .await;
        match response {
            Ok(response) => response
                .json::<Value>()
                .await
                .is_ok_and(|v| v["success"] == true),
            Err(error) => {
                log::warn!("Turnstile verification failed: {error}");
                false
            }
        }
    }
}

fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// The challenge page. `target` is the visitor's original path and query.
/// Cloudflare updates api.js in place and asks sites not to pin or cache it,
/// so it carries no integrity hash; the page's CSP limits scripts to that origin.
pub fn page(site_key: &str, target: &str, failed: bool) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>Checking your browser</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;background:#f6f6f7;color:#1c1c1f}}main{{max-width:420px;padding:32px 24px;text-align:center}}h1{{font-size:1.4rem}}button{{margin-top:16px;padding:10px 18px;border:0;border-radius:8px;background:#f06a28;color:#fff;font:inherit;cursor:pointer}}.error{{color:#b3261e}}@media(prefers-color-scheme:dark){{body{{background:#18181b;color:#ececee}}}}</style></head>
<body><main><h1>Checking your browser</h1><p>This site asks some visitors to confirm they are human before continuing.</p>{error}<form method="post" action="{PATH}"><input type="hidden" name="rd" value="{target}"><div class="cf-turnstile" data-sitekey="{site_key}"></div><button type="submit">Continue</button></form></main></body></html>"#,
        error = if failed {
            r#"<p class="error" role="alert">That check did not succeed. Please try again.</p>"#
        } else {
            ""
        },
        site_key = escape(site_key),
        target = escape(target),
    )
}

/// Only same-site paths are allowed as the post-challenge destination.
pub fn destination(value: &str) -> String {
    crate::oidc::same_site_path(value).unwrap_or_else(|| "/".into())
}

pub fn load(control: &crate::management::Control) -> Result<Remediation, String> {
    let settings = control
        .secret(SETTINGS)?
        .map(|v| {
            serde_json::from_str(&v)
                .map_err(|_| "Invalid CrowdSec remediation settings.".to_owned())
        })
        .transpose()?
        .unwrap_or_default();
    Ok(Remediation::new(
        settings,
        control.secret(SECRET)?.unwrap_or_default(),
    ))
}

pub fn validate_backup(key: &str, value: &str) -> Result<(), String> {
    match key {
        SETTINGS => serde_json::from_str::<Settings>(value)
            .map_err(|_| "Invalid CrowdSec remediation settings.".to_owned())?
            .validate(),
        SECRET if key_like(value) => Ok(()),
        _ => Err("Invalid CrowdSec captcha secret.".into()),
    }
}

fn summary(state: &Shared) -> Value {
    let remediation = state.crowdsec.remediation.load();
    json!({
        "settings": remediation.settings,
        "secret_configured": !remediation.secret.is_empty(),
        "challenges": remediation.challenges(),
        "default_ban_message": DEFAULT_BAN,
    })
}

async fn status(State(state): State<Shared>) -> Json<Value> {
    Json(summary(&state))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Save {
    #[serde(flatten)]
    settings: Settings,
    /// A new provider secret; omitted to keep the saved one.
    #[serde(default)]
    secret_key: Option<String>,
}

async fn save(
    State(state): State<Shared>,
    Json(input): Json<Save>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let invalid = |e: String| (StatusCode::UNPROCESSABLE_ENTITY, Json(json!({"error":e})));
    let unavailable = |e: String| (StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":e})));
    let mut settings = input.settings;
    settings.ban_message = settings.ban_message.trim().to_owned();
    settings.site_key = settings.site_key.trim().to_owned();
    settings.validate().map_err(invalid)?;
    let current = state.crowdsec.remediation.load_full();
    let secret = match (
        settings.provider,
        input
            .secret_key
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty()),
    ) {
        (Provider::None, _) => String::new(),
        (Provider::Turnstile, Some(secret)) if key_like(&secret) => secret,
        (Provider::Turnstile, Some(_)) => {
            return Err(invalid(
                "Enter the Turnstile secret key from your Cloudflare dashboard.".into(),
            ))
        }
        (Provider::Turnstile, None) if !current.secret.is_empty() => current.secret.clone(),
        (Provider::Turnstile, None) => {
            return Err(invalid("Enter the Turnstile secret key.".into()))
        }
    };
    state
        .control
        .set_secret(
            SETTINGS.into(),
            Some(serde_json::to_string(&settings).expect("settings")),
        )
        .await
        .map_err(unavailable)?;
    state
        .control
        .set_secret(
            SECRET.into(),
            Some(secret.clone()).filter(|s| !s.is_empty()),
        )
        .await
        .map_err(unavailable)?;
    state
        .crowdsec
        .remediation
        .store(std::sync::Arc::new(Remediation::new(settings, secret)));
    Ok(Json(summary(&state)))
}

pub fn routes() -> Router<Shared> {
    Router::new().route(
        "/api/integrations/crowdsec/remediation",
        get(status).put(save),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn remediation() -> Remediation {
        Remediation::new(
            Settings {
                provider: Provider::Turnstile,
                site_key: "0x4AAAAAAA-site".into(),
                ..Settings::default()
            },
            "0x4AAAAAAA-secret".into(),
        )
    }

    #[test]
    fn pass_cookies_are_bound_to_address_and_expire() {
        let r = remediation();
        let cookie = r.pass("203.0.113.9", 1000);
        assert!(r.passes(Some(&cookie), "203.0.113.9", 1000));
        assert!(r.passes(Some(&cookie), "203.0.113.9", 1000 + PASS_SECONDS - 1));
        assert!(
            !r.passes(Some(&cookie), "203.0.113.9", 1000 + PASS_SECONDS),
            "expired"
        );
        assert!(
            !r.passes(Some(&cookie), "203.0.113.10", 1000),
            "other address"
        );
        assert!(
            !remediation().passes(Some(&cookie), "203.0.113.9", 1000),
            "other process key"
        );
        let (expires, signature) = cookie.split_once('.').unwrap();
        assert!(!r.passes(
            Some(&format!(
                "{}.{signature}",
                expires.parse::<u64>().unwrap() + 1
            )),
            "203.0.113.9",
            1000
        ));
        assert!(!r.passes(
            Some(&format!("{}.{signature}", 1000 + PASS_SECONDS * 5)),
            "203.0.113.9",
            1000
        ));
        for bad in ["", "abc", "1.2", &format!("{cookie}0")] {
            assert!(!r.passes(Some(bad), "203.0.113.9", 1000), "{bad}");
        }
        assert!(!r.passes(None, "203.0.113.9", 1000));
    }

    #[test]
    fn challenges_need_a_provider_and_secret() {
        assert!(remediation().challenges());
        assert!(!Remediation::new(Settings::default(), "secret-value".into()).challenges());
        let mut no_secret = remediation();
        no_secret.secret.clear();
        assert!(!no_secret.challenges());
    }

    #[test]
    fn settings_and_destinations_are_validated() {
        assert!(Settings::default().validate().is_ok());
        assert!(Settings {
            ban_message: " ".into(),
            ..Settings::default()
        }
        .validate()
        .is_err());
        assert!(Settings {
            ban_message: "x".repeat(501),
            ..Settings::default()
        }
        .validate()
        .is_err());
        assert!(Settings {
            provider: Provider::Turnstile,
            ..Settings::default()
        }
        .validate()
        .is_err());
        assert!(Settings {
            site_key: "0x4AAAAAAA-site".into(),
            ..Settings::default()
        }
        .validate()
        .is_err());
        assert_eq!(destination("/photos?id=1"), "/photos?id=1");
        for bad in [
            "https://evil.test/",
            "//evil.test/",
            "/\\evil.test",
            "photos",
            "/a\r\nSet-Cookie: x",
        ] {
            assert_eq!(destination(bad), "/", "{bad}");
        }
        let html = page("key\"><script>", "/a?b=\"<x>", true);
        assert!(
            !html.contains("<script>\"")
                && html.contains("key&quot;&gt;&lt;script&gt;")
                && html.contains("/a?b=&quot;&lt;x&gt;")
        );
        assert!(html.contains("role=\"alert\""));
        assert!(validate_backup(
            SETTINGS,
            &serde_json::to_string(&Settings::default()).unwrap()
        )
        .is_ok());
        assert!(validate_backup(SECRET, "0x4AAAAAAA-secret").is_ok());
        assert!(validate_backup(SECRET, "bad secret").is_err());
    }
}
