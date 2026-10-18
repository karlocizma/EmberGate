//! Local visitor-facing responses. Upstream response bodies are never replaced.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PagePolicy {
    pub maintenance: bool,
    pub status: u16,
    pub title: String,
    pub message: String,
    pub retry_after_seconds: u32,
    pub branded_errors: bool,
}
impl Default for PagePolicy {
    fn default() -> Self {
        Self {
            maintenance: false,
            status: 503,
            title: "We’ll be back shortly".into(),
            message: "This service is temporarily undergoing maintenance. Please try again later."
                .into(),
            retry_after_seconds: 300,
            branded_errors: true,
        }
    }
}
impl PagePolicy {
    pub fn validate(&mut self) -> Result<(), String> {
        self.title = self.title.trim().into();
        self.message = self.message.trim().into();
        if ![200, 503].contains(&self.status) || !(1..=86400).contains(&self.retry_after_seconds) {
            return Err(
                "Maintenance status must be 503 or 200; Retry-After must be 1–86400 seconds."
                    .into(),
            );
        }
        for (value, limit) in [(&self.title, 120), (&self.message, 2000)] {
            if value.is_empty()
                || value.chars().count() > limit
                || value
                    .chars()
                    .any(|c| c.is_control() && c != '\n' && c != '\t')
            {
                return Err("Use a title of 1–120 characters and a message of 1–2000 characters, without control characters.".into());
            }
        }
        Ok(())
    }
}

// HTML requires an explicit acceptable text/html range. Absent/wildcard Accept keeps API clients plain.
// More specific q=0 takes precedence over wildcards; malformed quality values are rejected.
pub fn wants_html(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get_all("accept")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|range| {
            let mut parts = range.trim().split(';');
            if !parts
                .next()
                .is_some_and(|p| p.trim().eq_ignore_ascii_case("text/html"))
            {
                return false;
            }
            let mut quality = 1.0;
            let mut seen = false;
            for part in parts {
                if let Some((name, value)) = part.trim().split_once('=') {
                    if name.trim().eq_ignore_ascii_case("q") {
                        if seen {
                            return false;
                        }
                        seen = true;
                        let Ok(q) = value.trim().parse::<f32>() else {
                            return false;
                        };
                        if !(0.0..=1.0).contains(&q) {
                            return false;
                        }
                        quality = q;
                    }
                }
            }
            quality > 0.0
        })
}
fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn html(status: u16, title: &str, message: &str, maintenance: bool) -> String {
    let title = escape(title);
    let message = escape(message);
    let label = if maintenance {
        "SCHEDULED MAINTENANCE"
    } else {
        "REQUEST INTERRUPTED"
    };
    let css = include_str!("page-style.css");
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light dark"><title>{title} · EmberGate</title><style>{css}</style></head><body><main><div class="brand"><span class="brand-mark" aria-hidden="true">⇄</span>EmberGate</div><section class="card"><div class="eyebrow">{label}</div><span class="status">HTTP {status}</span><h1>{title}</h1><p>{message}</p><div class="signal"><span></span>{note}</div></section><footer>Powered by Pingora</footer></main></body></html>"#,
        note = if maintenance {
            "Thank you for your patience."
        } else {
            "Please try again later or contact the service administrator."
        }
    )
}
pub fn error_title(status: u16) -> &'static str {
    match status {
        400 => "Invalid request",
        403 => "Access denied",
        404 => "Page not found",
        429 => "Too many requests",
        502 => "Unable to reach this service",
        503 => "Service temporarily unavailable",
        504 => "The service took too long to respond",
        _ => "Something went wrong",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pages_escape_custom_text_and_validate_policy() {
        let body = html(
            503,
            "<script>alert('x')</script>",
            "<img src=x onerror=alert(1)> & unsafe",
            true,
        );
        assert!(!body.contains("<script>"));
        assert!(!body.contains("<img"));
        assert!(body.contains("&lt;script&gt;"));
        assert!(body.contains("Powered by Pingora"));
        for value in [
            serde_json::json!({"status":302}),
            serde_json::json!({"retry_after_seconds":0}),
            serde_json::json!({"title":" "}),
            serde_json::json!({"message":"bad\u{0000}"}),
            serde_json::json!({"title":"x".repeat(121)}),
        ] {
            assert!(serde_json::from_value::<PagePolicy>(value)
                .unwrap()
                .validate()
                .is_err());
        }
    }
    #[test]
    fn html_requires_explicit_accept_and_positive_quality() {
        for (accept, expected) in [
            ("", false),
            ("*/*", false),
            ("application/json", false),
            ("text/html,application/xhtml+xml,*/*;q=0.8", true),
            ("text/html;q=0,*/*;q=1", false),
            ("TEXT/HTML;Q=0.5", true),
            ("text/html;q=NaN", false),
            ("text/html;q=2", false),
            ("text/html;q=0.5;q=1", false),
        ] {
            let mut headers = axum::http::HeaderMap::new();
            headers.insert("accept", accept.parse().unwrap());
            assert_eq!(wants_html(&headers), expected, "{accept}");
        }
    }
}
