//! Deterministic upstream transformations; public routing, identity, and cache keys stay unchanged.
use axum::http::{HeaderName, HeaderValue, Uri};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutingPolicy {
    pub strip_prefix: bool,
    pub rewrite_prefix: Option<String>,
    pub set_headers: Vec<crate::policy::HeaderRule>,
    pub remove_headers: Vec<String>,
}

fn protected(name: &str) -> bool {
    name.starts_with("x-forwarded-")
        || name.starts_with("sec-websocket-")
        || [
            "host",
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailer",
            "transfer-encoding",
            "upgrade",
            "content-length",
            "expect",
            "proxy-connection",
            "content-encoding",
            "accept-encoding",
            "cache-control",
            "pragma",
            "range",
            "if-range",
            "if-match",
            "if-none-match",
            "if-modified-since",
            "if-unmodified-since",
            "forwarded",
            "cf-connecting-ip",
            "cf-connecting-ipv6",
            "true-client-ip",
            "x-real-ip",
            "authorization",
            "cookie",
        ]
        .contains(&name)
}

impl RoutingPolicy {
    pub fn validate(&mut self) -> Result<(), String> {
        if self.strip_prefix && self.rewrite_prefix.is_some() {
            return Err("Choose either prefix stripping or prefix replacement.".into());
        }
        if let Some(prefix) = &self.rewrite_prefix {
            if !prefix.starts_with('/')
                || prefix.starts_with("//")
                || prefix.len() > 1024
                || prefix.contains(['?', '#', '\\'])
                || !prefix.is_ascii()
                || prefix.chars().any(|c| c.is_control() || c.is_whitespace())
                || prefix.parse::<Uri>().is_err()
            {
                return Err("Replacement prefixes must be URL paths starting with a single /, up to 1024 ASCII bytes, without queries, fragments, backslashes, or whitespace. Percent-encode non-ASCII characters.".into());
            }
        }
        if self.set_headers.len() > 32 || self.remove_headers.len() > 32 {
            return Err("Use at most 32 header overrides and 32 header removals.".into());
        }
        let mut seen = HashSet::new();
        for name in self
            .remove_headers
            .iter_mut()
            .chain(self.set_headers.iter_mut().map(|r| &mut r.name))
        {
            *name = name.trim().to_ascii_lowercase();
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| "Invalid request header name.")?;
            if protected(name) {
                return Err(format!("{name} is protected and cannot be changed here."));
            }
            if !seen.insert(name.clone()) {
                return Err("Request headers must be unique across overrides and removals.".into());
            }
        }
        for rule in &self.set_headers {
            HeaderValue::from_str(&rule.value)
                .map_err(|_| "Invalid request header value; newlines are forbidden.")?;
            if rule.value.len() > 4096 || !rule.value.is_ascii() {
                return Err("Request header values must contain at most 4096 ASCII bytes.".into());
            }
        }
        Ok(())
    }

    pub fn target(
        &self,
        original: &Uri,
        matched_prefix: &str,
    ) -> Result<Uri, axum::http::uri::InvalidUri> {
        if !self.strip_prefix && self.rewrite_prefix.is_none() {
            return Ok(original.clone());
        }
        let Some(suffix) = original.path().strip_prefix(matched_prefix) else {
            return Ok(original.clone());
        };
        let prefix = self.rewrite_prefix.as_deref().unwrap_or("");
        let mut path = if prefix.ends_with('/') && suffix.starts_with('/') {
            format!("{prefix}{}", &suffix[1..])
        } else if !prefix.is_empty()
            && !suffix.is_empty()
            && !prefix.ends_with('/')
            && !suffix.starts_with('/')
        {
            format!("{prefix}/{suffix}")
        } else {
            format!("{prefix}{suffix}")
        };
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        // Preserve the original query byte for byte, including a trailing empty '?'.
        if let Some((_, query)) = original
            .path_and_query()
            .and_then(|p| p.as_str().split_once('?'))
        {
            path.push('?');
            path.push_str(query);
        }
        path.parse()
    }

    pub fn apply(
        &self,
        request: &mut pingora::http::RequestHeader,
        original: &Uri,
        prefix: &str,
    ) -> pingora::Result<()> {
        let target = self
            .target(original, prefix)
            .map_err(|_| pingora::Error::new(pingora::ErrorType::HTTPStatus(400)))?;
        if self.strip_prefix || self.rewrite_prefix.is_some() {
            request.set_uri(target);
        }
        for name in &self.remove_headers {
            request.remove_header(name);
        }
        for rule in &self.set_headers {
            request.insert_header(rule.name.clone(), rule.value.clone())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rewrites_preserve_encoded_paths_queries_and_empty_targets() {
        for (source, matched, replacement, expected) in [
            ("/api", "/api", None, "/"),
            (
                "/api/v1%2Ftwo?x=%2f&x=2",
                "/api",
                None,
                "/v1%2Ftwo?x=%2f&x=2",
            ),
            ("/api/", "/api/", Some("/internal"), "/internal"),
            ("/api/items", "/api/", Some("/internal"), "/internal/items"),
            (
                "/api/items?",
                "/api",
                Some("/internal/"),
                "/internal/items?",
            ),
            ("/apiv2", "/api", None, "/v2"),
            ("/api//x", "/api", None, "//x"),
            ("/other", "/api", None, "/other"),
        ] {
            let policy = RoutingPolicy {
                strip_prefix: replacement.is_none(),
                rewrite_prefix: replacement.map(String::from),
                ..Default::default()
            };
            assert_eq!(
                policy
                    .target(&source.parse().unwrap(), matched)
                    .unwrap()
                    .to_string(),
                expected
            );
        }
    }
    #[test]
    fn rejects_unsafe_and_conflicting_rules() {
        for name in [
            "Host",
            "Content-Length",
            "Connection",
            "X-Forwarded-For",
            "Sec-WebSocket-Key",
            "Cookie",
            "Authorization",
            "Cache-Control",
            "If-None-Match",
            "Accept-Encoding",
            "bad name",
        ] {
            let mut policy = RoutingPolicy {
                remove_headers: vec![name.into()],
                ..Default::default()
            };
            assert!(policy.validate().is_err(), "{name}");
        }
        for prefix in [
            "https://evil.test",
            "//evil",
            "/x?y",
            "/x#y",
            "/x\\y",
            "/x\ny",
            "/é",
        ] {
            let mut policy = RoutingPolicy {
                rewrite_prefix: Some(prefix.into()),
                ..Default::default()
            };
            assert!(policy.validate().is_err(), "{prefix}");
        }
        for value in [
            serde_json::json!({"strip_prefix":true,"rewrite_prefix":"/x"}),
            serde_json::json!({"remove_headers":["X-Test"],"set_headers":[{"name":"x-test","value":"ok"}]}),
            serde_json::json!({"set_headers":[{"name":"x-test","value":"ok\r\nInjected: bad"}]}),
        ] {
            assert!(serde_json::from_value::<RoutingPolicy>(value)
                .unwrap()
                .validate()
                .is_err());
        }
    }
}
