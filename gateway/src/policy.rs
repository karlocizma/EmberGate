//! Client identity, network access policy, and response transformations.
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpHeader {
    Cloudflare,
    XForwardedFor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedProxy {
    pub network: String,
    pub header: IpHeader,
    #[serde(default)]
    pub trust_proto: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMode {
    Allow,
    Block,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    pub mode: AccessMode,
    pub networks: Vec<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResponsePolicy {
    pub redirect_https: bool,
    #[serde(default = "https_port")]
    pub https_port: u16,
    pub hsts_max_age: u64,
    pub hsts_include_subdomains: bool,
    pub nosniff: bool,
    pub frame_deny: bool,
    pub referrer_policy: bool,
    pub custom_headers: Vec<HeaderRule>,
}
impl Default for ResponsePolicy {
    fn default() -> Self {
        Self {
            redirect_https: false,
            https_port: 443,
            hsts_max_age: 0,
            hsts_include_subdomains: false,
            nosniff: false,
            frame_deny: false,
            referrer_policy: false,
            custom_headers: vec![],
        }
    }
}
fn https_port() -> u16 {
    443
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRule {
    pub name: String,
    pub value: String,
}

pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}
pub fn network(value: &str) -> Result<IpNet, String> {
    value
        .trim()
        .parse::<IpNet>()
        .or_else(|_| value.trim().parse::<IpAddr>().map(IpNet::from))
        .map(|net| {
            let net = net.trunc();
            if let IpNet::V6(v6) = net {
                if v6.prefix_len() >= 96 {
                    if let Some(ip) = v6.network().to_ipv4_mapped() {
                        return IpNet::new(IpAddr::V4(ip), v6.prefix_len() - 96).unwrap();
                    }
                }
            }
            net
        })
        .map_err(|_| format!("Invalid IP address or CIDR: {value}"))
}
fn contains(value: &str, ip: IpAddr) -> bool {
    network(value).is_ok_and(|net| net.contains(&normalize_ip(ip)))
}
pub fn validate_trusted(proxies: &mut [TrustedProxy]) -> Result<(), String> {
    if proxies.len() > 64 {
        return Err("Use at most 64 trusted proxy networks.".into());
    }
    let mut seen = HashSet::new();
    for proxy in proxies {
        let net = network(&proxy.network)?;
        if net.prefix_len() == 0 {
            return Err("A trusted proxy network cannot cover the entire Internet (/0).".into());
        }
        proxy.network = net.to_string();
        // Overlapping policies are ambiguous: reject rather than silently choosing a header.
        for other in &seen {
            let other: &IpNet = other;
            if net.contains(&other.network()) || other.contains(&net.network()) {
                return Err("Trusted proxy networks must not overlap.".into());
            }
        }
        seen.insert(net);
    }
    Ok(())
}
impl AccessPolicy {
    pub fn validate(&mut self) -> Result<(), String> {
        if self.networks.is_empty() || self.networks.len() > 256 {
            return Err("Access rules require 1–256 IP addresses or CIDRs.".into());
        }
        let mut seen = HashSet::new();
        for entry in &mut self.networks {
            *entry = network(entry)?.to_string();
            if !seen.insert(entry.clone()) {
                return Err("Access rule networks must be unique.".into());
            }
        }
        Ok(())
    }
    pub fn permits(&self, client: Option<IpAddr>) -> bool {
        let Some(ip) = client else { return false };
        let matches = self.networks.iter().any(|net| contains(net, ip));
        match self.mode {
            AccessMode::Allow => matches,
            AccessMode::Block => !matches,
        }
    }
}
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() {
        return None;
    }
    Some(value)
}
#[derive(Clone, Debug)]
pub struct Identity {
    pub client: Option<IpAddr>,
    pub peer: Option<IpAddr>,
    pub https: bool,
    pub source: &'static str,
}
pub fn identity(
    peer: Option<IpAddr>,
    tls: bool,
    headers: &HeaderMap,
    trusted: &[TrustedProxy],
) -> Identity {
    let peer = peer.map(normalize_ip);
    let mut result = Identity {
        client: peer,
        peer,
        https: tls,
        source: "connection",
    };
    let Some(peer) = peer else { return result };
    let Some(proxy) = trusted.iter().find(|proxy| contains(&proxy.network, peer)) else {
        return result;
    };
    match proxy.header {
        IpHeader::Cloudflare => {
            if let Some(ip) =
                single(headers, "cf-connecting-ip").and_then(|s| s.parse::<IpAddr>().ok())
            {
                result.client = Some(normalize_ip(ip));
                result.source = "cloudflare";
            }
        }
        IpHeader::XForwardedFor => {
            if let Some(chain) = single(headers, "x-forwarded-for").filter(|s| s.len() <= 2048) {
                let addresses: Option<Vec<IpAddr>> = chain
                    .split(',')
                    .map(|s| s.trim().parse().ok().map(normalize_ip))
                    .collect();
                if let Some(addresses) = addresses.filter(|a| !a.is_empty() && a.len() <= 32) {
                    let mut current = peer;
                    for ip in addresses.into_iter().rev() {
                        // Stop at the first untrusted hop; never accept its supplied left side.
                        if !trusted.iter().any(|p| {
                            p.header == IpHeader::XForwardedFor && contains(&p.network, current)
                        }) {
                            break;
                        }
                        current = ip;
                    }
                    result.client = Some(current);
                    result.source = "x_forwarded_for";
                }
            }
        }
    }
    if proxy.trust_proto {
        match single(headers, "x-forwarded-proto") {
            Some("https") => result.https = true,
            Some("http") => result.https = false,
            _ => {}
        }
    }
    result
}
impl ResponsePolicy {
    pub fn validate(&mut self) -> Result<(), String> {
        if self.https_port == 0 || self.hsts_max_age > 31_536_000 || self.custom_headers.len() > 32
        {
            return Err("Use an HTTPS port from 1–65535, HSTS up to 31536000 seconds, and at most 32 response headers.".into());
        }
        let mut seen = HashSet::new();
        for rule in &mut self.custom_headers {
            rule.name = rule.name.trim().to_ascii_lowercase();
            HeaderName::from_bytes(rule.name.as_bytes())
                .map_err(|_| "Invalid response header name.")?;
            HeaderValue::from_str(&rule.value)
                .map_err(|_| "Response header values cannot contain newlines or invalid bytes.")?;
            if rule.value.len() > 4096 || !seen.insert(rule.name.clone()) {
                return Err(
                    "Response headers must be unique and values at most 4096 bytes.".into(),
                );
            }
            if [
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailer",
                "transfer-encoding",
                "upgrade",
                "content-length",
                "content-encoding",
                "content-range",
                "host",
                "location",
                "set-cookie",
                "strict-transport-security",
            ]
            .contains(&rule.name.as_str())
            {
                return Err(format!("{} cannot be overridden here. Use dedicated HTTPS/HSTS controls where available.",rule.name));
            }
        }
        Ok(())
    }
    pub fn apply(
        &self,
        response: &mut pingora::http::ResponseHeader,
        https: bool,
    ) -> pingora::Result<()> {
        if self.nosniff {
            response.insert_header("X-Content-Type-Options", "nosniff")?;
        }
        if self.frame_deny {
            response.insert_header("X-Frame-Options", "DENY")?;
        }
        if self.referrer_policy {
            response.insert_header("Referrer-Policy", "strict-origin-when-cross-origin")?;
        }
        for rule in &self.custom_headers {
            response.insert_header(
                HeaderName::from_bytes(rule.name.as_bytes()).unwrap(),
                rule.value.as_str(),
            )?;
        }
        if https && self.hsts_max_age > 0 {
            response.insert_header(
                "Strict-Transport-Security",
                format!(
                    "max-age={}{}",
                    self.hsts_max_age,
                    if self.hsts_include_subdomains {
                        "; includeSubDomains"
                    } else {
                        ""
                    }
                ),
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn peer() -> Option<IpAddr> {
        Some("10.0.0.1".parse().unwrap())
    }
    fn trusted(header: IpHeader) -> Vec<TrustedProxy> {
        vec![TrustedProxy {
            network: "10.0.0.0/8".into(),
            header,
            trust_proto: true,
        }]
    }
    #[test]
    fn forged_and_duplicate_headers_are_not_client_identity() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        let identity = identity(peer(), false, &headers, &[]);
        assert_eq!(identity.client, peer());
        assert!(!identity.https);
        let identity = super::identity(peer(), false, &headers, &trusted(IpHeader::Cloudflare));
        assert_eq!(identity.client, Some("203.0.113.7".parse().unwrap()));
        assert!(identity.https);
        headers.append("cf-connecting-ip", "198.51.100.1".parse().unwrap());
        assert_eq!(
            super::identity(peer(), false, &headers, &trusted(IpHeader::Cloudflare)).client,
            peer()
        );
        headers.insert("x-forwarded-proto", "https, http".parse().unwrap());
        assert!(!super::identity(peer(), false, &headers, &trusted(IpHeader::Cloudflare)).https);
    }
    #[test]
    fn forwarded_chain_stops_at_first_untrusted_hop() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "192.0.2.99, 198.51.100.5, 10.0.0.2".parse().unwrap(),
        );
        assert_eq!(
            identity(peer(), false, &headers, &trusted(IpHeader::XForwardedFor)).client,
            Some("198.51.100.5".parse().unwrap())
        );
        headers.insert(
            "x-forwarded-for",
            "192.0.2.99, invalid, 10.0.0.2".parse().unwrap(),
        );
        assert_eq!(
            identity(peer(), false, &headers, &trusted(IpHeader::XForwardedFor)).client,
            peer()
        );
    }
    #[test]
    fn cidrs_and_response_protections_are_validated() {
        assert_eq!(
            network("::ffff:192.0.2.0/120").unwrap().to_string(),
            "192.0.2.0/24"
        );
        let mut overlap = trusted(IpHeader::Cloudflare);
        overlap.push(TrustedProxy {
            network: "10.0.0.1/32".into(),
            header: IpHeader::XForwardedFor,
            trust_proto: false,
        });
        assert!(validate_trusted(&mut overlap).is_err());
        assert!(validate_trusted(&mut [TrustedProxy {
            network: "0.0.0.0/0".into(),
            header: IpHeader::Cloudflare,
            trust_proto: false
        }])
        .is_err());
        let mut access = AccessPolicy {
            mode: AccessMode::Allow,
            networks: vec!["2001:db8::/32".into()],
        };
        access.validate().unwrap();
        assert!(access.permits(Some("2001:db8::1".parse().unwrap())));
        assert!(!access.permits(peer()));
        assert!(!access.permits(None));
        for (name, value) in [
            ("content-length", "123"),
            ("x-test", "bad\r\nInjected: true"),
            ("bad name", "value"),
        ] {
            let mut response: ResponsePolicy = serde_json::from_value(
                serde_json::json!({"custom_headers":[{"name":name,"value":value}]}),
            )
            .unwrap();
            assert!(response.validate().is_err());
        }
        let mut response: ResponsePolicy =
            serde_json::from_value(serde_json::json!({"hsts_max_age":300,"nosniff":true})).unwrap();
        response.validate().unwrap();
        let mut header = pingora::http::ResponseHeader::build(200, None).unwrap();
        response.apply(&mut header, false).unwrap();
        assert!(!header.headers.contains_key("strict-transport-security"));
        response.apply(&mut header, true).unwrap();
        assert_eq!(header.headers["strict-transport-security"], "max-age=300");
    }
}
