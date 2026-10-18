//! Downstream-only streaming compression. Cache/origin bytes and request headers stay unchanged.
use async_trait::async_trait;
use axum::http::{header, HeaderMap};
use bytes::Bytes;
use pingora::{
    http::{RequestHeader, ResponseHeader},
    modules::http::{HttpModule, HttpModuleBuilder, HttpModules, Module},
    protocols::http::compression::{Algorithm, ResponseCompressionCtx},
    Result,
};
use serde::{Deserialize, Serialize};
use std::{any::Any, io::Write};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Auto,
    Gzip,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CompressionPolicy {
    pub mode: Mode,
    pub level: u32,
    pub min_bytes: usize,
}
impl Default for CompressionPolicy {
    fn default() -> Self {
        Self {
            mode: Mode::Auto,
            level: 4,
            min_bytes: 1024,
        }
    }
}
impl CompressionPolicy {
    pub fn validate(&self) -> std::result::Result<(), String> {
        if !(1..=6).contains(&self.level) || !(256..=1048576).contains(&self.min_bytes) {
            return Err(
                "Compression requires level 1–6 and a minimum declared size of 256–1048576 bytes."
                    .into(),
            );
        }
        Ok(())
    }
}
#[derive(Default, Debug)]
struct Preferences {
    gzip: Option<u16>,
    br: Option<u16>,
    identity: Option<u16>,
    wildcard: Option<u16>,
}
fn quality(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if !matches!(whole, "0" | "1")
        || fraction.len() > 3
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let scaled = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u16>().ok()? * 10u16.pow(3 - fraction.len() as u32)
    };
    match whole {
        "0" => Some(scaled),
        "1" if scaled == 0 => Some(1000),
        _ => None,
    }
}
impl Preferences {
    fn parse(headers: &HeaderMap) -> Self {
        let mut result = Self::default();
        let mut count = 0;
        let mut bytes = 0;
        for field in headers.get_all(header::ACCEPT_ENCODING) {
            bytes += field.as_bytes().len();
            if bytes > 16384 {
                return Self::default();
            }
            let Ok(field) = field.to_str() else {
                return Self::default();
            };
            for item in field.split(',').filter(|s| !s.trim().is_empty()) {
                count += 1;
                if count > 128 {
                    return Self::default();
                }
                let mut parts = item.split(';');
                let token = parts.next().unwrap().trim();
                let mut weight = Some(1000);
                let mut seen = false;
                for param in parts {
                    match param.trim().split_once('=') {
                        Some((name, value)) if name.trim().eq_ignore_ascii_case("q") && !seen => {
                            seen = true;
                            weight = quality(value.trim());
                        }
                        _ => {
                            weight = None;
                            break;
                        }
                    }
                }
                let slot = if token.eq_ignore_ascii_case("gzip") {
                    &mut result.gzip
                } else if token.eq_ignore_ascii_case("br") {
                    &mut result.br
                } else if token.eq_ignore_ascii_case("identity") {
                    &mut result.identity
                } else if token == "*" {
                    &mut result.wildcard
                } else {
                    continue;
                };
                // Conflicting duplicates cannot override an explicit exclusion.
                let q = weight.unwrap_or(0);
                *slot = Some(slot.map_or(q, |old| old.min(q)));
            }
        }
        result
    }
    fn identity_allowed(&self) -> bool {
        self.identity
            .unwrap_or(if self.wildcard == Some(0) { 0 } else { 1000 })
            > 0
    }
    fn choose(&self, mode: Mode) -> Option<Algorithm> {
        let gzip = self.gzip.or(self.wildcard).unwrap_or(0);
        let br = if mode == Mode::Auto {
            self.br.or(self.wildcard).unwrap_or(0)
        } else {
            0
        };
        let best = gzip.max(br);
        if best == 0 || self.identity.is_some_and(|q| q > best) {
            return None;
        }
        Some(if br >= gzip {
            Algorithm::Brotli
        } else {
            Algorithm::Gzip
        })
    }
}
fn directive(headers: &HeaderMap, expected: &str) -> bool {
    headers.get_all(header::CACHE_CONTROL).iter().any(|v| {
        v.to_str().map_or(true, |v| {
            v.split(',').any(|s| {
                s.trim()
                    .split('=')
                    .next()
                    .is_some_and(|name| name.trim().eq_ignore_ascii_case(expected))
            })
        })
    })
}
fn compressible_type(response: &ResponseHeader) -> Option<String> {
    if response
        .headers
        .get_all(header::CONTENT_TYPE)
        .iter()
        .count()
        != 1
    {
        return None;
    }
    let mime = response
        .headers
        .get(header::CONTENT_TYPE)?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim()
        .to_ascii_lowercase();
    let supported = (mime.starts_with("text/") && mime != "text/event-stream")
        || matches!(
            mime.as_str(),
            "application/json"
                | "application/javascript"
                | "application/x-javascript"
                | "application/xml"
                | "application/wasm"
                | "image/svg+xml"
        )
        || (mime.starts_with("application/")
            && (mime.ends_with("+json") || mime.ends_with("+xml")));
    if supported && !mime.contains("zip") {
        Some(mime)
    } else {
        None
    }
}
fn eligible(
    request: &RequestHeader,
    response: &ResponseHeader,
    policy: &CompressionPolicy,
) -> Option<String> {
    if !matches!(
        request.version,
        axum::http::Version::HTTP_11 | axum::http::Version::HTTP_2
    ) || request.method != "GET"
        || response.status.as_u16() != 200
        || [
            header::RANGE,
            header::IF_RANGE,
            header::UPGRADE,
            header::AUTHORIZATION,
            header::COOKIE,
        ]
        .iter()
        .any(|h| request.headers.contains_key(h))
        || [
            header::CONTENT_ENCODING,
            header::CONTENT_RANGE,
            header::SET_COOKIE,
        ]
        .iter()
        .any(|h| response.headers.contains_key(h))
        || directive(&request.headers, "no-transform")
        || directive(&response.headers, "no-transform")
        || directive(&response.headers, "private")
        || directive(&response.headers, "no-store")
    {
        return None;
    }
    let lengths = response
        .headers
        .get_all(header::CONTENT_LENGTH)
        .iter()
        .collect::<Vec<_>>();
    if lengths.len() > 1 {
        return None;
    }
    if let Some(value) = lengths.first() {
        let size = value.to_str().ok()?.parse::<u64>().ok()?;
        if size < policy.min_bytes as u64 {
            return None;
        }
    }
    compressible_type(response)
}
fn vary(response: &mut ResponseHeader) -> Result<()> {
    if !response.headers.get_all(header::VARY).iter().any(|v| {
        v.to_str().is_ok_and(|v| {
            v.split(',')
                .any(|s| s.trim() == "*" || s.trim().eq_ignore_ascii_case("accept-encoding"))
        })
    }) {
        response.append_header(header::VARY, "Accept-Encoding")?;
    }
    Ok(())
}
const DIGESTS: [&str; 4] = ["content-md5", "digest", "content-digest", "repr-digest"];
fn strip_digests(headers: &mut HeaderMap) {
    for name in DIGESTS {
        headers.remove(name);
    }
}

pub struct Downstream {
    native: ResponseCompressionCtx,
    mime: Option<String>,
    reject: bool,
    brotli_level: Option<u32>,
    brotli: Option<brotli::CompressorWriter<Vec<u8>>>,
    transformed: bool,
}
impl Default for Downstream {
    fn default() -> Self {
        Self {
            native: ResponseCompressionCtx::new(0, false, false),
            mime: None,
            reject: false,
            brotli_level: None,
            brotli: None,
            transformed: false,
        }
    }
}
impl Downstream {
    pub fn prepare(
        &mut self,
        request: &RequestHeader,
        response: &mut ResponseHeader,
        policy: &CompressionPolicy,
    ) -> Result<()> {
        if response.status.is_informational() {
            return Ok(());
        }
        // A 304 must carry the Vary metadata its corresponding 200 can acquire here.
        if response.status.as_u16() == 304 && matches!(request.method.as_str(), "GET" | "HEAD") {
            vary(response)?;
            return Ok(());
        }
        let preferences = Preferences::parse(&request.headers);
        self.mime = eligible(request, response, policy);
        if self.mime.is_some() {
            vary(response)?;
        }
        if let (Some(_), Some(algorithm)) = (&self.mime, preferences.choose(policy.mode)) {
            // Feed only the selected coding to Pingora: its native parser ignores quality values.
            if algorithm == Algorithm::Brotli {
                self.brotli_level = Some(policy.level);
            } else {
                self.native.adjust_algorithm_level(algorithm, policy.level);
                let mut normalized = RequestHeader::build("GET", b"/", None)?;
                normalized.insert_header(header::ACCEPT_ENCODING, algorithm.as_str())?;
                self.native.request_filter(&normalized);
            }
        } else if request.method == "GET"
            && response.status.as_u16() == 200
            && !response.headers.contains_key(header::CONTENT_ENCODING)
            && !preferences.identity_allowed()
            && !request.headers.contains_key(header::UPGRADE)
        {
            self.reject = true;
            vary(response)?;
        }
        Ok(())
    }
    fn brotli_bytes(&mut self, body: Option<&Bytes>, end: bool) -> Result<Option<Bytes>> {
        let Some(writer) = self.brotli.as_mut() else {
            return Ok(None);
        };
        if let Some(body) = body {
            writer.write_all(body).map_err(|e| {
                pingora::Error::because(
                    pingora::ErrorType::InternalError,
                    "Brotli encoding failed",
                    e,
                )
            })?;
        }
        if end {
            // into_inner emits BROTLI_OPERATION_FINISH; flush alone leaves an incomplete stream.
            Ok(Some(self.brotli.take().unwrap().into_inner().into()))
        } else {
            writer.flush().map_err(|e| {
                pingora::Error::because(pingora::ErrorType::InternalError, "Brotli flush failed", e)
            })?;
            Ok(Some(std::mem::take(writer.get_mut()).into()))
        }
    }
}
#[async_trait]
impl HttpModule for Downstream {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    async fn response_header_filter(
        &mut self,
        response: &mut ResponseHeader,
        end: bool,
    ) -> Result<()> {
        if response.status.is_informational() {
            return Ok(());
        }
        if self.reject {
            response.set_status(406)?;
            for name in [
                "content-encoding",
                "content-range",
                "transfer-encoding",
                "etag",
                "accept-ranges",
                "trailer",
                "content-type",
            ] {
                response.remove_header(name);
            }
            for name in DIGESTS {
                response.remove_header(name);
            }
            response.insert_header(header::CONTENT_LENGTH, "0")?;
            response.insert_header(header::CACHE_CONTROL, "no-store")?;
            return Ok(());
        }
        // MIME types are case-insensitive; preserve the origin's original spelling and parameters.
        let original = if self.native.is_enabled() {
            response.headers.get(header::CONTENT_TYPE).cloned()
        } else {
            None
        };
        if self.native.is_enabled() {
            if let Some(mime) = &self.mime {
                response.insert_header(header::CONTENT_TYPE, mime.as_str())?;
            }
        }
        self.native.response_header_filter(response, end);
        if let Some(original) = original {
            response.insert_header(header::CONTENT_TYPE, original)?;
        }
        self.transformed = self.native.is_enabled();
        if let Some(level) = self.brotli_level.take().filter(|_| !end) {
            response.insert_header(header::CONTENT_ENCODING, "br")?;
            response.remove_header(&header::CONTENT_LENGTH);
            response.remove_header(&header::ACCEPT_RANGES);
            response.insert_header(header::TRANSFER_ENCODING, "chunked")?;
            if let Some(etag) = response.headers.get(header::ETAG).cloned() {
                if !etag.as_bytes().starts_with(b"W/") {
                    if etag.as_bytes().starts_with(b"\"") {
                        let weak =
                            axum::http::HeaderValue::from_bytes(&[b"W/", etag.as_bytes()].concat())
                                .expect("valid weakened ETag");
                        response.insert_header(header::ETAG, weak)?;
                    } else {
                        response.remove_header(&header::ETAG);
                    }
                }
            }
            self.brotli = Some(brotli::CompressorWriter::new(Vec::new(), 4096, level, 22));
            self.transformed = true;
        }
        if self.transformed {
            for name in DIGESTS {
                response.remove_header(name);
            }
            let trailers = response
                .headers
                .get_all(header::TRAILER)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .map(str::trim)
                .filter(|s| {
                    !s.is_empty()
                        && !DIGESTS.iter().any(|name| s.eq_ignore_ascii_case(name))
                        && !s.eq_ignore_ascii_case("etag")
                })
                .collect::<Vec<_>>()
                .join(", ");
            response.remove_header(&header::TRAILER);
            if !trailers.is_empty() {
                response.insert_header(header::TRAILER, trailers)?;
            }
        }
        Ok(())
    }
    fn response_body_filter(&mut self, body: &mut Option<Bytes>, end: bool) -> Result<()> {
        if self.reject {
            *body = None;
        } else if self.brotli.is_some() {
            *body = self.brotli_bytes(body.as_ref(), end)?;
        } else if self.native.is_enabled() {
            if let Some(encoded) = self.native.response_body_filter(body.as_ref(), end) {
                *body = Some(encoded);
            }
        }
        Ok(())
    }
    fn response_trailer_filter(
        &mut self,
        trailers: &mut Option<Box<HeaderMap>>,
    ) -> Result<Option<Bytes>> {
        if self.reject {
            *trailers = None;
        } else if self.transformed {
            if let Some(trailers) = trailers {
                strip_digests(trailers);
                trailers.remove(header::ETAG);
            }
        }
        Ok(None)
    }
    fn response_done_filter(&mut self) -> Result<Option<Bytes>> {
        if self.brotli.is_some() {
            return self.brotli_bytes(None, true);
        }
        Ok(if self.native.is_enabled() {
            self.native.response_body_filter(None, true)
        } else {
            None
        })
    }
}
struct Builder;
impl HttpModuleBuilder for Builder {
    fn init(&self) -> Module {
        Box::new(Downstream::default())
    }
    fn order(&self) -> i16 {
        i16::MIN / 2
    }
}
pub fn register(modules: &mut HttpModules) {
    modules.add_module(Box::new(Builder));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn prefs(values: &[&str]) -> Preferences {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(header::ACCEPT_ENCODING, v.parse().unwrap());
        }
        Preferences::parse(&h)
    }
    #[test]
    fn quality_negotiation_exclusions_wildcards_and_multiple_fields() {
        assert_eq!(
            prefs(&["gzip;q=0.8, br;q=0.3"]).choose(Mode::Auto),
            Some(Algorithm::Gzip)
        );
        assert_eq!(
            prefs(&["br, gzip"]).choose(Mode::Auto),
            Some(Algorithm::Brotli)
        );
        assert_eq!(
            prefs(&["br, gzip"]).choose(Mode::Gzip),
            Some(Algorithm::Gzip)
        );
        assert_eq!(prefs(&["*;q=1, gzip;q=0, br;q=0"]).choose(Mode::Auto), None);
        assert_eq!(prefs(&["gzip;q=0", "GZIP;q=1"]).choose(Mode::Auto), None);
        assert_eq!(
            prefs(&["gzip;q=0.8", "br;q=1"]).choose(Mode::Auto),
            Some(Algorithm::Brotli)
        );
        assert_eq!(prefs(&["gzip;q=0.5,identity;q=1"]).choose(Mode::Auto), None);
        assert!(!prefs(&["*;q=0"]).identity_allowed());
        assert!(prefs(&["*;q=0,identity;q=1"]).identity_allowed());
        for input in [
            "gzip;q=0",
            "gzip;q=1.001",
            "gzip;q=-1",
            "gzip;q=NaN",
            "gzip;q=0.1234",
            "gzip;q=1;q=0",
            "gzip;q=.5",
        ] {
            assert_eq!(prefs(&[input]).choose(Mode::Auto), None, "{input}");
        }
        assert_eq!(prefs(&[]).choose(Mode::Auto), None);
    }
    #[tokio::test]
    async fn brotli_streams_are_finished_on_body_or_done_and_keep_header_spelling() {
        use std::io::Read;
        for finish_on_body in [true, false] {
            let mut module = Downstream::default();
            let mut request = RequestHeader::build("GET", b"/", None).unwrap();
            request.insert_header("accept-encoding", "br").unwrap();
            let mut response = ResponseHeader::build(200, None).unwrap();
            response
                .insert_header("content-type", "Application/Json; charset=UTF-8")
                .unwrap();
            response.insert_header("etag", "\"strong\"").unwrap();
            module
                .prepare(&request, &mut response, &CompressionPolicy::default())
                .unwrap();
            module
                .response_header_filter(&mut response, false)
                .await
                .unwrap();
            assert_eq!(
                response.headers["content-type"],
                "Application/Json; charset=UTF-8"
            );
            assert_eq!(response.headers["content-encoding"], "br");
            assert_eq!(response.headers["etag"], "W/\"strong\"");
            let input = b"streamed compression regression ".repeat(300);
            let mut encoded = vec![];
            for (index, part) in input.chunks(512).enumerate() {
                let mut chunk = Some(Bytes::copy_from_slice(part));
                let end = finish_on_body && (index + 1) * 512 >= input.len();
                module.response_body_filter(&mut chunk, end).unwrap();
                encoded.extend_from_slice(&chunk.unwrap_or_default());
            }
            if let Some(last) = module.response_done_filter().unwrap() {
                encoded.extend_from_slice(&last);
            }
            let mut decoded = vec![];
            brotli::Decompressor::new(encoded.as_slice(), 4096)
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, input);
            assert!(module.response_done_filter().unwrap().is_none());
        }
    }
    #[test]
    fn policy_and_response_eligibility_are_bounded() {
        let policy = CompressionPolicy::default();
        policy.validate().unwrap();
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .insert_header("Content-Type", "Application/Problem+Json; charset=UTF-8")
            .unwrap();
        response.insert_header("Content-Length", "2048").unwrap();
        assert!(eligible(&request, &response, &policy).is_some());
        for name in ["cookie", "authorization", "range", "if-range", "upgrade"] {
            request.insert_header(name, "x").unwrap();
            assert!(eligible(&request, &response, &policy).is_none());
            request.remove_header(name);
        }
        for name in ["content-encoding", "content-range", "set-cookie"] {
            response.insert_header(name, "x").unwrap();
            assert!(eligible(&request, &response, &policy).is_none());
            response.remove_header(name);
        }
        for mime in [
            "image/png",
            "application/zip",
            "application/octet-stream",
            "text/event-stream",
            "audio/mpeg",
            "font/woff2",
        ] {
            response.insert_header("content-type", mime).unwrap();
            assert!(eligible(&request, &response, &policy).is_none());
        }
        response
            .insert_header("content-type", "text/plain")
            .unwrap();
        response
            .insert_header("cache-control", "public, no-transform")
            .unwrap();
        assert!(eligible(&request, &response, &policy).is_none());
        response.remove_header("cache-control");
        response.insert_header("content-length", "10").unwrap();
        assert!(eligible(&request, &response, &policy).is_none());
        response.remove_header("content-length");
        assert!(eligible(&request, &response, &policy).is_some());
        let mut bad = policy.clone();
        bad.level = 7;
        assert!(bad.validate().is_err());
        bad.level = 4;
        bad.min_bytes = 0;
        assert!(bad.validate().is_err());
    }
}
