//! Native gRPC detection and trailers-only local failures. No gRPC-Web translation.
use pingora::http::RequestHeader;

pub fn is_grpc(request: &RequestHeader) -> bool {
    let Some(value) = request
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
    else {
        return false;
    };
    let mime = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    mime == "application/grpc" || mime.starts_with("application/grpc+")
}
pub fn status_for_http(status: u16) -> &'static str {
    match status {
        401 => "16",                   // UNAUTHENTICATED
        403 => "7",                    // PERMISSION_DENIED
        404 | 405 | 426 | 501 => "12", // UNIMPLEMENTED
        429 => "8",                    // RESOURCE_EXHAUSTED
        502 | 503 => "14",             // UNAVAILABLE
        504 => "4",                    // DEADLINE_EXCEEDED
        _ => "13",                     // INTERNAL
    }
}
pub fn message(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if (0x20..=0x7e).contains(&byte) && byte != b'%' {
            encoded.push(byte as char);
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_types_exclude_grpc_web_and_prefix_lookalikes() {
        for (mime, expected) in [
            ("application/grpc", true),
            ("Application/Grpc+Proto; charset=utf-8", true),
            ("application/grpc+json", true),
            ("application/grpc-web+proto", false),
            ("application/grpcfake", false),
            ("application/json", false),
        ] {
            let mut request =
                RequestHeader::build("POST", b"/example.Service/Method", None).unwrap();
            request.insert_header("Content-Type", mime).unwrap();
            assert_eq!(is_grpc(&request), expected, "{mime}");
        }
        assert_eq!(message("bad%\n☃"), "bad%25%0A%E2%98%83");
        assert_eq!(status_for_http(403), "7");
        assert_eq!(status_for_http(503), "14");
    }
}
