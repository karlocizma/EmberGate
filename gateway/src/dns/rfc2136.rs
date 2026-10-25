//! RFC 2136 dynamic DNS updates signed with TSIG (RFC 8945), over TCP.
use super::{closest_zone, ChallengeRecord, Settings};
use openssl::{hash::MessageDigest, memcmp, pkey::PKey, sign::Signer};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TXT: u16 = 16;
const SOA: u16 = 6;
const TSIG: u16 = 250;
const IN: u16 = 1;
const NONE: u16 = 254;
const ANY: u16 = 255;
const FUDGE: u16 = 300;
const TTL: u32 = 60;

pub struct Rfc2136 {
    pub settings: Settings,
    zones: Vec<String>,
    key_name: Vec<u8>,
    algorithm: (&'static str, MessageDigest),
    secret: Vec<u8>,
}

/// Encodes a domain name in wire format, lowercased for TSIG canonical form.
fn name(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim_end_matches('.');
    let mut wire = Vec::new();
    for label in value.split('.').filter(|label| !label.is_empty()) {
        if label.len() > 63 {
            return Err(format!("{value} has a label longer than 63 characters."));
        }
        wire.push(label.len() as u8);
        wire.extend(label.to_ascii_lowercase().bytes());
    }
    wire.push(0);
    if wire.len() > 255 {
        return Err(format!("{value} is too long for DNS."));
    }
    Ok(wire)
}

fn valid_name(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|label| {
            !label.is_empty()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        })
        && name(value).is_ok()
}

impl Rfc2136 {
    pub fn new(settings: Settings) -> Result<Self, String> {
        let zones: Vec<String> = settings
            .get("zones")
            .split(',')
            .map(|zone| zone.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|zone| !zone.is_empty())
            .collect();
        if zones.is_empty() || zones.len() > 50 || !zones.iter().all(|zone| valid_name(zone)) {
            return Err("Enter up to 50 zone names separated by commas, for example example.com,example.org.".into());
        }
        let key_name = settings.get("key_name").trim_end_matches('.');
        if !valid_name(key_name) {
            return Err("Enter the TSIG key name as configured on the DNS server.".into());
        }
        let algorithm = match settings.get("algorithm").to_ascii_lowercase().as_str() {
            "hmac-sha256" => ("hmac-sha256", MessageDigest::sha256()),
            "hmac-sha512" => ("hmac-sha512", MessageDigest::sha512()),
            _ => return Err("Use the hmac-sha256 or hmac-sha512 TSIG algorithm.".into()),
        };
        let secret = openssl::base64::decode_block(settings.get("secret"))
            .ok()
            .filter(|secret| secret.len() >= 16)
            .ok_or("Enter the TSIG secret in base64, at least 16 bytes long.")?;
        Self::address(settings.get("server"))?;
        Ok(Self {
            key_name: name(key_name)?,
            zones,
            algorithm,
            secret,
            settings,
        })
    }
    /// Splits `host`, `host:port`, or `[v6]:port`.
    fn address(server: &str) -> Result<(String, u16), String> {
        let invalid = || "Enter the DNS server as host or host:port.".to_owned();
        if let Ok(address) = server.parse::<std::net::SocketAddr>() {
            return Ok((address.ip().to_string(), address.port()));
        }
        if let Ok(address) = server.parse::<std::net::IpAddr>() {
            return Ok((address.to_string(), 53));
        }
        let (host, port) = match server.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().map_err(|_| invalid())?),
            None => (server, 53),
        };
        if !valid_name(host) || port == 0 {
            return Err(invalid());
        }
        Ok((host.to_owned(), port))
    }
    pub fn zone_for(&self, domain: &str) -> Result<String, String> {
        let domain = domain.strip_prefix("*.").unwrap_or(domain);
        closest_zone(
            &format!("_acme-challenge.{domain}"),
            self.zones.iter().map(String::as_str),
        )
        .map(str::to_owned)
        .ok_or_else(|| format!("{domain} is not in the zones configured for RFC 2136 updates."))
    }
    fn mac(&self, parts: &[&[u8]]) -> Result<Vec<u8>, String> {
        let key = PKey::hmac(&self.secret).map_err(|_| "Invalid TSIG secret.")?;
        let mut signer =
            Signer::new(self.algorithm.1, &key).map_err(|_| "Could not sign the DNS update.")?;
        for part in parts {
            signer
                .update(part)
                .map_err(|_| "Could not sign the DNS update.")?;
        }
        signer
            .sign_to_vec()
            .map_err(|_| "Could not sign the DNS update.".into())
    }
    /// TSIG variables (RFC 8945 §4.3.3) for the given time.
    fn variables(&self, time: u64) -> Result<Vec<u8>, String> {
        let mut out = self.key_name.clone();
        out.extend(ANY.to_be_bytes());
        out.extend(0u32.to_be_bytes());
        out.extend(name(self.algorithm.0)?);
        out.extend(&time.to_be_bytes()[2..]);
        out.extend(FUDGE.to_be_bytes());
        out.extend(0u16.to_be_bytes()); // error
        out.extend(0u16.to_be_bytes()); // other length
        Ok(out)
    }
    /// Builds a signed UPDATE that adds (`class` IN) or deletes (`class` NONE) one TXT value.
    fn message(
        &self,
        record: &ChallengeRecord,
        class: u16,
        id: u16,
        time: u64,
    ) -> Result<(Vec<u8>, Vec<u8>), String> {
        if record.value.len() > 255 {
            return Err("Challenge value is too long.".into());
        }
        let mut message = Vec::new();
        message.extend(id.to_be_bytes());
        message.extend(0x2800u16.to_be_bytes()); // opcode UPDATE
        for count in [1u16, 0, 1, 0] {
            message.extend(count.to_be_bytes());
        }
        message.extend(name(&record.zone)?);
        message.extend(SOA.to_be_bytes());
        message.extend(IN.to_be_bytes());
        message.extend(name(&record.name)?);
        message.extend(TXT.to_be_bytes());
        message.extend(class.to_be_bytes());
        message.extend(if class == IN { TTL } else { 0 }.to_be_bytes());
        message.extend((record.value.len() as u16 + 1).to_be_bytes());
        message.push(record.value.len() as u8);
        message.extend(record.value.bytes());

        let mac = self.mac(&[&message, &self.variables(time)?])?;
        let mut rdata = name(self.algorithm.0)?;
        rdata.extend(&time.to_be_bytes()[2..]);
        rdata.extend(FUDGE.to_be_bytes());
        rdata.extend((mac.len() as u16).to_be_bytes());
        rdata.extend(&mac);
        rdata.extend(id.to_be_bytes());
        rdata.extend(0u16.to_be_bytes());
        rdata.extend(0u16.to_be_bytes());
        message.extend(&self.key_name);
        message.extend(TSIG.to_be_bytes());
        message.extend(ANY.to_be_bytes());
        message.extend(0u32.to_be_bytes());
        message.extend((rdata.len() as u16).to_be_bytes());
        message.extend(rdata);
        message[10..12].copy_from_slice(&1u16.to_be_bytes());
        Ok((message, mac))
    }
    /// Checks the server's TSIG signature over its response (RFC 8945 §5.3).
    fn verify(&self, response: &[u8], id: u16, request_mac: &[u8]) -> Result<(), String> {
        let invalid = || "The DNS server's response signature is invalid.".to_owned();
        let start = last_record(response).ok_or_else(invalid)?;
        let mut cursor = skip_name(response, start).ok_or_else(invalid)?;
        let field = |at: usize, len: usize| response.get(at..at + len).ok_or_else(invalid);
        if u16::from_be_bytes(field(cursor, 2)?.try_into().unwrap()) != TSIG {
            return Err(
                "The DNS server did not sign its response. Check the key on the server.".into(),
            );
        }
        cursor += 10;
        let algorithm_end = skip_name(response, cursor).ok_or_else(invalid)?;
        if response[cursor..algorithm_end] != name(self.algorithm.0)? {
            return Err(invalid());
        }
        cursor = algorithm_end;
        let time = field(cursor, 6)?;
        let fudge = field(cursor + 6, 2)?;
        let mac_len = u16::from_be_bytes(field(cursor + 8, 2)?.try_into().unwrap()) as usize;
        let mac = field(cursor + 10, mac_len)?;
        cursor += 10 + mac_len;
        if u16::from_be_bytes(field(cursor, 2)?.try_into().unwrap()) != id {
            return Err(invalid());
        }
        let error = field(cursor + 2, 4)?;
        let other_len = u16::from_be_bytes(error[2..4].try_into().unwrap()) as usize;
        let other = field(cursor + 6, other_len)?;
        let mut unsigned = response[..start].to_vec();
        let count = u16::from_be_bytes(unsigned[10..12].try_into().unwrap());
        unsigned[10..12].copy_from_slice(&count.saturating_sub(1).to_be_bytes());
        let mut variables = self.key_name.clone();
        variables.extend(ANY.to_be_bytes());
        variables.extend(0u32.to_be_bytes());
        variables.extend(name(self.algorithm.0)?);
        variables.extend(time);
        variables.extend(fudge);
        variables.extend(error);
        variables.extend(other);
        let expected = self.mac(&[
            &(request_mac.len() as u16).to_be_bytes(),
            request_mac,
            &unsigned,
            &variables,
        ])?;
        if mac.len() != expected.len() || !memcmp::eq(mac, &expected) {
            return Err(invalid());
        }
        Ok(())
    }
    async fn update(&self, record: &ChallengeRecord, class: u16) -> Result<(), String> {
        let id = u16::from_be_bytes(*uuid::Uuid::new_v4().as_bytes().first_chunk().unwrap());
        let time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |t| t.as_secs());
        let (message, mac) = self.message(record, class, id, time)?;
        let (host, port) = Self::address(self.settings.get("server"))?;
        let unreachable = || {
            format!(
                "Could not reach the DNS server {}.",
                self.settings.get("server")
            )
        };
        let response = tokio::time::timeout(Duration::from_secs(20), async {
            let mut stream = tokio::net::TcpStream::connect((host.as_str(), port))
                .await
                .map_err(|_| unreachable())?;
            let mut framed = (message.len() as u16).to_be_bytes().to_vec();
            framed.extend(&message);
            stream.write_all(&framed).await.map_err(|_| unreachable())?;
            let length = stream.read_u16().await.map_err(|_| unreachable())? as usize;
            let mut response = vec![0; length];
            stream
                .read_exact(&mut response)
                .await
                .map_err(|_| unreachable())?;
            Ok::<_, String>(response)
        })
        .await
        .map_err(|_| unreachable())??;
        if response.len() < 12 || response[..2] != id.to_be_bytes() || response[2] & 0x80 == 0 {
            return Err("The DNS server sent an invalid response.".into());
        }
        let rcode = response[3] & 0x0f;
        if rcode != 0 {
            return Err(match rcode {
                5 => "The DNS server refused the update. Allow this TSIG key to update TXT records in the zone.".into(),
                9 => "The DNS server did not accept the TSIG key. Check the key name, algorithm, secret, and the gateway's clock.".into(),
                10 => format!("{} is not in a zone the DNS server is primary for.", record.name),
                code => format!("The DNS server rejected the update (response code {code})."),
            });
        }
        self.verify(&response, id, &mac)
    }
    pub async fn present(&self, record: &ChallengeRecord) -> Result<(), String> {
        self.update(record, IN).await
    }
    /// Deletes exactly this TXT value; other values under the name stay.
    pub async fn cleanup(&self, record: &ChallengeRecord) -> Result<(), String> {
        self.update(record, NONE).await
    }
}

/// Offset just past a possibly compressed name at `at`.
fn skip_name(message: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let length = *message.get(at)?;
        match length {
            0 => return Some(at + 1),
            length if length & 0xc0 == 0xc0 => {
                return Some(at + 2).filter(|end| *end <= message.len())
            }
            length if length < 64 => at += 1 + length as usize,
            _ => return None,
        }
    }
}

/// Offset of the last resource record, where a TSIG record must be.
fn last_record(message: &[u8]) -> Option<usize> {
    let count =
        |at: usize| Some(u16::from_be_bytes(message.get(at..at + 2)?.try_into().ok()?) as usize);
    let questions = count(4)?;
    let records = count(6)? + count(8)? + count(10)?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(message, at)? + 4;
    }
    let mut last = None;
    for _ in 0..records {
        last = Some(at);
        let end = skip_name(message, at)?;
        at = end + 10 + count(end + 8)?;
    }
    (at == message.len()).then_some(last).flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(server: &str) -> Rfc2136 {
        Rfc2136::new(Settings {
            provider: "rfc2136".into(),
            credentials: [
                ("server", server),
                ("zones", "example.com, sub.example.com."),
                ("key_name", "embergate."),
                ("algorithm", "hmac-sha256"),
                ("secret", "c2VjcmV0LWtleS1mb3ItdGVzdGluZy0xMjM0NTY="),
            ]
            .iter()
            .map(|(k, v)| ((*k).into(), (*v).into()))
            .collect(),
        })
        .unwrap()
    }

    #[test]
    fn configuration_is_checked() {
        let dns = provider("192.0.2.1");
        assert_eq!(
            dns.zone_for("*.a.sub.example.com").unwrap(),
            "sub.example.com"
        );
        assert!(dns.zone_for("example.org").is_err());
        assert_eq!(
            Rfc2136::address("ns1.example.com:5353").unwrap(),
            ("ns1.example.com".into(), 5353)
        );
        assert_eq!(
            Rfc2136::address("[2001:db8::1]:53").unwrap().0,
            "2001:db8::1"
        );
        assert_eq!(Rfc2136::address("2001:db8::1").unwrap().1, 53);
        assert!(Rfc2136::address("bad host").is_err());
        let mut short = dns.settings.clone();
        short.credentials.insert("secret".into(), "c2hvcnQ=".into());
        assert!(Rfc2136::new(short).is_err());
    }

    #[test]
    fn signed_message_verifies_like_a_server_would() {
        let dns = provider("192.0.2.1");
        let record = ChallengeRecord {
            zone: "example.com".into(),
            name: "_acme-challenge.www.example.com".into(),
            value: "value".into(),
            comment: String::new(),
        };
        let (message, mac) = dns.message(&record, IN, 7, 1_700_000_000).unwrap();
        // A response is the request header echoed with QR set, signed over the request MAC.
        let mut response = message[..message.len()].to_vec();
        let start = last_record(&response).unwrap();
        response.truncate(start);
        response[2] |= 0x80;
        response[10..12].copy_from_slice(&0u16.to_be_bytes());
        let mut variables = dns.key_name.clone();
        variables.extend(ANY.to_be_bytes());
        variables.extend(0u32.to_be_bytes());
        variables.extend(name("hmac-sha256").unwrap());
        variables.extend(&1_700_000_000u64.to_be_bytes()[2..]);
        variables.extend(FUDGE.to_be_bytes());
        variables.extend([0, 0, 0, 0]);
        let signature = dns
            .mac(&[
                &(mac.len() as u16).to_be_bytes(),
                &mac,
                &response,
                &variables,
            ])
            .unwrap();
        let mut rdata = name("hmac-sha256").unwrap();
        rdata.extend(&1_700_000_000u64.to_be_bytes()[2..]);
        rdata.extend(FUDGE.to_be_bytes());
        rdata.extend((signature.len() as u16).to_be_bytes());
        rdata.extend(&signature);
        rdata.extend(7u16.to_be_bytes());
        rdata.extend([0, 0, 0, 0]);
        let mut signed = response.clone();
        signed.extend(&dns.key_name);
        signed.extend(TSIG.to_be_bytes());
        signed.extend(ANY.to_be_bytes());
        signed.extend(0u32.to_be_bytes());
        signed.extend((rdata.len() as u16).to_be_bytes());
        signed.extend(&rdata);
        signed[10..12].copy_from_slice(&1u16.to_be_bytes());
        dns.verify(&signed, 7, &mac).unwrap();
        let mut tampered = signed.clone();
        tampered[3] ^= 0x01;
        assert!(dns.verify(&tampered, 7, &mac).is_err());
        assert!(dns.verify(&signed, 8, &mac).is_err());
        assert!(dns.verify(&response, 7, &mac).is_err());
    }

    /// Runs against a real server: `EMBERGATE_RFC2136_SERVER=127.0.0.1:5399`
    /// with zone example.com and the key above (see docs/testing.md).
    #[tokio::test]
    #[ignore]
    async fn updates_a_real_server() {
        let server = std::env::var("EMBERGATE_RFC2136_SERVER").unwrap();
        let dns = provider(&server);
        let record = ChallengeRecord {
            zone: dns.zone_for("www.example.com").unwrap(),
            name: "_acme-challenge.www.example.com".into(),
            value: "embergate-value".into(),
            comment: String::new(),
        };
        dns.present(&record).await.unwrap();
        dns.cleanup(&record).await.unwrap();
        let mut wrong = dns.settings.clone();
        wrong.credentials.insert(
            "secret".into(),
            "d3Jvbmctc2VjcmV0LWtleS0xMjM0NTY3OA==".into(),
        );
        let error = Rfc2136::new(wrong)
            .unwrap()
            .present(&record)
            .await
            .unwrap_err();
        assert!(error.contains("TSIG key"), "{error}");
        let outside = ChallengeRecord {
            zone: "example.org".into(),
            name: "_acme-challenge.example.org".into(),
            ..record
        };
        assert!(dns.present(&outside).await.is_err());
    }
}
