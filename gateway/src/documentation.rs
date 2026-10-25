//! Read-only documentation embedded from the same Markdown used on GitHub.
use axum::Json;
use pulldown_cmark::{html, Event, Options, Parser, Tag, TagEnd};
use serde::Serialize;
use std::sync::OnceLock;

const INSTALLATION: &str = include_str!("../../docs/installation.md");
const PROXY: &str = include_str!("../../docs/proxy.md");
const CERTIFICATES: &str = include_str!("../../docs/certificates.md");
const ADMINISTRATION: &str = include_str!("../../docs/administration.md");
const MONITORING: &str = include_str!("../../docs/monitoring.md");
const TROUBLESHOOTING: &str = include_str!("../../docs/troubleshooting.md");

/// Screenshots referenced as `images/<name>.png`, regenerated with
/// `npm run docs:screenshots`.
pub const IMAGES: &[(&str, &[u8])] = &[
    (
        "analytics.png",
        include_bytes!("../../docs/images/analytics.png"),
    ),
    (
        "api-tokens.png",
        include_bytes!("../../docs/images/api-tokens.png"),
    ),
    (
        "containers.png",
        include_bytes!("../../docs/images/containers.png"),
    ),
    (
        "host-editor.png",
        include_bytes!("../../docs/images/host-editor.png"),
    ),
    (
        "host-single-sign-on.png",
        include_bytes!("../../docs/images/host-single-sign-on.png"),
    ),
    ("hosts.png", include_bytes!("../../docs/images/hosts.png")),
    (
        "overview.png",
        include_bytes!("../../docs/images/overview.png"),
    ),
    (
        "single-sign-on.png",
        include_bytes!("../../docs/images/single-sign-on.png"),
    ),
    (
        "threat-protection.png",
        include_bytes!("../../docs/images/threat-protection.png"),
    ),
];

/// Returns the embedded screenshot a Markdown image destination names, if any.
fn local_image(destination: &str) -> Option<&'static str> {
    let name = destination.strip_prefix("images/")?;
    IMAGES
        .iter()
        .find(|(image, _)| *image == name)
        .map(|(image, _)| *image)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[derive(Serialize)]
pub struct Heading {
    pub id: String,
    pub title: String,
}
#[derive(Serialize)]
pub struct Guide {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub html: String,
    pub text: String,
    pub headings: Vec<Heading>,
}
#[derive(Serialize)]
pub struct Documentation {
    pub version: &'static str,
    pub guides: Vec<Guide>,
}

fn slug(text: &str) -> String {
    text.to_lowercase()
        .chars()
        .filter_map(|c| match c {
            ' ' => Some('-'),
            c if c.is_ascii_alphanumeric() || c == '-' => Some(c),
            _ => None,
        })
        .collect()
}

fn admin_topic(anchor: &str) -> &'static str {
    match anchor {
        "accounts-and-audit-trail"
        | "two-factor-authentication"
        | "passkeys"
        | "api-tokens"
        | "dashboard-single-sign-on"
        | "crowdsec-threat-protection" => "security",
        "scheduled-encrypted-backups" | "full-backup-and-restore" => "backups",
        _ => "administration",
    }
}

fn link(destination: &str, topic: &str) -> String {
    if destination.starts_with("https://") || destination.starts_with("http://") {
        return destination.to_owned();
    }
    let (path, anchor) = destination.split_once('#').unwrap_or((destination, ""));
    let mapped = match path {
        "" => topic,
        "installation.md" => "getting-started",
        "proxy.md" => "proxy-hosts",
        "certificates.md" => "certificates",
        "administration.md" => admin_topic(anchor),
        "monitoring.md" => "monitoring",
        "troubleshooting.md" => "troubleshooting",
        "README.md" | "../README.md" => "getting-started",
        _ => {
            // Only known repository files can become external source links.
            let file = match path {
                "../ROADMAP.md" => "ROADMAP.md",
                "../SECURITY.md" => "SECURITY.md",
                "../CONTRIBUTING.md" => "CONTRIBUTING.md",
                "../THIRD_PARTY_NOTICES.md" => "THIRD_PARTY_NOTICES.md",
                "../pingora/README.md" => "pingora/README.md",
                "../deploy/cluster-compose.yaml" => "deploy/cluster-compose.yaml",
                "../deploy/haproxy.cfg" => "deploy/haproxy.cfg",
                "../deploy/crowdsec-compose.yaml" => "deploy/crowdsec-compose.yaml",
                "../deploy/crowdsec/acquis.yaml" => "deploy/crowdsec/acquis.yaml",
                _ => return format!("#/help/{topic}"),
            };
            return format!("https://github.com/karlocizma/EmberGate/blob/main/{file}");
        }
    };
    if anchor.is_empty() {
        format!("#/help/{mapped}")
    } else {
        format!("#/help/{mapped}/{}", slug(anchor))
    }
}

fn render(id: &'static str, title: &'static str, description: &'static str, source: &str) -> Guide {
    let options = Options::ENABLE_TABLES | Options::ENABLE_STRIKETHROUGH;
    let mut headings = Vec::new();
    let mut heading_text = None;
    let mut text = String::new();
    for event in Parser::new_ext(source, options) {
        match event {
            Event::Start(Tag::Heading { .. }) => heading_text = Some(String::new()),
            Event::Text(value) | Event::Code(value) => {
                text.push_str(&value);
                text.push(' ');
                if let Some(heading) = &mut heading_text {
                    heading.push_str(&value);
                }
            }
            Event::End(TagEnd::Heading(_)) => {
                let title = heading_text.take().unwrap_or_default();
                let base = slug(&title);
                let mut anchor = base.clone();
                let mut count = 1;
                while headings.iter().any(|h: &Heading| h.id == anchor) {
                    anchor = format!("{base}-{count}");
                    count += 1;
                }
                headings.push(Heading { id: anchor, title });
            }
            _ => {}
        }
    }
    let mut next_heading = 0;
    // Whether the image being rendered is an embedded screenshot.
    let mut image: Option<bool> = None;
    let events = Parser::new_ext(source, options).map(|event| match event {
        Event::Html(value) | Event::InlineHtml(value) => Event::Text(value),
        Event::Start(Tag::Heading { level, .. }) => {
            let anchor = &headings[next_heading].id;
            next_heading += 1;
            Event::Html(format!("<{level} id=\"help-{id}-{anchor}\" tabindex=\"-1\">").into())
        }
        Event::End(TagEnd::Heading(level)) => Event::Html(format!("</{level}>\n").into()),
        Event::Start(Tag::Link {
            link_type,
            dest_url,
            title,
            id: link_id,
        }) => Event::Start(Tag::Link {
            link_type,
            dest_url: link(&dest_url, id).into(),
            title,
            id: link_id,
        }),
        // Only embedded screenshots load; other images and embedded HTML become text.
        Event::Start(Tag::Image { dest_url, .. }) => match local_image(&dest_url) {
            Some(name) => {
                image = Some(true);
                Event::Html(
                    format!("<img src=\"/docs/images/{name}\" loading=\"lazy\" alt=\"").into(),
                )
            }
            None => {
                image = Some(false);
                Event::Html("<span>".into())
            }
        },
        Event::Text(value) | Event::Code(value) if image == Some(true) => {
            Event::Html(escape(&value).into())
        }
        Event::End(TagEnd::Image) => match image.take() {
            Some(true) => Event::Html("\">".into()),
            _ => Event::Html("</span>".into()),
        },
        event => event,
    });
    let mut output = String::new();
    html::push_html(&mut output, events);
    Guide {
        id,
        title,
        description,
        html: output,
        text,
        headings,
    }
}

fn content(source: &str) -> &str {
    source.splitn(5, '\n').nth(4).unwrap_or(source)
}

fn admin_sections(topic: &str) -> String {
    let mut selected = false;
    let mut result = String::new();
    for line in content(ADMINISTRATION).lines() {
        if let Some(title) = line.strip_prefix("## ") {
            selected = admin_topic(&slug(title)) == topic;
        }
        if selected {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

pub fn embedded() -> &'static Documentation {
    static DOCS: OnceLock<Documentation> = OnceLock::new();
    DOCS.get_or_init(|| Documentation {
        version: env!("CARGO_PKG_VERSION"),
        guides: vec![
            render(
                "getting-started",
                "Getting started",
                "Install EmberGate and route your first request.",
                content(INSTALLATION),
            ),
            render(
                "proxy-hosts",
                "Proxy hosts",
                "Routing, balancing, caching, compression, and traffic policies.",
                content(PROXY),
            ),
            render(
                "certificates",
                "Certificates",
                "HTTPS, Cloudflare DNS challenges, and automatic renewal.",
                content(CERTIFICATES),
            ),
            render(
                "security",
                "Security",
                "Accounts, two-factor sign-in, passkeys, API tokens, single sign-on, and CrowdSec.",
                &admin_sections("security"),
            ),
            render(
                "administration",
                "Settings & configuration",
                "Settings, host templates, configuration, and history.",
                &admin_sections("administration"),
            ),
            render(
                "backups",
                "Backups & restore",
                "Encrypted snapshots, schedules, offsite copies, and recovery.",
                &admin_sections("backups"),
            ),
            render(
                "monitoring",
                "Monitoring",
                "Analytics, diagnostics, Prometheus, and notifications.",
                content(MONITORING),
            ),
            render(
                "troubleshooting",
                "Troubleshooting",
                "Resolve setup, routing, certificate, and backup problems.",
                content(TROUBLESHOOTING),
            ),
        ],
    })
}

pub async fn get() -> Json<&'static Documentation> {
    Json(embedded())
}

pub async fn image(
    axum::extract::Path(name): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};
    match IMAGES.iter().find(|(image, _)| *image == name) {
        Some((_, bytes)) => (
            [
                (header::CONTENT_TYPE, "image/png"),
                (header::CACHE_CONTROL, "public, max-age=3600"),
            ],
            *bytes,
        )
            .into_response(),
        None => axum::http::StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_guides_have_safe_html_and_resolvable_internal_links() {
        let docs = embedded();
        assert_eq!(docs.guides.len(), 8);
        for guide in &docs.guides {
            assert!(!guide.text.is_empty());
            assert!(!guide.headings.is_empty());
            assert!(!guide.html.contains("<script"));
            for part in guide.html.split("href=\"#/help/").skip(1) {
                let route = part.split('"').next().unwrap();
                let (id, anchor) = route.split_once('/').unwrap_or((route, ""));
                let target = docs.guides.iter().find(|g| g.id == id).unwrap();
                assert!(
                    anchor.is_empty() || target.headings.iter().any(|h| h.id == anchor),
                    "{route}"
                );
            }
        }
        // Dashboard links must point at real guide sections.
        for part in include_str!("../web/index.html")
            .split("href=\"#/help/")
            .skip(1)
        {
            let route = part.split('"').next().unwrap();
            let (id, anchor) = route.split_once('/').unwrap_or((route, ""));
            let target = docs.guides.iter().find(|g| g.id == id).expect(route);
            assert!(
                anchor.is_empty() || target.headings.iter().any(|h| h.id == anchor),
                "{route}"
            );
        }
        for (topic, heading) in [
            ("security", "two-factor-authentication"),
            ("security", "api-tokens"),
            ("security", "dashboard-single-sign-on"),
            ("backups", "full-backup-and-restore"),
            ("administration", "configuration"),
        ] {
            assert!(docs
                .guides
                .iter()
                .find(|guide| guide.id == topic)
                .unwrap()
                .headings
                .iter()
                .any(|h| h.id == heading));
        }
    }

    #[test]
    fn markdown_cannot_inject_html_scripts_or_remote_images() {
        let guide = render("test", "Test", "", "## Heading\n\n<script>alert(1)</script>\n\n[x](javascript:alert) ![image](https://example.test/image.png)\n\n| A | B |\n| - | - |\n| 1 | 2 |");
        assert!(!guide.html.contains("<script>"));
        assert!(!guide.html.contains("javascript:"));
        assert!(!guide.html.contains("<img"));
        assert!(guide.html.contains("&lt;script&gt;"));
        assert!(guide.html.contains("<table>"));
        assert!(guide.html.contains("id=\"help-test-heading\""));
    }

    #[test]
    fn only_embedded_screenshots_render_as_images_with_escaped_alt_text() {
        let guide = render("test", "Test", "", "## H\n\n![The \"hosts\" <list>](images/hosts.png) ![x](images/missing.png) ![y](../images/hosts.png)");
        assert!(guide.html.contains(r#"<img src="/docs/images/hosts.png" loading="lazy" alt="The &quot;hosts&quot; &lt;list&gt;">"#), "{}", guide.html);
        assert_eq!(guide.html.matches("<img").count(), 1);
    }

    #[test]
    fn every_screenshot_is_embedded_referenced_and_described() {
        let sources = [
            INSTALLATION,
            PROXY,
            CERTIFICATES,
            ADMINISTRATION,
            MONITORING,
            TROUBLESHOOTING,
        ]
        .concat();
        let on_disk: std::collections::BTreeSet<String> =
            std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/images"))
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_string().unwrap())
                .collect();
        let embedded: std::collections::BTreeSet<String> =
            IMAGES.iter().map(|(name, _)| name.to_string()).collect();
        assert_eq!(on_disk, embedded, "docs/images and IMAGES must match");
        for (name, bytes) in IMAGES {
            assert!(bytes.starts_with(b"\x89PNG"), "{name}");
            let reference = format!("](images/{name})");
            let at = sources
                .find(&reference)
                .unwrap_or_else(|| panic!("{name} is not used in the docs"));
            assert!(!sources[..at].ends_with("!["), "{name} needs alt text");
        }
        for part in sources.split("](images/").skip(1) {
            let name = part.split(')').next().unwrap();
            assert!(embedded.contains(name), "images/{name} is not embedded");
        }
    }
}
