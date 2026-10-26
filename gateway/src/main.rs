mod access_log;
mod accounts;
mod acme;
mod alerts;
mod analytics;
mod api;
mod backup;
mod cache;
mod captcha;
mod certificates;
mod cloudflare;
mod cluster;
mod compression;
mod config;
mod crowdsec;
mod diagnostics;
mod dns;
mod docker;
mod documentation;
mod forward_auth;
mod grpc;
mod history;
mod management;
mod mfa;
mod oidc;
mod pages;
mod passkeys;
mod policy;
mod prometheus;
mod proxy;
mod rate_limit;
mod routing;
mod scheduled;
mod serialize;
mod state;
mod templates;
mod timing;
mod tokens;
mod trust;
mod upstreams;

use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use pingora::{prelude::*, services::background::background_service};
use rand_core::OsRng;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Warnings carry the reasons for failed sign-ins and certificate renewals.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let password = std::env::var("GATEWAY_ADMIN_PASSWORD")
        .ok()
        .filter(|p| !p.is_empty());
    let hash = |password: &str| -> Result<String, Box<dyn std::error::Error>> {
        management::password(password)?;
        Ok(Argon2::default()
            .hash_password(password.as_bytes(), &SaltString::generate(&mut OsRng))
            .map_err(|e| std::io::Error::other(e.to_string()))?
            .to_string())
    };
    let password_hash = password.as_deref().map(hash).transpose()?;
    let dummy_password_hash = hash(&uuid::Uuid::new_v4().to_string())?;
    let data_dir =
        PathBuf::from(std::env::var("GATEWAY_DATA_DIR").unwrap_or_else(|_| "data".into()));
    std::fs::create_dir_all(&data_dir)?;
    let _data_lock = backup::lock_data(&data_dir)?;
    cluster::recover(&data_dir)?;
    backup::apply_pending(&data_dir)?;
    let config_path = data_dir.join("routes.json");
    let config = config::Config::load(&config_path)?;
    let certificates_path = data_dir.join("certificates.json");
    let certificates = certificates::CertificateStore::load(&certificates_path)?;
    let control = management::Control::open(&data_dir.join("management.sqlite3"))?;
    if let Some(hash) = &password_hash {
        control.seed_admin(hash)?;
    }
    let setup_token = if control.admin_exists()? {
        None
    } else {
        Some(uuid::Uuid::new_v4().to_string())
    };
    let dns = match control.secret("dns_provider")? {
        Some(value) => Some(
            serde_json::from_str(&value).map_err(|_| "Invalid saved DNS provider credentials.")?,
        ),
        None => control
            .secret("cloudflare_token")?
            .map(dns::Settings::cloudflare),
    };
    let acme = acme::Acme::load(&data_dir, dns)?;
    let proxy_addr =
        std::env::var("GATEWAY_PROXY_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let admin_addr =
        std::env::var("GATEWAY_ADMIN_ADDR").unwrap_or_else(|_| "127.0.0.1:9090".into());
    let https_addr = std::env::var("GATEWAY_HTTPS_ADDR")
        .ok()
        .filter(|addr| !addr.is_empty());
    // Require concrete socket addresses so dashboard status matches the listeners.
    proxy_addr.parse::<std::net::SocketAddr>()?;
    admin_addr.parse::<std::net::SocketAddr>()?;
    if let Some(addr) = &https_addr {
        addr.parse::<std::net::SocketAddr>()?;
    }
    let listener = std::net::TcpListener::bind(&admin_addr)?;
    listener.set_nonblocking(true)?;
    let http_cache = Box::leak(Box::new(cache::ResponseCache::default()));
    http_cache.sync_config(&config);
    let analytics = analytics::Analytics::open(&data_dir.join("analytics.sqlite3"))?;
    let mut metrics = state::Metrics::default();
    metrics.prometheus.configure(&config);
    let state = Arc::new(state::AppState {
        backups: backup::Manager::default(),
        http_cache,
        analytics,
        rate_limits: rate_limit::RateLimits::default(),
        crowdsec: {
            let bouncer = crowdsec::Bouncer::default();
            bouncer
                .remediation
                .store(Arc::new(captcha::load(&control)?));
            bouncer
        },
        trust: trust::load_secret(&control)?,
        oidc: oidc::Oidc::load(&control)?,
        access_log: access_log::AccessLogFile::start(
            std::env::var_os("GATEWAY_ACCESS_LOG_DIR")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| data_dir.join("access-log")),
            access_log::initially_enabled(&control)?,
        )?,
        docker: docker::Endpoint::from_env(),
        upstreams: upstreams::Upstreams::default(),
        session_locks: serialize::SessionLocks::default(),
        config: arc_swap::ArcSwap::from_pointee(config),
        certificates: arc_swap::ArcSwap::from_pointee(certificates),
        certificates_path,
        acme,
        write_lock: tokio::sync::Mutex::new(()),
        metrics: Mutex::new(metrics),
        sessions: Mutex::new(HashMap::new()),
        login_attempts: Mutex::new(HashMap::new()),
        control,
        account_write_lock: tokio::sync::Mutex::new(()),
        password_hash,
        dummy_password_hash,
        setup_token: setup_token.clone(),
        config_path,
        proxy_addr: proxy_addr.clone(),
        admin_addr: admin_addr.clone(),
        https_addr: https_addr.clone(),
        secure_cookie: std::env::var("GATEWAY_SECURE_COOKIE").as_deref() == Ok("true"),
        started: Instant::now(),
    });
    cluster::initialize(&state)?;
    // Container replacement must not wait through Pingora's default five-minute drain.
    let mut server = Server::new_with_opt_and_conf(
        None,
        pingora::server::configuration::ServerConf {
            grace_period_seconds: Some(5),
            graceful_shutdown_timeout_seconds: Some(2),
            ..Default::default()
        },
    );
    server.bootstrap();
    let mut proxy = http_proxy_service(&server.configuration, proxy::Gateway(state.clone()));
    // Detect the H2 prior-knowledge preface while keeping ordinary HTTP/1.1 on this listener.
    proxy.app_logic_mut().unwrap().server_options = Some({
        let mut options = pingora::apps::HttpServerOptions::default();
        options.h2c = true;
        options
    });
    proxy.add_tcp(&proxy_addr);
    if let Some(addr) = &https_addr {
        let mut tls = pingora::listeners::tls::TlsSettings::with_callbacks(Box::new(
            certificates::DynamicCertificates(state.clone()),
        ))?;
        tls.enable_h2();
        proxy.add_tls_with_settings(addr, None, tls);
    }
    server.add_service(proxy);
    server.add_service(background_service(
        "instance synchronization",
        cluster::Synchronizer(state.clone()),
    ));
    server.add_service(background_service(
        "upstream health checks",
        upstreams::HealthMonitor(state.clone()),
    ));
    server.add_service(background_service(
        "certificate automation",
        acme::CertificateAutomation(state.clone()),
    ));
    server.add_service(background_service(
        "scheduled backups",
        scheduled::Scheduler(state.clone()),
    ));
    server.add_service(background_service(
        "alerts",
        alerts::Monitor(state.clone(), alerts::webhook()?),
    ));
    server.add_service(background_service(
        "CrowdSec decision sync",
        crowdsec::Synchronizer(state.clone()),
    ));
    server.add_service(background_service(
        "management",
        api::Management {
            state,
            listener: Mutex::new(Some(listener)),
        },
    ));
    println!("EmberGate dashboard: http://{admin_addr}\nProxy listener: http://{proxy_addr}");
    if let Some(addr) = &https_addr {
        println!("HTTPS listener: https://{addr} (upload matching certificates in the dashboard)");
    }
    if let Some(code) = setup_token {
        println!("EmberGate first-run setup: open the dashboard and enter this one-time setup code: {code}");
    }
    server.run_forever();
}
