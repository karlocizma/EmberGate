# Contributing to EmberGate

EmberGate application code is in `gateway/`. The `pingora/` directory is a pinned
Git submodule of Cloudflare's upstream framework. Keep application changes in
EmberGate; propose framework changes upstream separately.

Clone with `git clone --recurse-submodules <repository-url>`. For an existing
checkout, run `git submodule update --init --recursive`. See [README.md](README.md)
for the project overview and [docs/](docs/README.md) for setup and feature guides.

Before opening a pull request, run from `gateway/`:

```sh
cargo fmt --check
cargo test --locked
cargo build --locked
npm test
npm run check
python3 tests/proxy-smoke.py
```

Run the relevant integration suites in the [testing guide](docs/testing.md) for
behavior changes. Dashboard changes should also pass `npm run test:browser` with
`BROWSER_BIN` pointing to an installed Chromium browser. Python compression tests
need the `brotli` module, and HTTP/2 checks need an HTTP/2-enabled curl. No npm
installation is required. Tests use temporary state and local fixtures; never
point test processes at an existing installation's data directory.

Keep `gateway/Cargo.lock` checked in. Describe the problem, resulting behavior,
and checks in the pull request. Add a regression check when changing important
proxy, persistence, authentication, or certificate behavior. Update the README, relevant `docs/` guides,
and roadmap when user-facing behavior or planned work changes. Operational guides
are embedded into in-app Help at compile time; rebuild after changing them.
`gateway/src/documentation.rs` maps shared guides into Help topics. Preserve
section anchors when possible so contextual links and bookmarks keep working.

Do not include runtime databases, certificate keys, exported backups, tokens,
passwords, or logs containing private data in commits or issue reports. See
[SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

EmberGate is licensed under [Apache 2.0](LICENSE). Unless explicitly stated
otherwise, contributions intentionally submitted for inclusion are under that
license, as described in its contribution terms. Preserve third-party notices.
