# Contributing to EmberGate

EmberGate application code is in `gateway/`. The `pingora/` directory is a pinned
Git submodule of Cloudflare's upstream framework. Keep application changes in
EmberGate; propose framework changes upstream separately.

Clone with `git clone --recurse-submodules <repository-url>`. For an existing
checkout, run `git submodule update --init --recursive`. See [README.md](README.md)
for native dependencies, first-run setup, architecture, and feature behavior.

Before opening a pull request, run from `gateway/`:

```sh
cargo fmt --check
cargo test --locked
cargo build --locked
npm test
npm run check
python3 tests/proxy-smoke.py
```

Run the relevant integration suites listed under **Checks** in the README for
behavior changes. Dashboard changes should also pass `npm run test:browser` with
`BROWSER_BIN` pointing to an installed Chromium browser. Python compression tests
need the `brotli` module, and HTTP/2 checks need an HTTP/2-enabled curl. No npm
installation is required. Tests use temporary state and local fixtures; never
point test processes at an existing installation's data directory.

Keep `gateway/Cargo.lock` checked in. Describe the problem, resulting behavior,
and checks in the pull request. Add a regression check when changing important
proxy, persistence, authentication, or certificate behavior. Update the README
and roadmap when user-facing behavior or planned work changes.

Do not include runtime databases, certificate keys, exported backups, tokens,
passwords, or logs containing private data in commits or issue reports. See
[SECURITY.md](SECURITY.md) for vulnerability reporting.
