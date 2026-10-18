# Repository and CI

[Documentation index](README.md) · [EmberGate overview](../README.md)

## GitHub repository

**Application license:** pending the project owner's selection. No root license has been assigned to EmberGate's own code. Pingora retains its existing Apache 2.0 license; see [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md). Select the application license before public release.

The repository keeps EmberGate at the top level and pins unmodified Cloudflare Pingora as the `pingora/` Git submodule. Clone with submodules as described above. Commit `gateway/Cargo.lock`, `.gitmodules`, and the Pingora submodule pointer along with application changes. Runtime state, environment files, private keys, exported backups, build outputs, and local tooling directories are excluded by `.gitignore`. Keep deployment secrets in private environment/service configuration or the dashboard, never in repository files.

GitHub Actions runs formatting, Rust tests/builds, dashboard checks, local integration suites, browser interactions, Compose configuration validation, and a container image build on pushes and pull requests. Browser screenshots are retained as workflow artifacts. The workflow does not publish images or deploy anything. Pebble DNS-01 tests and live Cloudflare/Let’s Encrypt checks require separate setup and are excluded from CI. A successful workflow run is still required after the first push; adding CI does not establish that the container or hosted runner checks have passed.

The repository is hosted at [karlocizma/EmberGate](https://github.com/karlocizma/EmberGate). Clone it with:

```sh
git clone --recurse-submodules https://github.com/karlocizma/EmberGate.git
cd EmberGate
```

For an existing checkout, initialize the framework with `git submodule update --init --recursive`. Contributions and subsequent changes can be reviewed with `git diff` before committing and pushing.

The repository was created as private. Enable private vulnerability reporting before making it public. Contribution guidelines and issue/PR templates are included. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) for Pingora attribution and dependency notices.
