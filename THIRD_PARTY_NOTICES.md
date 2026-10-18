# Third-party notices

EmberGate is built with [Pingora](https://github.com/cloudflare/pingora), the Rust
framework developed by Cloudflare. EmberGate is an independent project and is
not an official Cloudflare product.

Pingora is included as an unmodified Git submodule at
`4487f7b2ab50f159e4a2cf4f6a6b813f61bb6e19`. Its source and license notices remain
in `pingora/`, including [the upstream Apache 2.0 license](pingora/LICENSE).
The Git submodule entry records the authoritative revision; update this notice
when intentionally upgrading that revision.

Other Rust dependencies are resolved in `gateway/Cargo.lock` and retain their
respective licenses. A release distributor should review the dependencies and
preserve their required notices when distributing source or compiled binaries.

EmberGate's own application code is licensed separately under
[Apache 2.0](LICENSE). See the root [NOTICE](NOTICE) for EmberGate's copyright
and attribution statement. Third-party components retain their own notices.
