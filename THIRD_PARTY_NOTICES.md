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

The license of Pingora does not by itself license EmberGate's own application
code. See the root LICENSE file when one has been selected by the project owner.
