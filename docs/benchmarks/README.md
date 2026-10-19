# Local release load measurement

Measured on 2026-10-19 with Rust 1.99.0 in release mode, an AMD Ryzen 7 5800X3D (16 logical CPUs), and Linux. The tested application source is commit `9ee971f`; the report records the exact binary SHA-256. Subsequent guide wording changes do not change the proxy implementation.

From `gateway/`:

```sh
cargo build --locked --release
python3 tests/load-check.py --seconds 120 --concurrency 8 --binary target/release/embergate --output ../docs/benchmarks/release-local.json
```

Eight persistent HTTP clients and a Python origin run on the same machine over loopback. Each phase lasts 120 seconds and verifies the complete 5,248-byte response body. There is no TLS or external authentication in this measurement. The fixture body compresses particularly well.

| Mode | Requests | Requests/second | p50 / p95 / p99 latency, ms | Origin requests |
| --- | ---: | ---: | --- | ---: |
| Uncached | 552,807 | 4,606.67 | 1.677 / 2.743 / 3.321 | 552,807 |
| Cached | 1,061,497 | 8,845.65 | 0.560 / 2.482 / 7.619 | 2 |
| Cached gzip | 822,440 | 6,853.54 | 1.060 / 2.240 / 2.942 | 2 |

All 2,436,744 requests passed body/status validation with zero errors. Both cache phases served more than 99.99% hits, including initial fills. Gzip reduced the transmitted response body to 115 bytes. Percentiles use a per-client uniform reservoir of up to 25,000 samples, 200,000 samples per phase.

Gateway RSS rose from the initial 60.3 MiB sample to a 68.6 MiB peak. The in-flight response completed after SIGTERM and the process exited normally with status 0 after 300.013 seconds. The [machine-readable report](release-local.json) contains per-phase RSS, cache counts, the binary hash, and shutdown results. The tool waits for Pingora's default five-minute graceful-shutdown period after traffic.

This is a reproducible development check, not a capacity guarantee or a memory-leak proof. Client/origin CPU, body compressibility, HTTP version, TLS, policies, duration, and deployment hardware affect results. Builds and container checks ran only after all three traffic phases finished.
