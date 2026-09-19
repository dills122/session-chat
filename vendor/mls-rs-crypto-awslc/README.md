# Local dependency patch: mls-rs-crypto-awslc 0.25.0

This directory copies the published `mls-rs-crypto-awslc` 0.25.0 crate
(crates.io checksum
`858ba8df345ebbda20868b503fda4fb46a921ca0e035025cbbaed0c8b5245da0`).
Its `src/`, `tests/`, and `test_data/` files are unchanged. The normalized
`Cargo.toml` changes only these dependency pins:

- `aws-lc-rs`: `=1.16.3` to `=1.18.1`
- `aws-lc-sys`: `=0.40.0` to `=0.45.0`

Upstream 0.25.0 pins the older AWS-LC pair. That prevents Cargo from selecting
`rustls` 0.23.45, the first fixed release for RUSTSEC-2026-0285. ADR 0036
records this exception and its removal condition. Do not change provider code
here as part of routine dependency updates; replace this patch with an upstream
release after its graph and cross-platform behavior pass review.

The upstream crate is licensed under Apache-2.0 OR MIT. Its license texts are
included beside this file.
