# Launch policy source checks

This independent Cargo workspace tests Trustee source modules without building
full AS/KBS services or optional TEE/Git backends. Its library points to
`deps/policy-engine/src/lib.rs`; AS/KBS modules are included through `#[path]`.
Tests use MemoryKeyValueStorage, Regorus 0.10.1, and the KBS default resource
policy. PostgreSQL and Redis services are not required.

## Feature profiles

- `capture` checks exact policy/input/data snapshots, strict boolean decisions,
  input bounds, reserved-namespace rejection, and capture-print suppression.
- `launch-session` adds AS quote binding and KBS session transitions. The verifier
  leaf imports `deps/verifier/src/lib.rs`, including its trait and factory, with
  no hardware verifier features. Public quote verification selects TDX and fails
  closed when that backend is unavailable. Positive fixtures use private
  software Verifier implementations.
- `launch-http` adds Actix handlers, recorder proof of possession, bounded bodies,
  resource-policy evaluation, signed aggregates, and client roundtrip/history.
  Actix test services open no listener. The positive roundtrip completes AS
  verification through a private software fixture; public HTTP capture uses
  the TDX factory.
- `launch-credentials` adds ResourceStorage/KvStorage, the KBS JWE library, live
  session checks, and the HTTP credential route. OpenSSL decryption checks the
  ciphertext independently. The JWE library's inline tests are excluded.

The aggregate-to-issuer-to-guest bridge uses captured AS/KBS evaluations, a
software quote fixture, KBS signing, SQLite issuer admission, and
GuestAdmissionGate. It checks exact first/history receipt bytes and foreign
context rejection. Preparation remains unsupported and the bridge invokes no
guest RPCs.

## Running the checks

Run from this directory with a populated Cargo cache for offline operation.
The workspace declares Rust 1.93 as its minimum version. These commands select
the installed stable toolchain:

```sh
cargo +stable test --locked --offline --features capture
cargo +stable test --locked --offline --no-default-features
cargo +stable clippy --locked --offline --all-targets --features capture -- -D warnings
cargo +stable fmt --all --check
cargo +stable test --locked --offline --features launch-session
```

Use the corresponding feature name to select the HTTP or credential profile.
Capture-print checks must inspect process output with `--nocapture`: capture
markers must be absent, and the legacy marker must remain present in both
feature-on and feature-off modes. All markers are public synthetic fixtures.

## Dependency and integration requirements

Use the checked-in lockfile for `--locked --offline` operation. The harness
disables storage default features to avoid linking SQLite through both
`sqlx` and `rusqlite`.

Product manifests use `execution-proof-prototype/contract` as an optional
sibling path dependency. Preserve that layout when packaging, or provide the
shared crate separately. HTTP bridge tests also depend on the sibling client,
issuer, and handoff crates. The verifier leaf allows `double_must_use` from the
imported `async_trait` expansion without changing production source lint policy.

Production features `evaluation-capture`, `launch-policy-capture`,
`launch-session`, `launch-http`, and `launch-credentials` are default off. The
legacy request paths remain separate. `ApiServer` registers launch routes only
when constructed with `with_launch_proof_service`; the ordinary constructor
leaves the service disabled. Share one service instance across HTTP workers.

## Scope and security boundaries

Static data cannot contain a top-level `policy` key because Regorus base data
can shadow rules in that namespace. Wrappers apply byte bounds before parsing
with the Regorus JSON parser. Capture evaluation discards Rego prints; legacy
evaluation retains its existing print behavior. TDX backend DEBUG quote logging
is outside this suppression mechanism.

Policy aggregates record policy facts and confer no resource permission.
Credential publication requires recorder possession and a live session even
for cached responses; expiry prevents JWE delivery. A delivery receipt records
encrypted publication without asserting recipient receipt, CDH/KMS use, or
execution. Tests use no bearer/cookie fallback, listeners, hardware, or cloud
requests. They provide no TLS/ApiServer server or genuine DCAP/GCP quote evidence.
Cross-version Trustee JWE compatibility with the guest-components keypair is
covered separately by the sibling
`tests/launch-credential-checks/tests/jwe_compat.rs`.
