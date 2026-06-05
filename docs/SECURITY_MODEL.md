# Sigil Security Model

Sigil is designed as a local cryptography bench for analysts, engineers, and
cryptologists. The current implementation favors conservative primitives,
small trusted surfaces, and explicit failure over silent recovery.

## Backend

- Language/runtime: Go.
- Dependency posture: no third-party runtime dependencies in the first slice.
- Randomness: `crypto/rand`.
- Hashing: standard SHA-2 and SHA-3 implementations.
- MAC: HMAC with deprecated digests rejected.
- Research profiling: descriptive statistics for unknown samples, including
  entropy, bit balance, byte coincidence, repeated-block checks,
  autocorrelation, and repeating-key-size hints.
- Signatures: Ed25519 with X.509 PKIX public keys and PKCS#8 private keys.
- Sealing: AES-256-GCM with per-stream random salt and nonce prefix.
- Key derivation: PBKDF2-HMAC-SHA256, default 600,000 iterations, minimum 100,000.
- File sealing: chunked authenticated records with header and metadata bound as AAD.
- Tamper behavior: authentication failure aborts opening.

## GUI

- Default bind address: `127.0.0.1:8765`.
- No external JavaScript, CSS, fonts, images, analytics, or CDN calls.
- Per-process random session token required in `X-Sigil-Token`.
- API methods are JSON-only POST requests.
- No CORS headers are emitted.
- Same-origin and fetch-site checks reject cross-site attempts.
- Strict `Content-Security-Policy` blocks inline script, frames, forms, objects, and unknown network destinations.
- Submitted secrets are processed in memory and are not written to disk by the GUI server.

## Boundaries

- Sigil is not audited.
- Sigil is not FIPS validated.
- Profile reports are triage aids, not proofs of encryption, compression,
  randomness, weakness, or provenance.
- Browser memory, operating-system compromise, shell history, and process-list exposure are outside the tool boundary.
- Command-line passphrases can leak through shell/process surfaces; prefer `SIGIL_PASSPHRASE` for automation or `-passphrase-file` for files with tight permissions.
- PBKDF2 is intentionally conservative and available in the Go standard library. Future work can add memory-hard KDF support once dependency and audit posture are settled.

## Near-Term Hardening

- Add AEAD test vectors for the Sigil envelope format.
- Add deterministic import/export fixtures for key and signature workflows.
- Add optional memory-hard KDF support behind a clear format version.
- Add analyst fixtures for entropy, profiles, encodings, and malformed envelope rejection.
- Add release signing and reproducible build notes.
