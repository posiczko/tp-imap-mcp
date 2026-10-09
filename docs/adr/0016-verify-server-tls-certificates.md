# 0016. Verify server TLS certificates (chain, SNI, host name)

- Status: Accepted
- Date: 2026-10-07

## Context

The final code review found that `mailimap_ssl_connect` performs no
certificate verification: libetpan only sets `SSL_VERIFY_PEER` when the caller
supplies a CA bundle through `mailstream_ssl_set_server_certicate`, it sets no
SNI by default, and libetpan 1.10.1 has no host-name check at all (the dylib
imports no `X509_check_host` / `SSL_set1_host`). Verified with a fake IMAPS
server using a self-signed certificate: the server received
`LOGIN victim hunter2`. Anyone able to intercept traffic (public Wi-Fi, DNS
spoofing) could harvest IMAP passwords.

Options considered:

- Chain via libetpan + CA bundle, SNI, and host-name check with Zig's
  `std.crypto.Certificate.verifyHostName` — no new dependency.
- Link `openssl@3` directly for `X509_VERIFY_PARAM_set1_host` — a new direct
  dependency.
- Per-account certificate pinning (`IMAP_<NAME>_CERT_SHA256`) — strict, but
  breaks on every certificate renewal.

## Decision

Use the first option (approved by the user):

- `tpi_connect` connects with `mailimap_ssl_connect_with_callback`; the
  callback sets SNI (`mailstream_ssl_set_server_name`) and enables chain
  verification against a PEM bundle (`mailstream_ssl_set_server_certicate`).
  A handshake failure is reported as "certificate is not trusted".
- Before LOGIN, the server's leaf certificate (element 0 of
  `mailstream_get_certificate_chain`) is checked against the configured host
  with `std.crypto.Certificate.parse` + `verifyHostName` (SAN DNS/IP entries,
  else CN). A mismatch closes the connection without sending credentials.
- The bundle is `TP_IMAP_MCP_CA_FILE`, default
  `/opt/homebrew/etc/ca-certificates/cert.pem` (Homebrew `ca-certificates`).
  Startup fails with a clear message if it is unreadable.

`mailstream_ssl_get_certificate` is deliberately not used: in libetpan 1.10.1
it returns a pointer advanced past its buffer by `i2d_X509`, which can be
neither read nor freed.

## Consequences

- Credentials are only sent to servers presenting a trusted certificate valid
  for the configured host name. Verified: untrusted chain refused; trusted
  chain with the wrong host refused; trusted and matching host proceeds.
- Self-signed or private-CA servers need `TP_IMAP_MCP_CA_FILE` pointing at a
  bundle that includes their CA.
- `IMAP_<NAME>_HOST` must be a name (or IP) the certificate covers.
- `std.crypto.Certificate.parse` may panic on malformed bytes; it is only fed
  certificates OpenSSL already verified, so input is well-formed by
  construction.
- Supersedes nothing; complements ADR 0008.

## Amendment (2026-10-09): Linux, where libetpan uses GnuTLS

Debian/Ubuntu build libetpan (1.9.4 on Ubuntu 26.04) against GnuTLS, whose
backend does not implement `mailstream_ssl_set_server_certicate` (it returns
-1 with "not implemented", in 1.9.4 and 1.10 alike). The handshake then
completes without any chain check. Before this amendment the shim treated the
-1 as a TLS failure, so Linux failed closed: every connection refused.

Options considered: build libetpan from source against OpenSSL; verify the
chain in Zig on every platform; verify in Zig only where libetpan cannot.
Chosen (user's call): the last.

- `tls_setup` records that the backend could not take the CA file instead of
  failing; `tpi_chain_verified` reports it and `tpi_peer_chain` returns the
  server's chain (DER, leaf first).
- `Session.connect` then verifies the chain in Zig (`src/imap/trust.zig`)
  before the host-name check and before any credential: each certificate
  valid now and signed by the next, every issuer a CA (basicConstraints cA,
  read from the DER because `std.crypto.Certificate.Parsed` neither exposes
  nor checks it), ending at a certificate signed by one in the bundle. The
  bundle is read once per process (`Trust`).
- The default bundle is per OS: `/opt/homebrew/etc/ca-certificates/cert.pem`
  on macOS, `/etc/ssl/certs/ca-certificates.crt` elsewhere.
- macOS (OpenSSL) is unchanged: libetpan still verifies the chain.

Consequences:

- Verified live on Ubuntu 26.04 with Gmail and dummy credentials: with the
  system bundle the connection reaches LOGIN ("Invalid credentials"); with a
  bundle holding one unrelated root it stops at "certificate is not
  trusted", before LOGIN.
- No revocation (CRL/OCSP) and no name or policy constraints, as with
  `std.http`'s TLS client. OpenSSL on macOS does more.
- `Certificate.parse` panics on malformed DER. The chain comes from GnuTLS,
  which has already imported each certificate as X.509 and re-exported it,
  so the input is well formed by construction, as on macOS.
- Tests use Gmail's public chain at a fixed time. Not covered by a test: a
  chain whose intermediate is not a CA (needs a forged chain, i.e. generated
  keys); `isCa` itself is tested.
