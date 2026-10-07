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
