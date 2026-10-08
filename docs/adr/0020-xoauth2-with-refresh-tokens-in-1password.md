# 0020. Support XOAUTH2 with refresh tokens kept in 1Password

- Status: Accepted
- Date: 2026-10-07
- Supersedes: the "password LOGIN only" decision of [ADR 0008](0008-password-login-over-implicit-tls.md)

## Context

ADR 0008 limited authentication to passwords because static OAuth access
tokens expire within about an hour. Microsoft has since disabled IMAP basic
authentication on most Microsoft 365 tenants, so OAuth is often the only way
in; Gmail supports it as an alternative to app passwords. The user wants both
providers, designed generically.

Questions decided:

- **First refresh token:** (A) a built-in `auth` command (PKCE, loopback
  redirect); (B) an external tool; (C) device-code flow (not allowed by Google
  for the IMAP scope). Chosen: A.
- **Rotated refresh tokens** (Microsoft issues a new one on every refresh):
  (A) keep 1Password as the only store and re-run `auth` when the stored token
  expires (~90 days for Microsoft); (B) the server writes rotated tokens back
  via `op item edit` (needs vault write access); (C) store them in the macOS
  Keychain (new framework dependency, second secret store). Chosen: A.

## Decision

- Per-account `IMAP_<NAME>_AUTH=oauth2` with provider presets for Google and
  Microsoft and a `custom` provider; client ID/secret and refresh token come
  from 1Password via `op run`.
- The server refreshes access tokens over HTTPS (`std.http.Client`, CA bundle
  from `TP_IMAP_MCP_CA_FILE`), keeps them only in memory, and authenticates
  with `mailimap_oauth2_authenticate`; one refresh-and-retry on rejection.
- `tp_imap_mcp auth <account>` performs the authorization-code flow with PKCE
  (S256) and a `127.0.0.1` loopback redirect, and prints the refresh token once
  for the user to store; nothing is written to disk.
- Rotated refresh tokens are ignored; an expired or revoked refresh token
  produces a tool error telling the user to re-run `auth`.

## Consequences

- Microsoft 365 / Outlook.com accounts work where passwords no longer do.
- Secrets still never touch disk; the server never needs write access to the
  vault (ADR 0007 unchanged).
- Microsoft accounts need `auth` re-run roughly every 90 days; Google apps in
  *Testing* status every 7 days (publishing/verification is the user's call).
- More code: a minimal HTTP listener and a token client, both with no new
  dependency.
- Token values join passwords in the "never logged or returned" rule.
