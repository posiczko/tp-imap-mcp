# XOAUTH2 authentication — Design

Date: 2026-10-07
Status: Approved
Extends: `docs/superpowers/specs/2026-10-07-tp-imap-mcp-design.md`
Decision record: `docs/adr/0020-xoauth2-with-refresh-tokens-in-1password.md` (supersedes the password-only part of ADR 0008)

## 1. Goal

Let accounts authenticate with OAuth 2.0 (SASL XOAUTH2) instead of a password,
for Microsoft 365 / Outlook.com (where IMAP basic auth is largely disabled) and
Gmail, with a generic "custom" provider for others. Secrets stay in 1Password;
nothing is written to disk.

### Non-goals

- Writing rotated refresh tokens anywhere (1Password remains the only store).
- Device-code flow (Google does not allow it for the IMAP scope).
- OAUTHBEARER (RFC 7628); XOAUTH2 is what Google and Microsoft document.
- Publishing or verifying a Google OAuth app (user's responsibility; see §8).

## 2. Configuration

Per account, in addition to `IMAP_<NAME>_HOST`, `_PORT`, `_LOGIN`, `_READONLY`,
`_DRAFTS`, `_FILTERS`:

| Variable | Required | Meaning |
|---|---|---|
| `IMAP_<NAME>_AUTH` | no | `password` (default) or `oauth2` |
| `IMAP_<NAME>_OAUTH_PROVIDER` | oauth2 | `google`, `microsoft`, or `custom` |
| `IMAP_<NAME>_OAUTH_CLIENT_ID` | oauth2 | OAuth client ID |
| `IMAP_<NAME>_OAUTH_CLIENT_SECRET` | google; optional otherwise | OAuth client secret |
| `IMAP_<NAME>_OAUTH_REFRESH_TOKEN` | oauth2 (server mode) | Refresh token from `tp_imap_mcp auth` |
| `IMAP_<NAME>_OAUTH_TENANT` | no | Microsoft tenant, default `common` |
| `IMAP_<NAME>_OAUTH_AUTH_URL` | custom | Authorization endpoint (https) |
| `IMAP_<NAME>_OAUTH_TOKEN_URL` | custom | Token endpoint (https) |
| `IMAP_<NAME>_OAUTH_SCOPE` | custom | Space-separated scopes |

Rules (startup errors name the variable, never the value):

- `AUTH=oauth2` with `IMAP_<NAME>_PASSWORD` set is an error; `AUTH=password`
  (or unset) requires `PASSWORD` as today.
- `LOGIN` stays required: it is the SASL user and what `whoami` returns.
- `custom` requires `AUTH_URL`, `TOKEN_URL`, `SCOPE`; both URLs must start with
  `https://` (case-insensitive).
- `TENANT`: `[A-Za-z0-9.-]+`.
- In `auth` mode (§4), a missing `REFRESH_TOKEN` is allowed for the account
  being authorized.
- Client secret and refresh token are zeroed on shutdown like passwords.

Presets:

| | Authorization URL | Token URL | Scope |
|---|---|---|---|
| google | `https://accounts.google.com/o/oauth2/v2/auth` | `https://oauth2.googleapis.com/token` | `https://mail.google.com/` |
| microsoft | `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize` | `https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token` | `https://outlook.office.com/IMAP.AccessAsUser.All offline_access` |

## 3. Server mode: connecting an OAuth account

1. **Access token.** Held in memory per account with its expiry. If absent or
   expiring within 300 s, POST `application/x-www-form-urlencoded`
   `grant_type=refresh_token&refresh_token=…&client_id=…[&client_secret=…][&scope=…]`
   to the token URL. Response: JSON with `access_token` (required),
   `expires_in` (default 3600 when absent), others ignored. A rotated
   `refresh_token` in the response is ignored (ADR 0020).
2. **IMAP.** TLS connect and certificate verification as today (ADR 0016),
   then `mailimap_oauth2_authenticate(login, access_token)` instead of LOGIN.
3. **Rejected token.** If authentication fails, drop the cached access token,
   refresh once, and retry once; a second failure is a tool error naming the
   account and the server's response text (cleaned).
4. **`invalid_grant`.** Tool error: `account "<name>": the OAuth refresh token
   was rejected (expired or revoked); run \`op run --env-file imap.env --
   tp_imap_mcp auth <name>\` and store the new token`.
5. **Other token-endpoint failures** (HTTP error, non-JSON, missing
   `access_token`, network): tool error with the provider's `error` /
   `error_description` (Unicode-cleaned, each capped at 200 bytes) or the HTTP
   status; never token values.

HTTPS for token requests uses `std.http.Client` with its CA bundle loaded from
`TP_IMAP_MCP_CA_FILE`; timeout 30 s.

## 4. `tp_imap_mcp auth <account>`

Run as `op run --env-file imap.env -- tp_imap_mcp auth <account>`.

1. Load configuration; the account must have `AUTH=oauth2`.
2. Generate a PKCE `code_verifier` (32 random bytes, base64url, 43 chars),
   `code_challenge = base64url(SHA-256(verifier))` (`S256`), and a 32-byte
   random `state`.
3. Listen on `127.0.0.1:0` (OS-chosen port). Redirect URI:
   `http://127.0.0.1:<port>/` (an IP literal, not `localhost`, so the browser
   cannot try IPv6 where nothing listens; root path for the widest provider
   compatibility).
4. Authorization URL: `response_type=code`, `client_id`, `redirect_uri`,
   `scope`, `state`, `code_challenge`, `code_challenge_method=S256`; Google
   adds `access_type=offline&prompt=consent` (so a refresh token is issued);
   all values percent-encoded. Open it with `/usr/bin/open` and print it to
   stderr.
5. Accept one HTTP request (5-minute timeout). Parse the request line only:
   `GET /?…`. If `error=` is present, report it (cleaned) and fail; if
   `state` does not match exactly, fail; otherwise take `code`. Respond `200`
   with a small fixed HTML page, then close the listener. Any other path gets
   `404` and is ignored (keep waiting until the timeout).
6. POST `grant_type=authorization_code&code=…&redirect_uri=…&client_id=…
   &code_verifier=…[&client_secret=…]` to the token URL.
7. Print the refresh token once to stdout, then to stderr:
   `store it with: op item edit "<item>" "<field>=<token>"` (placeholders for
   item and field). Exit 0. If no refresh token was returned, exit 1 with an
   explanation (Google: consent must include `access_type=offline`; the app
   may need re-consent).

No file is written; the access token from this exchange is discarded.

## 5. Architecture

| File | Responsibility |
|---|---|
| `src/oauth/provider.zig` | Presets, custom endpoints, authorization-URL building, form encoding |
| `src/oauth/pkce.zig` | Verifier, S256 challenge, state |
| `src/oauth/token.zig` | Token requests and response parsing; `AccessToken{ value, expires_at }`; refresh decision |
| `src/oauth/flow.zig` | `auth` command: loopback listener, callback parsing, browser launch |
| `src/c/session.c`, `tpi.h`, `src/imap/c.zig`, `src/imap/session.zig` | `tpi_oauth2_login` / `Session.oauth2Login` |
| `src/config.zig` | `Account.auth` (`password` or `oauth2` with its settings) |
| `src/accounts.zig` | Login branch, access-token cache, refresh-and-retry |
| `src/main.zig` | `auth <account>` dispatch |

## 6. Errors and secrets

- Token values, client secrets, authorization codes, and PKCE verifiers never
  appear in logs, diagnostics, or tool output; the only deliberate output is
  the refresh token printed by `auth`.
- Configuration errors stop startup (exit 1); runtime OAuth failures are tool
  errors scoped to the account.

## 7. Testing

Unit (offline):

- PKCE: RFC 7636 Appendix B test vector (verifier → challenge).
- Authorization URL: parameters present and percent-encoded; Google extras;
  tenant substitution.
- Token response parsing: success; `expires_in` absent; `error` /
  `error_description`; non-JSON; missing `access_token`; extra fields.
- Refresh decision: absent token, expiring within 300 s, fresh.
- Config: each new variable's validation; password + oauth2 conflict; custom
  requires https URLs; auth-mode exemption for the refresh token.
- Callback parsing: success, `state` mismatch, `error=access_denied`,
  wrong path, malformed request line, percent-decoding of `code`.
- Redaction: diagnostics built from token-endpoint failures contain no token.

Local integration (offline, plain HTTP via a test-only seam): a fake token
endpoint on `127.0.0.1` returning success, `invalid_grant`, and an HTTP 500;
the token client produces the expected `AccessToken` or error.

Live (manual, user): register an OAuth app (§8), run `auth`, store the
refresh token, then `zig build itest -- <oauth-account>` passes (it logs in
via XOAUTH2).

## 8. Provider setup (documented in README)

- **Microsoft:** register an app in Microsoft Entra ID ("Mobile and desktop
  applications" platform, redirect `http://127.0.0.1`), API permission
  `IMAP.AccessAsUser.All` + `offline_access`; public client (no secret) is
  fine. Refresh tokens last ~90 days; re-run `auth` when told.
- **Google:** create an OAuth client of type "Desktop app"; enable the Gmail
  API; scope `https://mail.google.com/`. While the app is in *Testing* status,
  refresh tokens expire after 7 days; avoiding that requires publishing and
  Google's verification for restricted scopes. App passwords remain an
  alternative.

## 9. Open items to confirm during the live test

- Microsoft Entra: whether the portal accepts `http://127.0.0.1` as a
  "Mobile and desktop" redirect (or it must be added in the app manifest), and
  that the port is ignored for loopback redirects as documented. If not, fall
  back to registering `http://localhost` and redirecting to
  `http://localhost:<port>/` while listening on both `127.0.0.1` and `::1`.
- Google: Desktop-app clients accept any loopback port with path `/`
  (expected per Google's loopback guidance).

## 10. Implementation notes

- Zig 0.17's `std.http.Client.fetch` has no overall request timeout, so each
  token request runs on a detached worker thread with its own HTTP client; the
  caller waits at most 30 s (`error.TokenRequestTimeout`), so a stalled
  endpoint cannot block the single-threaded server. Each request builds a
  fresh client, so certificate validity uses the current time.
- `expires_in` is clamped to 60–86400 s.
- Verified before merge: 162/162 unit tests (RFC 7636 vector; real HTTP
  exchanges with a local fake token endpoint); live checks pass for password
  accounts. A real XOAUTH2 login is pending the user's OAuth app.
