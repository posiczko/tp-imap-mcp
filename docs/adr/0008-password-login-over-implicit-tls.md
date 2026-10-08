# 0008. Authenticate with password LOGIN over implicit TLS only

- Status: Accepted; "password only" superseded by [0020](0020-xoauth2-with-refresh-tokens-in-1password.md) (implicit TLS still applies)
- Date: 2026-10-07

## Context

The reference supports password login and a static XOAUTH2 token. Static
Google/Microsoft access tokens expire after about an hour, so a long-running
server would silently lose access; doing OAuth properly needs refresh-token
handling. All of the user's servers accept passwords (or app passwords).
STARTTLS on port 143 is not needed by any current server.

## Decision

Support only `LOGIN` with a password over implicit TLS (default port 993).
No XOAUTH2, no STARTTLS.

## Consequences

- No OAuth or token-refresh code.
- Gmail/Outlook accounts must use app passwords.
- Adding XOAUTH2 (libetpan has `mailimap_oauth2_authenticate`) or STARTTLS
  later is an additive change with a new config variable.
