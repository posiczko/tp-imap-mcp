# 0002. Use libetpan for IMAP and MIME

- Status: Accepted
- Date: 2026-10-07

## Context

The server must mirror vivier/imap-mcp-server (Python, `imap-tools`) without
implementing or porting IMAP in Zig. Two mature C libraries were evaluated:

|               | libetpan                                                          | GNU Mailutils                                                             |
|---------------|-------------------------------------------------------------------|---------------------------------------------------------------------------|
| License       | BSD-3-Clause                                                      | GPL-3.0+ package (library LGPL-3.0+)                                      |
| Homebrew deps | `openssl@3`                                                       | gnutls, gsasl, gdbm, libunistring, libtool, readline, gettext             |
| IMAP API      | Low-level `mailimap_*`, 1:1 with IMAP commands, typed parse trees | `mu_imap_*` client, thinly documented, secondary to a mailbox abstraction |
| MIME          | `mailmime` parser + `charconv`                                    | `mu_mime`                                                                 |
| Extensions    | XOAUTH2, IDLE, CONDSTORE/QRESYNC, Gmail `X-GM-*`                  | XOAUTH2 unconfirmed                                                       |
| Maintenance   | Dormant 2019–2026; active again (1.10 May 2026, 1.10.1 June 2026) | Steady GNU releases                                                       |
| Zig interop   | Plain structs and `clist`; a few macros                           | Macro- and opaque-stream-heavy                                            |

A throwaway probe against the user's Dovecot server confirmed that
`mailimap_custom_command("UID SEARCH ...")` leaves parsed results in
`imap_response_info->rsp_search_result`, so the reference's raw search-criteria
passthrough works without writing a criteria parser.

## Decision

Use libetpan (Homebrew 1.10.1) for all IMAP protocol work and for MIME body
extraction.

## Consequences

- One small, permissively licensed dependency covers IMAP and MIME.
- libetpan's 2019–2026 dormancy is a maintenance risk; mitigated by its
  revival and by isolating it behind a small C shim (ADR 0004).
- Server quirks surface as-is (e.g. this Dovecot returns an empty result for
  negated header searches); this is server behavior, not a libetpan bug.
