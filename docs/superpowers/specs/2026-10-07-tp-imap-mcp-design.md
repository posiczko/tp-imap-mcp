# tp-imap-mcp — Design

Date: 2026-10-07
Status: Draft, awaiting review

## 1. Goal

An MCP server, written in Zig 0.17, that mirrors the tools and behavior of
[vivier/imap-mcp-server](https://github.com/vivier/imap-mcp-server) (Python,
`fastmcp` + `imap-tools`) while:

- using an existing C IMAP library rather than implementing IMAP in Zig;
- serving **multiple IMAP accounts** from one process;
- taking all credentials from environment variables injected by the
  1Password CLI (`op run`).

### Non-goals

- PGP/MIME decryption (deferred; see §6.6).
- OAuth2 / XOAUTH2 (password `LOGIN` only).
- STARTTLS on port 143 (implicit TLS only; add `IMAP_<NAME>_TLS` later if needed).
- HTTP transport (stdio only).
- Concurrency (requests handled serially).

## 2. Decisions

| Decision | Choice | Rationale |
|---|---|---|
| IMAP library | **libetpan** (Homebrew 1.10.1, BSD-3) | Low-level `mailimap_*` API maps 1:1 to IMAP commands with typed parse trees; built-in MIME parser (`mailmime`) and charset conversion; only dependency is OpenSSL; actively maintained again (1.10 in 2026-05, 1.10.1 in 2026-06). |
| Rejected: GNU Mailutils | — | GPL-3+ package with LGPL library; heavy dependency set (gnutls, gsasl, gdbm, libunistring, libtool, readline, gettext); IMAP client API thinly documented and secondary to its mailbox abstraction; macro/opaque-stream heavy for Zig interop. |
| Linking | Homebrew libetpan via `pkg-config` (`linkSystemLibrary`) | Least build code; security fixes via `brew upgrade`. Personal macOS/arm64 tool, so portability is not a goal. |
| MCP layer | Hand-written JSON-RPC 2.0 over stdio on `std.json` | Small surface; no mature Zig 0.17 MCP library; avoids a new dependency. |
| C interop | Flat C shim (`src/c/`) + hand-written `extern fn` declarations in Zig | Zig 0.17 removed `@cImport`; the replacement `translate-c` package would be a new dependency and libetpan's `clist` macros do not translate well. All libetpan struct walking stays in C. |
| Multi-account | One process, `account` argument on every tool | Single MCP server registration; model sees one tool set. |
| Auth | Password `LOGIN` over implicit TLS | Covers all of the user's servers. |
| Write tools | Kept, with per-account read-only switch | Parity plus a safety valve. |

### 2.1 Feasibility probe (done)

Raw criteria passthrough was verified against the user's Dovecot server with a
throwaway C probe:

- `mailimap_custom_command(session, "UID SEARCH CHARSET UTF-8 <criteria>")`
  sends the string verbatim (libetpan appends a trailing space, which Dovecot
  accepts) and the untagged `* SEARCH` result is parsed into
  `session->imap_response_info->rsp_search_result` (`clist` of `uint32_t *`).
  No search-criteria parser is needed.
- Raw UTF-8 inside a quoted search string is accepted.
- Server errors return `MAILIMAP_ERROR_CUSTOM_COMMAND`; the server's text is in
  `session->imap_response`.
- Dovecot quirk: negated header searches (`NOT FROM "x"`) return an empty
  `* SEARCH`, while `NOT (SEEN)` works. This is server behavior (confirmed in
  the raw traffic log), not a client bug. Mention it in the `search` tool
  description as "some servers mis-handle NOT on header keys".
- `zig cc` links Homebrew libetpan with `pkg-config --cflags --libs libetpan`.

## 3. Architecture

```
stdin ──► mcp.zig ──► tools.zig ──► accounts.zig ──► imap/session.zig ──► imap/c.zig ──► src/c/*.c ──► libetpan ──► IMAP server
stdout ◄──┘    │          │                                │
          prompts.zig     └──► body.zig ──► (session.extractText → src/c/mime.c)
config.zig ──► accounts.zig          logs ──► stderr
```

| File | Responsibility |
|---|---|
| `src/main.zig` | Load config, set up allocator, run the stdio loop; `test` block imports every module. |
| `src/mcp.zig` | JSON-RPC 2.0, newline-delimited messages on stdin/stdout, logging to stderr only. Methods: `initialize`, `notifications/*` (ignored), `ping`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`. |
| `src/prompts.zig` | The two reference prompts. |
| `src/tools.zig` | Tool schemas, argument handling, handlers, result alignment. |
| `src/descriptions.zig` | Tool description texts (adapted from reference docstrings). |
| `src/validate.zig` | Injection-defense argument checks (§7). |
| `src/config.zig` | Parse environment into `[]Account`; validate. |
| `src/accounts.zig` | Registry: account → lazily connected `Session`; `NOOP` health check; one reconnect-and-retry; drafts discovery; failure diagnostics. |
| `src/headers.zig` | Raw header block → ordered (lowercased name, unfolded value) pairs. |
| `src/body.zig` | `get_text`/`get_html` rendering: extraction, UTF-8 sanitizing, LF line endings, encrypted marker. |
| `src/text.zig` | UTF-8 sanitizing (U+FFFD), CRLF ⇄ LF conversion. |
| `src/imap/session.zig` | Zig wrapper over the C shim. Copies results into arena memory and frees C buffers immediately; no C types leak above this file. |
| `src/imap/c.zig` | Hand-written `extern` declarations mirroring `src/c/tpi.h`. |
| `src/imap/mutf7.zig` | Modified UTF-7 (RFC 3501 §5.1.3) ⇄ UTF-8 for mailbox names. |
| `src/c/tpi.h`, `session.c`, `mime.c` | Flat C API over libetpan: IMAP commands (`mailimap_*`), raw `UID SEARCH` via `mailimap_custom_command`, MIME walk (`mailmime_parse`, `mailmime_part_parse`, `charconv`). |
| `src/itest.zig` | Live integration checks (separate executable). |
| `src/mime_test.zig`, `src/testdata/*.eml` | MIME fixtures and tests. |

## 4. Configuration

All values come from the environment, typically via
`op run --env-file imap.env -- tp_imap_mcp`. Any value may be an `op://`
reference; `op run` resolves it before the process starts.

```
IMAP_ACCOUNTS=tetra,work                         # comma-separated account names
IMAP_TETRA_HOST=mail.example.org                 # required
IMAP_TETRA_PORT=993                              # optional, default 993 (implicit TLS)
IMAP_TETRA_LOGIN=op://Tetrapyloctomy/IMAP Tetrapyloctomy/username   # required
IMAP_TETRA_PASSWORD=op://Tetrapyloctomy/IMAP Tetrapyloctomy/password # required
IMAP_TETRA_READONLY=1                            # optional; 1/true/yes → read-only
IMAP_TETRA_DRAFTS=Drafts                         # optional; else discovered via \Drafts
```

Rules:

- Account names: `[A-Za-z0-9_]+`, case-insensitive; the env-var segment is the
  upper-cased name. Tools accept the name as listed in `IMAP_ACCOUNTS`
  (case-insensitive match).
- Startup fails (exit 1, message on stderr) if `IMAP_ACCOUNTS` is missing or
  empty, a name is invalid or duplicated, a required variable is missing or
  empty, or `PORT`/`READONLY` is malformed. Messages name the variable, never
  the value.
- Passwords live only in process memory, are zeroed (`std.crypto.secureZero`)
  on shutdown, and never appear in logs, errors, or tool output.
- Example MCP client registration:

  ```json
  { "command": "op", "args": ["run", "--env-file", "/path/imap.env", "--", "/path/tp_imap_mcp"] }
  ```

## 5. Connection model

- One libetpan session per account, created on first use.
- Before each tool call: `NOOP`. On failure, or on a stream error during the
  call, discard the session, reconnect + login once, and retry the call once.
  A second failure is returned as a tool error naming the account.
- Login failure affects only that account; the server keeps running.
- Socket timeout: 60 s (`mailstream_network_delay`).
- Mailbox opening per call:
  - read tools: `EXAMINE <directory>` (cannot change flags; never sets `\Seen`);
  - `change_keywords`: `SELECT <directory>`;
  - `create_message`: `APPEND` (no mailbox open needed);
  - `list_mailboxes`, `mailboxes_status`: no open needed.
- Drafts folder: `IMAP_<NAME>_DRAFTS` if set; otherwise the first mailbox from
  `LIST "" "*"` carrying the `\Drafts` special-use flag (RFC 6154), cached per
  session; otherwise `Drafts`.
- Shutdown (stdin EOF): `LOGOUT` each open session, free, zero secrets.

## 6. Tools

Every tool takes a required `account: string` as its first argument. All other
arguments, defaults, and descriptions follow the reference, adjusted for
multi-account and the deviations below.

| Tool | IMAP | Result |
|---|---|---|
| `list_accounts()` *(new)* | — | `[{"name", "login", "readonly"}]` |
| `whoami(account)` | — | login string |
| `list_mailboxes(account, directory, pattern)` | `LIST "<dir>" "<pattern>"` | `[{"PATH", "DELIMITER", "FLAGS": [..]}]` |
| `mailboxes_status(account, directory)` | `STATUS <dir> (MESSAGES RECENT UNSEEN)` | `{"MESSAGES", "RECENT", "UNSEEN"}` |
| `search(account, directory="INBOX", criteria="ALL")` | `EXAMINE`; `UID SEARCH CHARSET UTF-8 <criteria>` | `["<uid>", ...]` ascending |
| `get_header(account, directory, uids)` | `UID FETCH <set> (BODY.PEEK[HEADER])` | per input uid: `{"<lowercased name>": ["<raw value>", ...]}` or `null` |
| `get_header_field(account, directory, uids, field)` | same | per input uid: `["<raw value>", ...]` (`[]` if field absent) or `null` |
| `get_text(account, directory, uids)` | `UID FETCH <set> (BODY.PEEK[])` | per input uid: string or `null` |
| `get_html(account, directory, uids)` | same | per input uid: string or `null` |
| `get_size(account, directory, uids)` | `UID FETCH <set> (RFC822.SIZE)` | per input uid: integer or `null` |
| `get_keywords(account, directory, uids)` | `UID FETCH <set> (FLAGS)` | per input uid: `{"<uid>": [flags]}` or `{"<uid>": null}` |
| `change_keywords(account, directory, uids, keywords, set)` | `SELECT`; `UID STORE <set> ±FLAGS (<keywords>)`; `UID FETCH <set> (FLAGS)` | as `get_keywords`, reflecting flags after the store |
| `create_message(account, content)` | `APPEND <drafts> {literal}` | `{"status": "OK", "data": ["<server text>"]}`; a rejected append is a tool error carrying the server text |

Tool results are returned as MCP `content: [{"type": "text", "text": <JSON>}]`.

### 6.1 Prompts

`list_patches_of_a_series(cover_letter)` and `review_a_patch_series()` are
carried over with identical text.

### 6.2 Ordering (deviation from reference)

The reference returns fetch results in server order and silently drops
nonexistent UIDs. This server returns results **aligned one-to-one with the
input `uids`**, with `null` for UIDs that do not exist in the mailbox. Duplicate
input UIDs produce duplicate entries.

### 6.3 Headers (parity)

Header names are lower-cased; values are unfolded but otherwise raw (RFC 2047
encoded-words are **not** decoded), matching `imap-tools`. Repeated headers
yield multiple values in order of appearance.

### 6.4 Bodies (parity)

`get_text`/`get_html` walk the MIME tree depth-first, skip `multipart/*`
containers and any part with a filename (`Content-Disposition` `filename` or
`Content-Type` `name`), and concatenate every part whose type is `text/plain`
(resp. `text/html`). Each part is transfer-decoded (base64, quoted-printable)
and converted from its declared charset (default `utf-8`) to UTF-8; invalid
sequences are replaced with U+FFFD. Line endings are normalized to LF. A
message with no matching part yields `""`. A message that cannot be parsed as
MIME at all is a tool error naming the UID. `message/rfc822` parts are
descended into, as Python's `Message.walk()` does.

### 6.5 Mailbox names

Names are modified UTF-7 on the wire. `PATH` in `list_mailboxes` is decoded to
UTF-8; every `directory` argument is encoded from UTF-8 before use.

### 6.6 Encrypted messages

A top-level `multipart/encrypted` message yields, for both `get_text` and
`get_html`, the string
`"[encrypted message (multipart/encrypted; protocol=<protocol>) — not decrypted]"`.
Adding PGP/MIME decryption later (via `gpg --batch --decrypt`, as the
reference does) changes no tool signature.

### 6.7 `create_message` (parity)

Appends `content` (UTF-8 bytes) as-is to the drafts folder with no flags. CRLF
normalization: bare `\n` is converted to `\r\n` before `APPEND`, since servers
require CRLF line endings (Python's `imaplib.append`, used by the reference,
does the same).

### 6.8 Read-only accounts

For an account with `READONLY` set, `change_keywords` and `create_message`
return a tool error (`account "<name>" is read-only`) without contacting the
server. All other tools already use `EXAMINE` or non-modifying commands.

## 7. Input validation (injection defense)

`criteria` is sent verbatim, so validation is the only barrier against command
smuggling (which would also bypass read-only):

| Argument | Rule |
|---|---|
| `criteria` | Reject if it contains CR, LF, or NUL. |
| `uids` | Non-empty array; each element a decimal string `1..4294967295`. |
| `keywords` | Non-empty array; each a system flag (`\Seen`, `\Answered`, `\Flagged`, `\Deleted`, `\Draft`) or an IMAP atom (no SP, CTL, `(`, `)`, `{`, `%`, `*`, `"`, `\`, `]`). |
| `directory`, `pattern` | Passed through libetpan's typed APIs (which quote/literal-encode); reject NUL. |
| `field` | Non-empty, header-name characters only (printable ASCII except `:` and SP). |
| `account` | Must match a configured account. |

## 8. Errors

- **Tool-level** (`tools/call` result with `isError: true`, text message):
  IMAP `NO`/`BAD` (including the server's response text), unknown account,
  read-only refusal, validation failure, connection/login failure after retry.
- **Protocol-level** (JSON-RPC error object): parse error (-32700), invalid
  request (-32600), unknown method (-32601), invalid params — missing/mistyped
  arguments or unknown tool (-32602).
- Only allocation failure terminates the process; every other failure is
  confined to the current call.

## 9. Testing

**Unit tests** (`zig build test`, no network):

- `config.zig`: valid multi-account env; each missing/empty/malformed variable;
  error messages never contain values.
- `mutf7.zig`: round-trips including `&` escaping, non-BMP characters, and
  RFC 3501 examples.
- Validation: criteria with CR/LF/NUL; non-numeric and out-of-range UIDs;
  invalid keywords; header field names.
- `body.zig` / `src/c/mime.c` against fixture `.eml` files in `src/testdata/`:
  multipart/alternative; `text/plain` attachment that must be skipped;
  ISO-8859-1 body; quoted-printable; base64; nested multipart/mixed;
  multipart/encrypted marker; message with no text parts.
- Result alignment: input order, duplicates, `null` for missing UIDs.
- `mcp.zig`: JSON-RPC framing, `initialize` handshake, error codes.

**Integration checks** (`op run --env-file imap.env -- zig build itest -- <account> [--write <scratch-mailbox>]`,
a separate executable, opt-in): every read tool against INBOX with result
alignment (including a nonexistent UID), a server-rejected search, and
reconnect after a forced server-side logout. Prints only PASS/FAIL and counts,
never message content. `--write` adds then removes the keyword
`$TpImapMcpTest` on the newest message in the given scratch mailbox, and is
run only with explicit user approval at the time. `create_message` is verified
manually via the MCP Inspector. (Verified against the user's Dovecot server on
2026-10-07 with a prototype of this design: 13/13 checks passed.)

**End-to-end**: MCP Inspector, or piping JSON-RPC lines to the binary.

## 10. Build

- `build.zig`: one helper builds a module with libc, `src/c/*.c` (compiled
  `-std=c11 -Wall -Wextra -Werror`), and `linkSystemLibrary("etpan")` via
  pkg-config. Steps: default install, `run`, `test` (unit tests, no network),
  `itest` (live checks).
- No new Zig package dependencies.
- Runtime requirement: Homebrew `libetpan` (and its `openssl@3`).
