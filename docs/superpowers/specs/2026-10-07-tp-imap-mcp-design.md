# tp-imap-mcp — Design

Date: 2026-10-07
Status: Approved (cache design added 2026-10-07)
Decisions: see `docs/adr/` (ADRs 0001–0016)

## 1. Goal

An MCP server, written in Zig 0.17, that mirrors the tools and behavior of
[vivier/imap-mcp-server](https://github.com/vivier/imap-mcp-server) (Python,
`fastmcp` + `imap-tools`) while:

- using an existing C IMAP library rather than implementing IMAP in Zig;
- serving **multiple IMAP accounts** from one process;
- taking all credentials from environment variables injected by the
  1Password CLI (`op run`);
- caching the mailbox list and message headers/sizes on disk in XDG
  directories.

### Non-goals

- PGP/MIME decryption (deferred; see §6.6, ADR 0009).
- OAuth2 / XOAUTH2 (password `LOGIN` only; ADR 0008).
- STARTTLS on port 143 (implicit TLS only; add `IMAP_<NAME>_TLS` later if needed).
- HTTP transport (stdio only; ADR 0005).
- Concurrency (requests handled serially).
- Caching message bodies or flags (ADR 0013).

## 2. Decisions

| Decision | Choice | ADR |
|---|---|---|
| IMAP library | libetpan (Homebrew 1.10.1, BSD-3); GNU Mailutils rejected | 0002 |
| Linking | Homebrew libetpan via `pkg-config` | 0003 |
| C interop | Flat C shim (`src/c/`) + hand-written `extern fn` declarations (Zig 0.17 has no `@cImport`) | 0004 |
| MCP layer | Hand-written JSON-RPC 2.0 over stdio on `std.json` | 0005 |
| Multi-account | One process, `account` argument on every tool | 0006 |
| Credentials | Environment variables resolved by `op run` | 0007 |
| Auth | Password `LOGIN` over implicit TLS | 0008 |
| PGP | Not decrypted; marker returned | 0009 |
| Write tools | Kept, with per-account read-only switch | 0010 |
| Search | Raw criteria passthrough, strict input validation | 0011 |
| Behavior | Reference parity with listed deviations | 0012 |
| Cache scope | Mailbox list + message headers/sizes; no bodies, no flags | 0013 |
| Local data location | XDG base directories | 0014 |
| Cache storage | SQLite via system `libsqlite3`, hand-written externs | 0015 |
| TLS | Verify chain (CA bundle), SNI, and host name before LOGIN | 0016 |

### 2.1 Feasibility probes (done)

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
  the raw traffic log), not a client bug. The `search` tool description warns
  about it.
- Zig 0.17 builds and links a C shim against Homebrew libetpan and the system
  `libsqlite3` (`linkSystemLibrary` resolves `-lsqlite3` from the macOS SDK).

## 3. Architecture

```
stdin ──► mcp.zig ──► tools.zig ──► accounts.zig ──► imap/session.zig ──► imap/c.zig ──► src/c/*.c ──► libetpan ──► IMAP server
stdout ◄──┘    │          │  │               │
          prompts.zig     │  └► listmatch.zig └──► cache/store.zig ──► cache/sqlite.zig ──► libsqlite3 ──► ~/.cache/tp-imap-mcp/<account>.sqlite3
                          └──► body.zig ──► (session.extractText → src/c/mime.c)
config.zig ──► accounts.zig          logs ──► stderr
```

| File | Responsibility |
|---|---|
| `src/main.zig` | Load config and settings, set up allocator, run the stdio loop; `test` block imports every module. |
| `src/mcp.zig` | JSON-RPC 2.0, newline-delimited messages on stdin/stdout, logging to stderr only. Methods: `initialize`, `notifications/*` (ignored), `ping`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`. |
| `src/prompts.zig` | The two reference prompts. |
| `src/tools.zig` | Tool schemas, argument handling, handlers, result alignment, cached header fetch. |
| `src/descriptions.zig` | Tool description texts (adapted from reference docstrings). |
| `src/validate.zig` | Injection-defense argument checks (§7). |
| `src/config.zig` | Environment → `[]Account` and `Settings` (cache location, TTL, on/off). |
| `src/accounts.zig` | Registry: account → lazily connected `Session`; `NOOP` health check; one reconnect-and-retry; per-account cache; mailbox list; drafts discovery; failure diagnostics. |
| `src/listmatch.zig` | Local evaluation of LIST reference + pattern (`*`, `%`, INBOX case-insensitivity). |
| `src/cache/sqlite.zig` | Hand-written externs for `libsqlite3` and a thin wrapper. |
| `src/cache/store.zig` | Cache schema and operations. |
| `src/headers.zig` | Raw header block → ordered (lowercased name, unfolded value) pairs. |
| `src/body.zig` | `get_text`/`get_html` rendering: extraction, UTF-8 sanitizing, LF line endings, encrypted marker. |
| `src/text.zig` | UTF-8 sanitizing (U+FFFD), CRLF ⇄ LF conversion. |
| `src/imap/session.zig` | Zig wrapper over the C shim. Copies results into arena memory and frees C buffers immediately; no C types leak above this file. |
| `src/imap/c.zig` | Hand-written `extern` declarations mirroring `src/c/tpi.h`. |
| `src/imap/mutf7.zig` | Modified UTF-7 (RFC 3501 §5.1.3) ⇄ UTF-8 for mailbox names. |
| `src/c/tpi.h`, `session.c`, `mime.c` | Flat C API over libetpan: IMAP commands (`mailimap_*`), raw `UID SEARCH` via `mailimap_custom_command`, UIDVALIDITY from `EXAMINE`/`SELECT`, MIME walk (`mailmime_parse`, `mailmime_part_parse`, `charconv`). |
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

TP_IMAP_MCP_CACHE=1                              # optional; 0/false/no disables caching
TP_IMAP_MCP_MAILBOX_TTL=3600                     # optional; seconds, default 3600
TP_IMAP_MCP_CA_FILE=/opt/homebrew/etc/ca-certificates/cert.pem  # optional; PEM bundle (default shown)
XDG_CACHE_HOME=/Users/me/.cache                  # optional; standard XDG variable
```

Rules:

- Account names: `[A-Za-z0-9_]+`, case-insensitive; the env-var segment is the
  upper-cased name. Tools accept the name as listed in `IMAP_ACCOUNTS`
  (case-insensitive match).
- Startup fails (exit 1, message on stderr) if `IMAP_ACCOUNTS` is missing or
  empty, a name is invalid or duplicated, a required variable is missing or
  empty, or `PORT`/`READONLY`/`TP_IMAP_MCP_CACHE`/`TP_IMAP_MCP_MAILBOX_TTL` is
  malformed. Messages name the variable, never the value.
- Passwords live only in process memory, are zeroed (`std.crypto.secureZero`)
  on shutdown, and never appear in logs, errors, or tool output.
- Startup fails if the CA bundle is not readable.
- Startup logs the account count and the cache directory (or "off") to stderr.
- Example MCP client registration:

  ```json
  { "command": "op", "args": ["run", "--env-file", "/path/imap.env", "--", "/path/tp_imap_mcp"] }
  ```

## 5. Connection model

- One libetpan session per account, created on first use.
- TLS (ADR 0016): the certificate chain is verified against
  `TP_IMAP_MCP_CA_FILE` with SNI set to the host; then the leaf certificate's
  host name (SAN DNS/IP, else CN) is checked against `IMAP_<NAME>_HOST` before
  LOGIN. Either failure is a tool error naming the account; no credentials are
  sent.
- Before each tool call: `NOOP`. On failure, or on a stream error during the
  call, discard the session, reconnect + login once, and retry the call once.
  A second failure is returned as a tool error naming the account.
- Login failure affects only that account; the server keeps running.
- Socket timeout: 60 s (`mailimap_set_timeout`).
- Mailbox opening per call:
  - read tools: `EXAMINE <directory>` (cannot change flags; never sets `\Seen`);
    returns the mailbox's UIDVALIDITY for the cache;
  - `change_keywords`: `SELECT <directory>`;
  - `create_message`: `APPEND` (no mailbox open needed);
  - `list_mailboxes`, `mailboxes_status`, `clear_cache`: no open needed.
- Any server rejection (`NO`/`BAD`) marks the account's cached mailbox list
  stale, so a mailbox renamed or deleted elsewhere is re-listed next time.
- Drafts folder: `IMAP_<NAME>_DRAFTS` if set; otherwise the first mailbox in
  the (cached) mailbox list carrying the `\Drafts` special-use flag (RFC 6154);
  otherwise `Drafts`. Remembered for the life of the process.
- Shutdown (stdin EOF): `LOGOUT` each open session, close caches, free, zero
  secrets.

## 6. Tools

Every tool except `list_accounts` takes a required `account: string` as its
first argument. All other arguments, defaults, and descriptions follow the
reference, adjusted for multi-account and the deviations below (ADR 0012).

| Tool | IMAP | Result |
|---|---|---|
| `list_accounts()` *(new)* | — | `[{"name", "login", "readonly"}]` |
| `whoami(account)` | — | login string |
| `list_mailboxes(account, directory, pattern, refresh?)` | cached `LIST "" "*"`, matched locally (§6.9) | `[{"PATH", "DELIMITER", "FLAGS": [..]}]` |
| `mailboxes_status(account, directory)` | `STATUS <dir> (MESSAGES RECENT UNSEEN)` | `{"MESSAGES", "RECENT", "UNSEEN"}` |
| `search(account, directory="INBOX", criteria="ALL")` | `EXAMINE`; `UID SEARCH CHARSET UTF-8 <criteria>` | `["<uid>", ...]` ascending |
| `get_header(account, directory, uids)` | `EXAMINE`; cache; misses: `UID FETCH (BODY.PEEK[HEADER] RFC822.SIZE)` | per input uid: `{"<lowercased name>": ["<raw value>", ...]}` or `null` |
| `get_header_field(account, directory, uids, field)` | same | per input uid: `["<raw value>", ...]` (`[]` if field absent) or `null` |
| `get_text(account, directory, uids)` | `EXAMINE`; `UID FETCH (BODY.PEEK[])` | per input uid: string or `null` |
| `get_html(account, directory, uids)` | same | per input uid: string or `null` |
| `get_size(account, directory, uids)` | same as `get_header` | per input uid: integer or `null` |
| `get_keywords(account, directory, uids)` | `EXAMINE`; `UID FETCH (FLAGS)` | per input uid: `{"<uid>": [flags]}` or `{"<uid>": null}` |
| `change_keywords(account, directory, uids, keywords, set)` | `SELECT`; `UID STORE ±FLAGS (<keywords>)`; `UID FETCH (FLAGS)` | as `get_keywords`, reflecting flags after the store |
| `create_message(account, content)` | `APPEND <drafts> {literal}` | `{"status": "OK", "data": ["<server text>"]}`; a rejected append is a tool error carrying the server text |
| `clear_cache(account)` *(new)* | — | `{"status": "OK"}`, plus `"note"` when caching is disabled |

Tool results are returned as MCP `content: [{"type": "text", "text": <JSON>}]`
(plain text for `whoami`).

### 6.1 Prompts

`list_patches_of_a_series(cover_letter)` and `review_a_patch_series()` are
carried over with identical text.

### 6.2 Ordering (deviation from reference)

The reference returns fetch results in server order and silently drops
nonexistent UIDs. This server returns results **aligned one-to-one with the
input `uids`**, with `null` for UIDs that do not exist in the mailbox. Duplicate
input UIDs produce duplicate entries. Several FETCH responses for one UID
(e.g. an unsolicited flag update) are merged field by field.

### 6.3 Headers (parity)

Header names are lower-cased; values are unfolded but otherwise raw (RFC 2047
encoded-words are **not** decoded), matching `imap-tools`. Repeated headers
yield multiple values in order of appearance. A line is a header only if its
name is 1*ftext (RFC 5322: printable ASCII except `:`; whitespace before the
colon tolerated); other lines are skipped. Invalid UTF-8 bytes in values are
replaced with U+FFFD.

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

Names are modified UTF-7 on the wire and in the cache. `PATH` in
`list_mailboxes` is decoded to UTF-8 (raw name, sanitized, if it is not valid
modified UTF-7); every `directory` argument is encoded from UTF-8 before use.

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
`clear_cache` is local and allowed.

### 6.9 `list_mailboxes` matching

The full mailbox list (`LIST "" "*"`, from the cache when fresh) is filtered
locally per RFC 3501 §6.3.8: `directory` and `pattern` are concatenated
without inserting a delimiter; `*` matches any characters, `%` matches any
characters except the mailbox's hierarchy delimiter; a leading `INBOX` is
case-insensitive in both names and patterns; an empty pattern matches nothing.
Matching is done on UTF-8 (decoded) names in O(name × pattern) time (no
backtracking: the pattern is model-supplied). `refresh: true` bypasses the
cache.

## 7. Input validation (injection defense)

`criteria` is sent verbatim, so validation is the only barrier against command
smuggling (which would also bypass read-only; ADR 0011):

| Argument | Rule |
|---|---|
| `criteria` | Reject if it contains CR, LF, or NUL. |
| `uids` | Non-empty array; each element a decimal string `1..4294967295`. |
| `keywords` | Non-empty array; each a system flag (`\Seen`, `\Answered`, `\Flagged`, `\Deleted`, `\Draft`) or an IMAP atom (no SP, CTL, `(`, `)`, `{`, `%`, `*`, `"`, `\`, `]`). |
| `directory`, `pattern` | Reject NUL. Mailbox names go through libetpan's typed APIs (which quote/literal-encode). |
| `field` | Non-empty, header-name characters only (printable ASCII except `:` and SP). |
| `refresh`, `set` | JSON booleans. |
| `account` | Must match a configured account. |

## 8. Errors

- **Tool-level** (`tools/call` result with `isError: true`, text message):
  IMAP `NO`/`BAD` (including the server's response text), unknown account,
  read-only refusal, connection/login failure after retry.
- **Protocol-level** (JSON-RPC error object): parse error (-32700), invalid
  request (-32600), unknown method (-32601), invalid params — missing/mistyped
  arguments, failed validation, or unknown tool (-32602).
- **Cache failures never fail a tool call** (§11).
- All text placed in JSON-RPC responses is valid UTF-8 (sanitized as a
  backstop in `mcp.zig`).
- Only allocation failure terminates the process; every other failure is
  confined to the current call.

## 9. Testing

**Unit tests** (`zig build test`, no network except a refused connection to
`127.0.0.1:1`):

- `config.zig`: valid multi-account env; each missing/empty/malformed variable;
  error messages never contain values; settings (XDG location, HOME fallback,
  relative `XDG_CACHE_HOME` ignored, disable switch, TTL).
- `mutf7.zig`: round-trips including `&` escaping, non-BMP characters, RFC 3501
  examples, and quoting-sensitive characters.
- Validation: criteria with CR/LF/NUL; non-numeric and out-of-range UIDs;
  invalid keywords; header field names.
- `body.zig` / `src/c/mime.c` against fixture `.eml` files in `src/testdata/`:
  multipart/alternative; `text/plain` attachment that must be skipped;
  ISO-8859-1 body; quoted-printable; base64; nested `message/rfc822`;
  multipart/encrypted marker; message with no text parts; undeclared 8-bit.
- `listmatch.zig`: `*` vs `%`, reference concatenation, INBOX case rules.
- `cache/sqlite.zig`, `cache/store.zig`: round trips; freshness and staleness;
  UIDVALIDITY change; vanished mailbox; clear; schema-version rebuild; corrupt
  file detection.
- `accounts.zig`: connect diagnostics; drafts override; fresh cached list
  served without the server; `refresh` bypass; corrupt cache rebuilt; caching
  disabled.
- `tools.zig`: alignment (input order, duplicates, `null`); offline tools;
  errors that never reach the server; `tools/list` schema shape.
- `mcp.zig`: JSON-RPC framing, `initialize` handshake, error codes, `id: 0`,
  omitted `arguments`, very long lines.

**Integration checks** (`op run --env-file imap.env -- zig build itest -- <account> [--write <scratch-mailbox>]`,
a separate executable, opt-in): every read tool against INBOX with result
alignment (including a nonexistent UID), a server-rejected search, reconnect
after a forced server-side logout, and the cache (list cached after first call,
cached list equals server list, local `inbox` match, `refresh`, cached header
equals live header, rows on disk, `clear_cache`). Uses a throwaway cache
directory (`.zig-cache/itest-cache`), never `~/.cache`. Prints only PASS/FAIL
and counts, never message content. `--write` adds then removes the keyword
`$TpImapMcpTest` on the newest message in the given scratch mailbox, and is run
only with explicit user approval at the time. `create_message` is verified
manually via the MCP Inspector.

Verification status (2026-10-07): the pre-cache prototype passed 12/12 live
checks against the user's Dovecot server; the implementation passes 68/68
unit tests; TLS verification was checked against fake IMAPS servers
(untrusted chain refused, wrong host refused, valid host proceeds); the full
live check passed 20/20 against the user's Dovecot server (TLS verification
with the Homebrew CA bundle, all read tools, reconnect, and the cache).

**End-to-end**: MCP Inspector, or piping JSON-RPC lines to the binary.

## 10. Build

- `build.zig`: one helper builds a module with libc, `src/c/*.c` (compiled
  `-std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror`),
  `linkSystemLibrary("etpan")` (pkg-config) and `linkSystemLibrary("sqlite3")`
  (system library). Steps: default install, `run`, `test` (unit tests),
  `itest` (live checks).
- No Zig package dependencies.
- Runtime requirements: Homebrew `libetpan` (and its `openssl@3`); the
  OS-provided `libsqlite3`.

## 11. Cache

ADRs 0013–0015.

**Location.** `$XDG_CACHE_HOME/tp-imap-mcp/` when `XDG_CACHE_HOME` is set and
absolute, else `$HOME/.cache/tp-imap-mcp/`; if neither is usable, caching is
off and startup says so. Directories are created with mode 0700; databases are
opened under a 0077 umask so the file and its `-wal`/`-shm` companions are
0600. One file per account: `<account, lower-cased>.sqlite3`. Nothing is read
from `$XDG_CONFIG_HOME` or written to `$XDG_STATE_HOME` yet. `TP_IMAP_MCP_CACHE=0`
disables caching entirely.

**Schema** (`PRAGMA user_version = 1`; any other version is dropped and
rebuilt — it is only a cache). WAL journal, 5 s busy timeout so concurrent
server processes can share a file.

```sql
CREATE TABLE meta      (key TEXT PRIMARY KEY, value INTEGER NOT NULL);   -- 'mailboxes_fetched_at' (unix seconds)
CREATE TABLE mailboxes (name TEXT PRIMARY KEY, delimiter TEXT NOT NULL, flags TEXT NOT NULL);
CREATE TABLE messages  (mailbox TEXT NOT NULL, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
                        size INTEGER NOT NULL, header BLOB NOT NULL,
                        PRIMARY KEY (mailbox, uidvalidity, uid)) WITHOUT ROWID;
```

Mailbox names are stored in wire form; `delimiter` is `""` for NIL; `flags` is
space-separated.

**Mailbox list.** Fresh when `mailboxes_fetched_at` is less than
`TP_IMAP_MCP_MAILBOX_TTL` seconds old. A refresh replaces the table, deletes
cached messages of mailboxes no longer present, and updates the timestamp in
one transaction. Marked stale on any server rejection (§5).

**Headers and sizes.** `get_header`, `get_header_field`, and `get_size`
`EXAMINE` the mailbox (learning UIDVALIDITY), delete that mailbox's rows with
a different UIDVALIDITY, serve cached UIDs, fetch the rest with one
`UID FETCH (BODY.PEEK[HEADER] RFC822.SIZE)`, and store them. Nonexistent UIDs
are not cached. If the server reports no UIDVALIDITY, the cache is bypassed for
that call.

**Not cached.** `search`, `mailboxes_status`, flags, bodies, write tools.

**`clear_cache(account)`** deletes all rows for the account. No size limit;
deleting the file is always safe.

**Failures.** A cache error is logged once to stderr (`std.log` scope
`accounts`) and the account continues uncached for the rest of the process. A
file that is not a valid database is deleted and recreated once.

**Privacy.** Cached headers contain subjects and addresses; the file is
readable only by the user.
