# TODO

Minor issues deferred from the final code review (2026-10-07). Each fix should
start with a failing test, per the project's TDD workflow. Line numbers are as
of the review fix pass.

- [ ] **Draft can be duplicated on reconnect.** `create_message` runs through
  `Registry.run`, which retries once after `ConnectionLost`
  (`src/accounts.zig:89`). If the connection drops after the server stored the
  message but before its tagged `OK` arrived, the retry appends a second draft
  (`src/tools.zig:472`, `AppendOp` at `src/tools.zig:581`).
  *Fix:* don't retry non-idempotent operations. Let `AppendOp` opt out of the
  retry, and report "connection lost; the draft may or may not have been
  saved".

- [ ] **Cached headers outlive expunged messages.** `get_header`,
  `get_header_field` and `get_size` serve cached rows even after the message
  was expunged on the server (`CachedHeadersOp`, `src/tools.zig:527`). Spec
  §6.2 says a nonexistent UID gives `null`. The data is stale but not wrong,
  because UIDs are never reused within a UIDVALIDITY.
  *Fix:* either document it in the tool descriptions, or confirm cached UIDs
  still exist with a cheap `UID SEARCH UID <set>` before serving them.

- [ ] **Corruption found at query time is never rebuilt.** A `SqliteCorrupt`
  raised during a query, not at open, only disables the cache for that process
  (`Registry.cacheFailed`, `src/accounts.zig:166`), so every later run hits it
  again. The rebuild path also deletes only the main file
  (`src/accounts.zig:253`), so a stale `-wal`/`-shm` may be replayed into the
  new database.
  *Fix:* on `SqliteCorrupt`, close the store and delete `<db>`, `<db>-wal` and
  `<db>-shm`, so the next open rebuilds. Do the same in `openCache`.

- [ ] **Embedded NUL truncates converted text.** After `charconv`, the length
  comes from `strlen(converted)` (`src/c/mime.c:91`), which stops at the first
  U+0000.
  *Fix:* use `charconv_buffer`, which returns the converted length, and free
  the result with `charconv_buffer_free`.

- [ ] **Password wiping is overstated in the spec.** `Account.wipe`
  (`src/config.zig:16`) zeroes only the arena copy. The values in
  `init.environ_map`, the process environment block, and libetpan's stream
  write buffer are never cleared. Spec §4 (line 132) promises more than that.
  *Fix:* zero the `environ_map` values for `IMAP_*_PASSWORD` after loading,
  and reword the spec to promise only what is achievable (the environment is
  inherent to `op run`; see ADR 0007).

- [ ] **Criteria ending in `{digits}` are not rejected.**
  `validate.criteria` (`src/validate.zig:31`) blocks CR, LF and NUL only.
  Criteria ending in `{5}` or `{5+}` would start an IMAP literal if
  libetpan's `mailimap_custom_command` stopped appending its trailing space.
  That behaviour is undocumented. It is not exploitable today, because the
  literal's bytes would come from the client.
  *Fix:* reject criteria whose trimmed end matches `\{\d+\+?\}`, and add a
  test.

## From the filters/sanitization review (2026-10-07)

- [ ] **Withheld header entries can be budget-omitted.** In `get_header` /
  `get_header_field`, withheld entries pass through `Budget.admit`; spec §5.2
  says withheld markers stay as they are. *Fix:* skip the budget for withheld
  entries.
- [ ] **Budget counts raw bytes, not JSON-escaped bytes.** Output can exceed
  `TP_IMAP_MCP_MAX_RESPONSE_BYTES` by up to ~2× for escape-heavy text.
  *Fix:* count escaped length, or lower the effective budget.
- [ ] **A "successful" RFC 2047 decode can be empty.** A leading encoded NUL
  (`=?UTF-8?B?AFJl...?=`) decodes to `""` (`strlen` in `mime.c`
  `tpi_decode_header_value`), so filters miss it. *Fix:* fall back to the raw
  value when the decode is empty but the raw value is not, or when the parse
  index is not at the end.
- [ ] **Regex patterns with an embedded NUL are silently cut.** *Fix:* reject
  them in `filter/load.zig`.
- [ ] **Elements hidden by default in browsers are rendered.** `noembed`,
  `noframes`, `datalist`, `dialog` without `open`. *Fix:* add them to the
  dropped elements.
- [ ] **`</ text>` and `</1 text>` are bogus comments in browsers** but are
  emitted as text. *Fix:* treat `</` followed by a non-letter as a comment up
  to `>`.
- [ ] **`href` is not checked for whitespace or length.** A newline inside a
  safe URL adds a line to the output. *Fix:* reject URLs with whitespace and
  cap their length.
- [ ] **Content loss, no security impact:** `<svg/>` (self-closing) drops the
  rest of the document; an unclosed `<p hidden>` hides everything after it
  (browsers close `p` implicitly). *Fix:* honour self-closing for raw-text
  elements; implicit `p` closing.
- [ ] **Spoofed marker headers.** A real `X-TP-IMAP-MCP-Withheld`/`-Omitted`
  header in a message appears in `get_header` output. *Fix:* drop the
  `x-tp-imap-mcp-*` namespace from message headers.
- [ ] **Diagnostics lose non-UTF-8 server text.** `unicode.cleanInto` returns
  `""` for invalid UTF-8 (`accounts.zig`). *Fix:* `sanitizeUtf8` before
  cleaning.
- [ ] **`Registry.active_filters` defaults to none** (fail-open by
  construction; `main` sets it). *Fix:* make it a required `init` parameter.
- [ ] **Cleaned mailbox names can't be passed back** when cleaning changed
  them. *Fix:* return the raw name alongside, or map cleaned names back.
- [ ] **Entity-encoded markup** (`&lt;script&gt;`) is rendered as literal
  `<script>` text (faithful, not markup); the stress test does not assert on
  it. *Fix:* decide whether to neutralize; add an assertion either way.
