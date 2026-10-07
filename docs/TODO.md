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
