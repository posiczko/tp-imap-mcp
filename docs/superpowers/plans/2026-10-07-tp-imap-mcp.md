# tp-imap-mcp Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A Zig 0.17 MCP server (stdio) that mirrors vivier/imap-mcp-server's tools across multiple IMAP accounts, using libetpan for IMAP and MIME, with credentials injected by `op run` and an XDG/SQLite cache for the mailbox list and message headers/sizes.

**Architecture:** A flat C shim (`src/c/`) wraps libetpan and is called from Zig through hand-written `extern` declarations (Zig 0.17 has no `@cImport`). SQLite (system `libsqlite3`) is reached the same way. Above them, small Zig modules handle config, account sessions with reconnect, the per-account cache, validation, header/body rendering, tool handlers, and newline-delimited JSON-RPC over stdio.

**Tech Stack:** Zig 0.17.0, libetpan 1.10.1 (Homebrew, via pkg-config), system libsqlite3, libc, `std.json`, `std.Io`.

**Spec:** `docs/superpowers/specs/2026-10-07-tp-imap-mcp-design.md` (decisions: `docs/adr/0001`–`0015`)

**Provenance:** Every code block below was compiled and tested before this plan was written: 61/61 unit tests pass. The pre-cache version passed 12/12 live checks against the user's Dovecot server; the cache's live checks run for the first time in Task 14. Copy code exactly; if something does not compile, the environment differs from the one verified — stop and report rather than improvising.

## Global Constraints

- Zig 0.17.0 exactly (`zig version`). No `@cImport` (removed in 0.17); C is reached only through `src/imap/c.zig` externs that mirror `src/c/tpi.h`.
- Platform: macOS on Apple Silicon. libetpan comes from Homebrew (`brew install libetpan`; `pkg-config --libs libetpan` must succeed).
- No Zig package dependencies (`build.zig.zon` keeps an empty `dependencies`). C libraries: Homebrew libetpan and the OS `libsqlite3` only. Ask the user before adding any dependency.
- Local data lives only in XDG locations (`$XDG_CACHE_HOME/tp-imap-mcp` or `~/.cache/tp-imap-mcp`); tests and itest never write to `~/.cache`.
- A cache failure must never fail a tool call.
- C sources compile with `-std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror`.
- Passwords never appear in logs, diagnostics, tool output, or test output.
- `criteria` is sent verbatim: CR, LF, NUL must be rejected before it reaches the server.
- Read tools use `EXAMINE` and `BODY.PEEK`; nothing a read tool does may set `\Seen`.
- Git: never run git commands. The user performs all git operations; each task ends with a hand-off.
- Unit tests must not touch the network except connecting to `127.0.0.1:1` to provoke a refused connection.

## Review Focus

1. Invalid UTF-8 from the server (8-bit header values, undeclared-charset bodies) must never yield invalid JSON — pinned by `text.zig` "sanitized bytes always serialize to valid JSON" (Task 2).
2. Mailbox names containing `"`, `\`, `%`, `*`, or the empty root name must pass through modified-UTF-7 encoding unchanged so libetpan can quote them — pinned by `mutf7.zig` "quoting-sensitive characters pass through unchanged" (Task 4).
3. A header block starting with a continuation line or containing colon-less junk must parse without crashing and without inventing headers — pinned by `headers.zig` "leading continuation and colon-less lines are skipped" (Task 6).
4. A trailing comma in `IMAP_ACCOUNTS` (`a,`) is a common typo and must be a clear config error, not a silent extra account — pinned in `config.zig` "rejects missing, malformed, duplicate" (Task 7).
5. JSON-RPC `id: 0` must be echoed (not treated as absent) and `tools/call` without `arguments` must work for argument-less tools — pinned by `mcp.zig` "id 0 is echoed and arguments may be omitted" (Task 13).
6. A cache file that is not a database (truncated, overwritten) must be rebuilt, not crash or disable the account's tools — pinned by `store.zig` "a non-database file reports SqliteCorrupt" (Task 10) and `accounts.zig` "corrupt cache file is rebuilt" (Task 11).

## File Map

| File | Task | Responsibility |
|---|---|---|
| `build.zig` | 1 | Exe, `run`, `test`, `itest` steps; C shim + libetpan linkage |
| `.gitignore` | 1 | Ignore build output and the real env file |
| `src/c/tpi.h`, `src/c/session.c`, `src/c/mime.c` | 1 | Flat C API over libetpan |
| `src/imap/c.zig` | 1 | Extern declarations for `tpi.h` |
| `src/imap/session.zig` | 1 | Zig wrapper; copies C results into arenas |
| `src/text.zig` | 2 | UTF-8 sanitizing, CRLF/LF conversion |
| `src/body.zig`, `src/mime_test.zig`, `src/testdata/*.eml` | 3 | Body rendering + fixtures |
| `src/imap/mutf7.zig` | 4 | Modified UTF-7 mailbox names |
| `src/validate.zig` | 5 | Injection-defense argument checks |
| `src/headers.zig` | 6 | Header block parsing |
| `src/config.zig` | 7 | Environment → accounts and cache settings (XDG) |
| `src/listmatch.zig` | 8 | Local LIST pattern matching |
| `src/cache/sqlite.zig` | 9 | SQLite externs and thin wrapper |
| `src/cache/store.zig` | 10 | Cache schema and operations |
| `src/accounts.zig` | 11 | Session registry, reconnect, cache, mailbox list, drafts discovery |
| `src/descriptions.zig`, `src/tools.zig` | 12 | Tool schemas and handlers (incl. cached headers, `clear_cache`) |
| `src/prompts.zig`, `src/mcp.zig` | 13 | Prompts and JSON-RPC loop |
| `src/main.zig`, `src/itest.zig`, `imap.env.example` | 1, 14 | Entry point, live checks, config example |

---

### Task 1: Build system, C shim, and session wrapper

**Files:**
- Delete: `src/root.zig` (zig init scaffold, unused)
- Replace: `build.zig`, `src/main.zig`
- Create: `.gitignore`, `src/itest.zig` (stub), `src/c/tpi.h`, `src/c/session.c`, `src/c/mime.c`, `src/imap/c.zig`, `src/imap/session.zig`
- Keep: `build.zig.zon` unchanged (its `paths` already include `src`)

**Interfaces:**
- Produces (`src/imap/session.zig`): `Error` = `error{ConnectFailed, ConnectionLost, ServerRejected, ProtocolError} || Allocator.Error`;
  `Session.connect(host: [:0]const u8, port: u16, timeout_sec: c_long) Error!Session`; methods `close`, `abandon`,
  `lastResponse() []const u8`, `login`, `noop`, `examine`, `select`, `uidSearch(arena, criteria) Error![]u32`,
  `list(arena, reference, pattern) Error![]Mailbox`, `status(mailbox) Error!Status`,
  `uidFetch(arena, uids, What) Error![]Fetched`, `uidStoreFlags(arena, uids, add, flags) Error!void`, `append(mailbox, data) Error!void`;
  types `Mailbox{name, delimiter: ?u8, flags}`, `Status{messages, recent, unseen}`, `What{header, body, size, flags: bool}`,
  `Fetched{uid, size, data: ?[]const u8, flags: ?[]const []const u8}`;
  `extractText(arena, message, subtype: [:0]const u8) Error!Extracted` where `Extracted = union(enum){ text, encrypted }`.
- Produces (`build.zig`): steps `test` (root `src/main.zig`), `run`, `itest` (root `src/itest.zig`); every module links libetpan and the system `libsqlite3` (used from Task 9).

- [ ] **Step 1: Confirm toolchain**

Run: `zig version && pkg-config --modversion libetpan`
Expected: `0.17.0` and `1.10.1`. If libetpan is missing: `brew install libetpan` (the user approved libetpan via Homebrew). SQLite needs nothing: the macOS SDK provides `libsqlite3`.

- [ ] **Step 2: Write the failing test**

Delete `src/root.zig`. Replace `src/main.zig` with:

```zig
//! tp-imap-mcp: an MCP server exposing IMAP mailboxes over stdio.

pub fn main() void {}

test {
    _ = @import("imap/session.zig");
}
```

Create `src/itest.zig` (stub, replaced in Task 11):

```zig
pub fn main() void {}
```

Create `src/imap/session.zig` with only its test:

```zig
const testing = std.testing;

test "splitFlags" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const fs = try splitFlags(arena_state.allocator(), "\\Seen $label1 NonJunk");
    try testing.expectEqual(3, fs.len);
    try testing.expectEqualStrings("$label1", fs[1]);
    try testing.expectEqual(0, (try splitFlags(arena_state.allocator(), "")).len);
}
```

Replace `build.zig`:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = imapModule(b, "src/main.zig", target, optimize);
    const exe = b.addExecutable(.{ .name = "tp_imap_mcp", .root_module = exe_mod });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the MCP server on stdio").dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{ .root_module = exe_mod });
    b.step("test", "Run unit tests (no network)").dependOn(&b.addRunArtifact(unit_tests).step);

    // Live, read-only checks against a real server; run under `op run`.
    const itest = b.addExecutable(.{
        .name = "itest",
        .root_module = imapModule(b, "src/itest.zig", target, optimize),
    });
    const run_itest = b.addRunArtifact(itest);
    run_itest.addPassthruArgs();
    b.step("itest", "Run live integration checks (needs IMAP_* env)").dependOn(&run_itest.step);
}

/// A module that can call libetpan through the C shim in src/c.
fn imapModule(b: *std.Build, root: []const u8, target: std.Build.ResolvedTarget, optimize: std.lang.OptimizeMode) *std.Build.Module {
    const mod = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    mod.addIncludePath(b.path("src/c"));
    mod.addCSourceFiles(.{
        .files = &.{ "src/c/session.c", "src/c/mime.c" },
        .flags = &.{ "-std=c11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Werror" },
    });
    mod.linkSystemLibrary("etpan", .{});
    mod.linkSystemLibrary("sqlite3", .{});
    return mod;
}
```

Create `.gitignore`:

```
.zig-cache/
zig-out/
zig-pkg/
imap.env
```

- [ ] **Step 3: Run test to verify it fails**

Run: `zig build test --summary all`
Expected: the build fails (missing `src/c/*.c` sources and/or `use of undeclared identifier 'std'` in `src/imap/session.zig`).

- [ ] **Step 4: Write the C shim**

`src/c/tpi.h`:

```c
/* Flat C interface over libetpan, consumed from Zig via hand-written externs
 * in src/imap/c.zig. Keep the two in sync. All returned buffers are malloc'd
 * and released with the matching tpi_*_free function. */
#ifndef TPI_H
#define TPI_H

#include <stddef.h>
#include <stdint.h>

enum {
  TPI_OK = 0,
  TPI_ERR_CONNECT = 1,  /* TCP/TLS connect failed */
  TPI_ERR_STREAM = 2,   /* connection dropped mid-command */
  TPI_ERR_SERVER = 3,   /* server replied NO or BAD; see tpi_last_response */
  TPI_ERR_PARSE = 4,    /* unparseable server response */
  TPI_ERR_MEMORY = 5,
  TPI_ERR_OTHER = 6,
};

typedef struct tpi_session tpi_session;

tpi_session *tpi_new(void);
void tpi_free(tpi_session *s);

/* Implicit TLS connect. timeout_sec applies to every network operation. */
int tpi_connect(tpi_session *s, const char *host, uint16_t port, long timeout_sec);
int tpi_login(tpi_session *s, const char *user, const char *password);
int tpi_noop(tpi_session *s);
int tpi_logout(tpi_session *s);
/* On success *uidvalidity is the mailbox's UIDVALIDITY (0 if the server did
 * not report one). */
int tpi_examine(tpi_session *s, const char *mailbox, uint32_t *uidvalidity);
int tpi_select(tpi_session *s, const char *mailbox, uint32_t *uidvalidity);

/* Text of the last server response line (e.g. "Unknown argument BOGUSKEY"),
 * or "" if none. Valid until the next call on this session. */
const char *tpi_last_response(tpi_session *s);

/* Sends "UID SEARCH <criteria>" verbatim; caller has already validated it. */
int tpi_uid_search(tpi_session *s, const char *criteria, uint32_t **uids, size_t *count);
void tpi_uids_free(uint32_t *uids);

typedef struct {
  char *name;   /* raw (modified UTF-7) mailbox name */
  char delimiter; /* 0 when the server reports NIL */
  char *flags;  /* space-separated, each with leading backslash */
} tpi_mailbox;

int tpi_list(tpi_session *s, const char *reference, const char *pattern,
             tpi_mailbox **out, size_t *count);
void tpi_mailboxes_free(tpi_mailbox *items, size_t count);

typedef struct {
  uint32_t messages;
  uint32_t recent;
  uint32_t unseen;
} tpi_status;

int tpi_status_get(tpi_session *s, const char *mailbox, tpi_status *out);

enum {
  TPI_FETCH_HEADER = 1, /* BODY.PEEK[HEADER] */
  TPI_FETCH_BODY = 2,   /* BODY.PEEK[]       */
  TPI_FETCH_SIZE = 4,   /* RFC822.SIZE       */
  TPI_FETCH_FLAGS = 8,  /* FLAGS             */
};

typedef struct {
  uint32_t uid;
  uint32_t size;  /* RFC822.SIZE, valid with TPI_FETCH_SIZE */
  char *data;     /* header or full message bytes; NULL if not fetched */
  size_t data_len;
  char *flags;    /* space-separated; NULL if not fetched */
} tpi_fetch_item;

/* Items come back in server order; the Zig layer aligns them to input. */
int tpi_uid_fetch(tpi_session *s, const uint32_t *uids, size_t uid_count, int what,
                  tpi_fetch_item **out, size_t *count);
void tpi_fetch_free(tpi_fetch_item *items, size_t count);

/* UID STORE <uids> +FLAGS/-FLAGS (<flags>). Flags are "\\Seen"-style system
 * flags or keyword atoms, already validated. */
int tpi_uid_store_flags(tpi_session *s, const uint32_t *uids, size_t uid_count, int add,
                        const char *const *flags, size_t flag_count);

int tpi_append(tpi_session *s, const char *mailbox, const char *data, size_t len);

/* MIME: concatenate every non-attachment text/<subtype> part of a full
 * RFC 822 message, transfer-decoded and converted to UTF-8 where possible.
 * If the top-level type is multipart/encrypted, *encrypted_protocol is set to
 * a malloc'd copy of its protocol parameter ("" if absent) and *out is NULL.
 * Release *out and *encrypted_protocol with tpi_buf_free. */
int tpi_extract_text(const char *msg, size_t len, const char *subtype,
                     char **out, size_t *out_len, char **encrypted_protocol);
void tpi_buf_free(char *buf);

#endif
```

`src/c/session.c`:

```c
/* IMAP session half of the tpi shim. See tpi.h for the contract. */
#include "tpi.h"

#include <libetpan/libetpan.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct tpi_session {
  mailimap *imap;
};

static int map_error(int r) {
  switch (r) {
  case MAILIMAP_NO_ERROR:
  case MAILIMAP_NO_ERROR_AUTHENTICATED:
  case MAILIMAP_NO_ERROR_NON_AUTHENTICATED:
    return TPI_OK;
  case MAILIMAP_ERROR_STREAM:
    return TPI_ERR_STREAM;
  case MAILIMAP_ERROR_PARSE:
    return TPI_ERR_PARSE;
  case MAILIMAP_ERROR_MEMORY:
    return TPI_ERR_MEMORY;
  case MAILIMAP_ERROR_CONNECTION_REFUSED:
  case MAILIMAP_ERROR_SSL:
    return TPI_ERR_CONNECT;
  default:
    return TPI_ERR_SERVER;
  }
}

tpi_session *tpi_new(void) {
  tpi_session *s = calloc(1, sizeof(*s));
  if (s == NULL)
    return NULL;
  s->imap = mailimap_new(0, NULL);
  if (s->imap == NULL) {
    free(s);
    return NULL;
  }
  return s;
}

void tpi_free(tpi_session *s) {
  if (s == NULL)
    return;
  mailimap_free(s->imap);
  free(s);
}

int tpi_connect(tpi_session *s, const char *host, uint16_t port, long timeout_sec) {
  mailimap_set_timeout(s->imap, (time_t)timeout_sec);
  int r = mailimap_ssl_connect(s->imap, host, port);
  if (r == MAILIMAP_NO_ERROR_AUTHENTICATED || r == MAILIMAP_NO_ERROR_NON_AUTHENTICATED)
    return TPI_OK;
  return r == MAILIMAP_ERROR_MEMORY ? TPI_ERR_MEMORY : TPI_ERR_CONNECT;
}

int tpi_login(tpi_session *s, const char *user, const char *password) {
  return map_error(mailimap_login(s->imap, user, password));
}

int tpi_noop(tpi_session *s) { return map_error(mailimap_noop(s->imap)); }

int tpi_logout(tpi_session *s) { return map_error(mailimap_logout(s->imap)); }

static uint32_t selected_uidvalidity(tpi_session *s) {
  return s->imap->imap_selection_info != NULL ? s->imap->imap_selection_info->sel_uidvalidity : 0;
}

int tpi_examine(tpi_session *s, const char *mailbox, uint32_t *uidvalidity) {
  *uidvalidity = 0;
  int rc = map_error(mailimap_examine(s->imap, mailbox));
  if (rc == TPI_OK)
    *uidvalidity = selected_uidvalidity(s);
  return rc;
}

int tpi_select(tpi_session *s, const char *mailbox, uint32_t *uidvalidity) {
  *uidvalidity = 0;
  int rc = map_error(mailimap_select(s->imap, mailbox));
  if (rc == TPI_OK)
    *uidvalidity = selected_uidvalidity(s);
  return rc;
}

const char *tpi_last_response(tpi_session *s) {
  return s->imap->imap_response != NULL ? s->imap->imap_response : "";
}

int tpi_uid_search(tpi_session *s, const char *criteria, uint32_t **uids, size_t *count) {
  *uids = NULL;
  *count = 0;

  size_t cmd_len = strlen("UID SEARCH ") + strlen(criteria) + 1;
  char *cmd = malloc(cmd_len);
  if (cmd == NULL)
    return TPI_ERR_MEMORY;
  strcpy(cmd, "UID SEARCH ");
  strcat(cmd, criteria);

  /* mailimap_custom_command runs the normal response parser, which leaves
   * untagged SEARCH results in imap_response_info->rsp_search_result. */
  int r = mailimap_custom_command(s->imap, cmd);
  free(cmd);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);

  clist *res = s->imap->imap_response_info != NULL
                   ? s->imap->imap_response_info->rsp_search_result
                   : NULL;
  if (res == NULL || clist_count(res) == 0)
    return TPI_OK;

  uint32_t *out = malloc(sizeof(uint32_t) * (size_t)clist_count(res));
  if (out == NULL)
    return TPI_ERR_MEMORY;
  size_t n = 0;
  for (clistiter *it = clist_begin(res); it != NULL; it = clist_next(it))
    out[n++] = *(uint32_t *)clist_content(it);
  *uids = out;
  *count = n;
  return TPI_OK;
}

void tpi_uids_free(uint32_t *uids) { free(uids); }

/* Appends "\<flag>" to a growing space-separated buffer. */
static int flags_append(char **buf, size_t *len, const char *prefix, const char *flag) {
  size_t add = (*len > 0 ? 1 : 0) + strlen(prefix) + strlen(flag);
  char *grown = realloc(*buf, *len + add + 1);
  if (grown == NULL)
    return -1;
  char *p = grown + *len;
  if (*len > 0)
    *p++ = ' ';
  strcpy(p, prefix);
  strcat(p, flag);
  *buf = grown;
  *len += add;
  return 0;
}

static char *empty_string(void) { return calloc(1, 1); }

static int mailbox_flags(struct mailimap_mbx_list_flags *mf, char **out) {
  char *buf = NULL;
  size_t len = 0;
  if (mf != NULL) {
    if (mf->mbf_type == MAILIMAP_MBX_LIST_FLAGS_SFLAG) {
      const char *sflag = NULL;
      switch (mf->mbf_sflag) {
      case MAILIMAP_MBX_LIST_SFLAG_MARKED: sflag = "Marked"; break;
      case MAILIMAP_MBX_LIST_SFLAG_NOSELECT: sflag = "Noselect"; break;
      case MAILIMAP_MBX_LIST_SFLAG_UNMARKED: sflag = "Unmarked"; break;
      default: break;
      }
      if (sflag != NULL && flags_append(&buf, &len, "\\", sflag) != 0)
        goto oom;
    }
    for (clistiter *it = clist_begin(mf->mbf_oflags); it != NULL; it = clist_next(it)) {
      struct mailimap_mbx_list_oflag *of = clist_content(it);
      const char *name = of->of_type == MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS ? "Noinferiors"
                                                                            : of->of_flag_ext;
      if (name != NULL && flags_append(&buf, &len, "\\", name) != 0)
        goto oom;
    }
  }
  *out = buf != NULL ? buf : empty_string();
  return *out != NULL ? TPI_OK : TPI_ERR_MEMORY;
oom:
  free(buf);
  return TPI_ERR_MEMORY;
}

int tpi_list(tpi_session *s, const char *reference, const char *pattern,
             tpi_mailbox **out, size_t *count) {
  *out = NULL;
  *count = 0;
  clist *result = NULL;
  int r = mailimap_list(s->imap, reference, pattern, &result);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);

  int rc = TPI_OK;
  size_t total = (size_t)clist_count(result);
  tpi_mailbox *items = calloc(total > 0 ? total : 1, sizeof(tpi_mailbox));
  if (items == NULL) {
    rc = TPI_ERR_MEMORY;
    goto done;
  }
  size_t n = 0;
  for (clistiter *it = clist_begin(result); it != NULL; it = clist_next(it)) {
    struct mailimap_mailbox_list *mb = clist_content(it);
    items[n].name = strdup(mb->mb_name);
    items[n].delimiter = mb->mb_delimiter;
    if (items[n].name == NULL || mailbox_flags(mb->mb_flag, &items[n].flags) != TPI_OK) {
      n++;
      tpi_mailboxes_free(items, n);
      rc = TPI_ERR_MEMORY;
      goto done;
    }
    n++;
  }
  *out = items;
  *count = n;
done:
  mailimap_list_result_free(result);
  return rc;
}

void tpi_mailboxes_free(tpi_mailbox *items, size_t count) {
  if (items == NULL)
    return;
  for (size_t i = 0; i < count; i++) {
    free(items[i].name);
    free(items[i].flags);
  }
  free(items);
}

int tpi_status_get(tpi_session *s, const char *mailbox, tpi_status *out) {
  memset(out, 0, sizeof(*out));
  struct mailimap_status_att_list *atts = mailimap_status_att_list_new_empty();
  if (atts == NULL)
    return TPI_ERR_MEMORY;
  if (mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_MESSAGES) != MAILIMAP_NO_ERROR ||
      mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_RECENT) != MAILIMAP_NO_ERROR ||
      mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_UNSEEN) != MAILIMAP_NO_ERROR) {
    mailimap_status_att_list_free(atts);
    return TPI_ERR_MEMORY;
  }
  struct mailimap_mailbox_data_status *st = NULL;
  int r = mailimap_status(s->imap, mailbox, atts, &st);
  mailimap_status_att_list_free(atts);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);
  if (st->st_info_list != NULL) {
    for (clistiter *it = clist_begin(st->st_info_list); it != NULL; it = clist_next(it)) {
      struct mailimap_status_info *info = clist_content(it);
      switch (info->st_att) {
      case MAILIMAP_STATUS_ATT_MESSAGES: out->messages = info->st_value; break;
      case MAILIMAP_STATUS_ATT_RECENT: out->recent = info->st_value; break;
      case MAILIMAP_STATUS_ATT_UNSEEN: out->unseen = info->st_value; break;
      default: break;
      }
    }
  }
  mailimap_mailbox_data_status_free(st);
  return TPI_OK;
}

static struct mailimap_set *uid_set(const uint32_t *uids, size_t count) {
  struct mailimap_set *set = mailimap_set_new_empty();
  if (set == NULL)
    return NULL;
  for (size_t i = 0; i < count; i++) {
    if (mailimap_set_add_single(set, uids[i]) != MAILIMAP_NO_ERROR) {
      mailimap_set_free(set);
      return NULL;
    }
  }
  return set;
}

static int add_att(struct mailimap_fetch_type *ft, struct mailimap_fetch_att *att) {
  if (att == NULL)
    return -1;
  if (mailimap_fetch_type_new_fetch_att_list_add(ft, att) != MAILIMAP_NO_ERROR) {
    mailimap_fetch_att_free(att);
    return -1;
  }
  return 0;
}

static struct mailimap_fetch_type *fetch_type(int what) {
  struct mailimap_fetch_type *ft = mailimap_fetch_type_new_fetch_att_list_empty();
  if (ft == NULL)
    return NULL;
  if (add_att(ft, mailimap_fetch_att_new_uid()) != 0)
    goto fail;
  if ((what & TPI_FETCH_SIZE) && add_att(ft, mailimap_fetch_att_new_rfc822_size()) != 0)
    goto fail;
  if ((what & TPI_FETCH_FLAGS) && add_att(ft, mailimap_fetch_att_new_flags()) != 0)
    goto fail;
  if (what & (TPI_FETCH_HEADER | TPI_FETCH_BODY)) {
    struct mailimap_section *sec =
        (what & TPI_FETCH_BODY) ? mailimap_section_new(NULL) : mailimap_section_new_header();
    if (sec == NULL)
      goto fail;
    struct mailimap_fetch_att *att = mailimap_fetch_att_new_body_peek_section(sec);
    if (att == NULL) {
      mailimap_section_free(sec);
      goto fail;
    }
    if (add_att(ft, att) != 0)
      goto fail;
  }
  return ft;
fail:
  mailimap_fetch_type_free(ft);
  return NULL;
}

static int fetch_flags(struct mailimap_msg_att_dynamic *dyn, char **out) {
  char *buf = NULL;
  size_t len = 0;
  if (dyn != NULL && dyn->att_list != NULL) {
    for (clistiter *it = clist_begin(dyn->att_list); it != NULL; it = clist_next(it)) {
      struct mailimap_flag_fetch *ff = clist_content(it);
      int rc = 0;
      if (ff->fl_type == MAILIMAP_FLAG_FETCH_RECENT) {
        rc = flags_append(&buf, &len, "\\", "Recent");
      } else if (ff->fl_flag != NULL) {
        struct mailimap_flag *f = ff->fl_flag;
        switch (f->fl_type) {
        case MAILIMAP_FLAG_ANSWERED: rc = flags_append(&buf, &len, "\\", "Answered"); break;
        case MAILIMAP_FLAG_FLAGGED: rc = flags_append(&buf, &len, "\\", "Flagged"); break;
        case MAILIMAP_FLAG_DELETED: rc = flags_append(&buf, &len, "\\", "Deleted"); break;
        case MAILIMAP_FLAG_SEEN: rc = flags_append(&buf, &len, "\\", "Seen"); break;
        case MAILIMAP_FLAG_DRAFT: rc = flags_append(&buf, &len, "\\", "Draft"); break;
        case MAILIMAP_FLAG_KEYWORD:
          if (f->fl_data.fl_keyword != NULL)
            rc = flags_append(&buf, &len, "", f->fl_data.fl_keyword);
          break;
        case MAILIMAP_FLAG_EXTENSION:
          if (f->fl_data.fl_extension != NULL)
            rc = flags_append(&buf, &len, "\\", f->fl_data.fl_extension);
          break;
        default: break;
        }
      }
      if (rc != 0) {
        free(buf);
        return TPI_ERR_MEMORY;
      }
    }
  }
  *out = buf != NULL ? buf : empty_string();
  return *out != NULL ? TPI_OK : TPI_ERR_MEMORY;
}

static int fill_item(struct mailimap_msg_att *ma, int what, tpi_fetch_item *item) {
  for (clistiter *it = clist_begin(ma->att_list); it != NULL; it = clist_next(it)) {
    struct mailimap_msg_att_item *ai = clist_content(it);
    if (ai->att_type == MAILIMAP_MSG_ATT_ITEM_DYNAMIC) {
      if ((what & TPI_FETCH_FLAGS) && item->flags == NULL &&
          fetch_flags(ai->att_data.att_dyn, &item->flags) != TPI_OK)
        return TPI_ERR_MEMORY;
      continue;
    }
    if (ai->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC)
      continue;
    struct mailimap_msg_att_static *st = ai->att_data.att_static;
    switch (st->att_type) {
    case MAILIMAP_MSG_ATT_UID: item->uid = st->att_data.att_uid; break;
    case MAILIMAP_MSG_ATT_RFC822_SIZE: item->size = st->att_data.att_rfc822_size; break;
    case MAILIMAP_MSG_ATT_BODY_SECTION: {
      struct mailimap_msg_att_body_section *bs = st->att_data.att_body_section;
      if (bs == NULL || item->data != NULL)
        break;
      size_t n = bs->sec_body_part != NULL ? bs->sec_length : 0;
      item->data = malloc(n + 1);
      if (item->data == NULL)
        return TPI_ERR_MEMORY;
      if (n > 0)
        memcpy(item->data, bs->sec_body_part, n);
      item->data[n] = '\0';
      item->data_len = n;
      break;
    }
    default: break;
    }
  }
  /* FLAGS requested but server sent an empty list: report "" not NULL. */
  if ((what & TPI_FETCH_FLAGS) && item->flags == NULL) {
    item->flags = empty_string();
    if (item->flags == NULL)
      return TPI_ERR_MEMORY;
  }
  return TPI_OK;
}

int tpi_uid_fetch(tpi_session *s, const uint32_t *uids, size_t uid_count, int what,
                  tpi_fetch_item **out, size_t *count) {
  *out = NULL;
  *count = 0;
  struct mailimap_set *set = uid_set(uids, uid_count);
  if (set == NULL)
    return TPI_ERR_MEMORY;
  struct mailimap_fetch_type *ft = fetch_type(what);
  if (ft == NULL) {
    mailimap_set_free(set);
    return TPI_ERR_MEMORY;
  }
  clist *result = NULL;
  int r = mailimap_uid_fetch(s->imap, set, ft, &result);
  mailimap_fetch_type_free(ft);
  mailimap_set_free(set);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);

  int rc = TPI_OK;
  size_t total = (size_t)clist_count(result);
  tpi_fetch_item *items = calloc(total > 0 ? total : 1, sizeof(tpi_fetch_item));
  if (items == NULL) {
    rc = TPI_ERR_MEMORY;
    goto done;
  }
  size_t n = 0;
  for (clistiter *it = clist_begin(result); it != NULL; it = clist_next(it)) {
    if (fill_item(clist_content(it), what, &items[n]) != TPI_OK) {
      tpi_fetch_free(items, n + 1);
      rc = TPI_ERR_MEMORY;
      goto done;
    }
    /* Servers may send unsolicited FETCH (e.g. flag updates) without UID. */
    if (items[n].uid != 0)
      n++;
    else {
      free(items[n].data);
      free(items[n].flags);
      memset(&items[n], 0, sizeof(items[n]));
    }
  }
  *out = items;
  *count = n;
done:
  mailimap_fetch_list_free(result);
  return rc;
}

void tpi_fetch_free(tpi_fetch_item *items, size_t count) {
  if (items == NULL)
    return;
  for (size_t i = 0; i < count; i++) {
    free(items[i].data);
    free(items[i].flags);
  }
  free(items);
}

static struct mailimap_flag *flag_from_string(const char *s) {
  if (s[0] != '\\') {
    char *kw = strdup(s);
    if (kw == NULL)
      return NULL;
    struct mailimap_flag *f = mailimap_flag_new_flag_keyword(kw);
    if (f == NULL)
      free(kw);
    return f;
  }
  const char *name = s + 1;
  if (strcasecmp(name, "Seen") == 0) return mailimap_flag_new_seen();
  if (strcasecmp(name, "Answered") == 0) return mailimap_flag_new_answered();
  if (strcasecmp(name, "Flagged") == 0) return mailimap_flag_new_flagged();
  if (strcasecmp(name, "Deleted") == 0) return mailimap_flag_new_deleted();
  if (strcasecmp(name, "Draft") == 0) return mailimap_flag_new_draft();
  char *ext = strdup(name);
  if (ext == NULL)
    return NULL;
  struct mailimap_flag *f = mailimap_flag_new_flag_extension(ext);
  if (f == NULL)
    free(ext);
  return f;
}

int tpi_uid_store_flags(tpi_session *s, const uint32_t *uids, size_t uid_count, int add,
                        const char *const *flags, size_t flag_count) {
  struct mailimap_flag_list *fl = mailimap_flag_list_new_empty();
  if (fl == NULL)
    return TPI_ERR_MEMORY;
  for (size_t i = 0; i < flag_count; i++) {
    struct mailimap_flag *f = flag_from_string(flags[i]);
    if (f == NULL || mailimap_flag_list_add(fl, f) != MAILIMAP_NO_ERROR) {
      if (f != NULL)
        mailimap_flag_free(f);
      mailimap_flag_list_free(fl);
      return TPI_ERR_MEMORY;
    }
  }
  struct mailimap_store_att_flags *sa = add ? mailimap_store_att_flags_new_add_flags(fl)
                                            : mailimap_store_att_flags_new_remove_flags(fl);
  if (sa == NULL) {
    mailimap_flag_list_free(fl);
    return TPI_ERR_MEMORY;
  }
  struct mailimap_set *set = uid_set(uids, uid_count);
  if (set == NULL) {
    mailimap_store_att_flags_free(sa);
    return TPI_ERR_MEMORY;
  }
  int r = mailimap_uid_store(s->imap, set, sa);
  mailimap_set_free(set);
  mailimap_store_att_flags_free(sa);
  return map_error(r);
}

int tpi_append(tpi_session *s, const char *mailbox, const char *data, size_t len) {
  return map_error(mailimap_append(s->imap, mailbox, NULL, NULL, data, len));
}
```

`src/c/mime.c`:

```c
/* MIME half of the tpi shim: text/<subtype> body extraction. */
#include "tpi.h"

#include <libetpan/libetpan.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
  char *buf;
  size_t len;
  size_t cap;
} growbuf;

static int grow_append(growbuf *g, const char *data, size_t n) {
  if (g->len + n + 1 > g->cap) {
    size_t cap = g->cap > 0 ? g->cap : 256;
    while (cap < g->len + n + 1)
      cap *= 2;
    char *p = realloc(g->buf, cap);
    if (p == NULL)
      return -1;
    g->buf = p;
    g->cap = cap;
  }
  memcpy(g->buf + g->len, data, n);
  g->len += n;
  g->buf[g->len] = '\0';
  return 0;
}

/* Content type of a part; RFC 2045 default is text/plain. */
static void content_type(struct mailmime_content *ct, const char **type, const char **subtype) {
  *type = "text";
  *subtype = "plain";
  if (ct == NULL || ct->ct_type == NULL)
    return;
  struct mailmime_type *t = ct->ct_type;
  if (t->tp_type == MAILMIME_TYPE_DISCRETE_TYPE && t->tp_data.tp_discrete_type != NULL) {
    struct mailmime_discrete_type *d = t->tp_data.tp_discrete_type;
    switch (d->dt_type) {
    case MAILMIME_DISCRETE_TYPE_TEXT: *type = "text"; break;
    case MAILMIME_DISCRETE_TYPE_IMAGE: *type = "image"; break;
    case MAILMIME_DISCRETE_TYPE_AUDIO: *type = "audio"; break;
    case MAILMIME_DISCRETE_TYPE_VIDEO: *type = "video"; break;
    case MAILMIME_DISCRETE_TYPE_APPLICATION: *type = "application"; break;
    default: *type = d->dt_extension != NULL ? d->dt_extension : "application"; break;
    }
  } else if (t->tp_type == MAILMIME_TYPE_COMPOSITE_TYPE && t->tp_data.tp_composite_type != NULL) {
    struct mailmime_composite_type *c = t->tp_data.tp_composite_type;
    *type = c->ct_type == MAILMIME_COMPOSITE_TYPE_MULTIPART ? "multipart" : "message";
  }
  *subtype = ct->ct_subtype != NULL ? ct->ct_subtype : "";
}

static const char *content_param(struct mailmime_content *ct, const char *name) {
  if (ct == NULL || ct->ct_parameters == NULL)
    return NULL;
  for (clistiter *it = clist_begin(ct->ct_parameters); it != NULL; it = clist_next(it)) {
    struct mailmime_parameter *p = clist_content(it);
    if (p->pa_name != NULL && strcasecmp(p->pa_name, name) == 0)
      return p->pa_value;
  }
  return NULL;
}

static int append_part(growbuf *g, struct mailmime *part) {
  struct mailmime_single_fields sf;
  mailmime_single_fields_init(&sf, part->mm_mime_fields, part->mm_content_type);
  /* Python's part.get_filename() skips these; so do we. */
  if (sf.fld_disposition_filename != NULL || sf.fld_content_name != NULL)
    return 0;

  struct mailmime_data *d = part->mm_data.mm_single;
  if (d == NULL || d->dt_type != MAILMIME_DATA_TEXT)
    return 0;

  int encoding = sf.fld_encoding != NULL ? sf.fld_encoding->enc_type : MAILMIME_MECHANISM_8BIT;
  size_t idx = 0;
  char *decoded = NULL;
  size_t decoded_len = 0;
  if (mailmime_part_parse(d->dt_data.dt_text.dt_data, d->dt_data.dt_text.dt_length, &idx,
                          encoding, &decoded, &decoded_len) != MAILIMF_NO_ERROR)
    return 0; /* undecodable part: skip, like a missing payload in Python */

  const char *charset = sf.fld_content_charset != NULL ? sf.fld_content_charset : "utf-8";
  int rc = 0;
  char *converted = NULL;
  if (strcasecmp(charset, "utf-8") != 0 && strcasecmp(charset, "us-ascii") != 0 &&
      charconv("utf-8", charset, decoded, decoded_len, &converted) == MAIL_CHARCONV_NO_ERROR) {
    rc = grow_append(g, converted, strlen(converted));
    charconv_buffer_free(converted);
  } else {
    /* UTF-8, ASCII, or unknown charset: pass bytes through; the Zig layer
     * replaces invalid UTF-8 with U+FFFD. */
    rc = grow_append(g, decoded, decoded_len);
  }
  mmap_string_unref(decoded);
  return rc;
}

/* Depth-first walk matching Python's Message.walk(). */
static int walk(growbuf *g, struct mailmime *mime, const char *want_subtype) {
  switch (mime->mm_type) {
  case MAILMIME_SINGLE: {
    const char *type, *subtype;
    content_type(mime->mm_content_type, &type, &subtype);
    if (strcasecmp(type, "text") == 0 && strcasecmp(subtype, want_subtype) == 0)
      return append_part(g, mime);
    return 0;
  }
  case MAILMIME_MULTIPLE:
    if (mime->mm_data.mm_multipart.mm_mp_list == NULL)
      return 0;
    for (clistiter *it = clist_begin(mime->mm_data.mm_multipart.mm_mp_list); it != NULL;
         it = clist_next(it)) {
      if (walk(g, clist_content(it), want_subtype) != 0)
        return -1;
    }
    return 0;
  case MAILMIME_MESSAGE:
    if (mime->mm_data.mm_message.mm_msg_mime != NULL)
      return walk(g, mime->mm_data.mm_message.mm_msg_mime, want_subtype);
    return 0;
  default:
    return 0;
  }
}

int tpi_extract_text(const char *msg, size_t len, const char *subtype,
                     char **out, size_t *out_len, char **encrypted_protocol) {
  *out = NULL;
  *out_len = 0;
  *encrypted_protocol = NULL;

  size_t idx = 0;
  struct mailmime *mime = NULL;
  if (mailmime_parse(msg, len, &idx, &mime) != MAILIMF_NO_ERROR)
    return TPI_ERR_PARSE;

  /* mailmime_parse wraps the message in a MAILMIME_MESSAGE node. */
  struct mailmime *top = mime;
  if (top->mm_type == MAILMIME_MESSAGE && top->mm_data.mm_message.mm_msg_mime != NULL)
    top = top->mm_data.mm_message.mm_msg_mime;

  const char *type, *sub;
  content_type(top->mm_content_type, &type, &sub);
  if (strcasecmp(type, "multipart") == 0 && strcasecmp(sub, "encrypted") == 0) {
    const char *proto = content_param(top->mm_content_type, "protocol");
    *encrypted_protocol = strdup(proto != NULL ? proto : "");
    mailmime_free(mime);
    return *encrypted_protocol != NULL ? TPI_OK : TPI_ERR_MEMORY;
  }

  growbuf g = {0};
  int rc = walk(&g, mime, subtype);
  mailmime_free(mime);
  if (rc != 0) {
    free(g.buf);
    return TPI_ERR_MEMORY;
  }
  if (g.buf == NULL) {
    g.buf = calloc(1, 1);
    if (g.buf == NULL)
      return TPI_ERR_MEMORY;
  }
  *out = g.buf;
  *out_len = g.len;
  return TPI_OK;
}

void tpi_buf_free(char *buf) { free(buf); }
```

- [ ] **Step 5: Write the externs and the Zig wrapper**

`src/imap/c.zig`:

```zig
//! Hand-written externs for src/c/tpi.h. Keep in sync with that header.

pub const OK: c_int = 0;
pub const ERR_CONNECT: c_int = 1;
pub const ERR_STREAM: c_int = 2;
pub const ERR_SERVER: c_int = 3;
pub const ERR_PARSE: c_int = 4;
pub const ERR_MEMORY: c_int = 5;
pub const ERR_OTHER: c_int = 6;

pub const FETCH_HEADER: c_int = 1;
pub const FETCH_BODY: c_int = 2;
pub const FETCH_SIZE: c_int = 4;
pub const FETCH_FLAGS: c_int = 8;

pub const Session = opaque {};

pub const Mailbox = extern struct {
    name: [*:0]u8,
    delimiter: u8,
    flags: [*:0]u8,
};

pub const Status = extern struct {
    messages: u32,
    recent: u32,
    unseen: u32,
};

pub const FetchItem = extern struct {
    uid: u32,
    size: u32,
    data: ?[*]u8,
    data_len: usize,
    flags: ?[*:0]u8,
};

pub extern fn tpi_new() ?*Session;
pub extern fn tpi_free(s: *Session) void;
pub extern fn tpi_connect(s: *Session, host: [*:0]const u8, port: u16, timeout_sec: c_long) c_int;
pub extern fn tpi_login(s: *Session, user: [*:0]const u8, password: [*:0]const u8) c_int;
pub extern fn tpi_noop(s: *Session) c_int;
pub extern fn tpi_logout(s: *Session) c_int;
pub extern fn tpi_examine(s: *Session, mailbox: [*:0]const u8, uidvalidity: *u32) c_int;
pub extern fn tpi_select(s: *Session, mailbox: [*:0]const u8, uidvalidity: *u32) c_int;
pub extern fn tpi_last_response(s: *Session) [*:0]const u8;

pub extern fn tpi_uid_search(s: *Session, criteria: [*:0]const u8, uids: *?[*]u32, count: *usize) c_int;
pub extern fn tpi_uids_free(uids: ?[*]u32) void;

pub extern fn tpi_list(s: *Session, reference: [*:0]const u8, pattern: [*:0]const u8, out: *?[*]Mailbox, count: *usize) c_int;
pub extern fn tpi_mailboxes_free(items: ?[*]Mailbox, count: usize) void;

pub extern fn tpi_status_get(s: *Session, mailbox: [*:0]const u8, out: *Status) c_int;

pub extern fn tpi_uid_fetch(s: *Session, uids: [*]const u32, uid_count: usize, what: c_int, out: *?[*]FetchItem, count: *usize) c_int;
pub extern fn tpi_fetch_free(items: ?[*]FetchItem, count: usize) void;

pub extern fn tpi_uid_store_flags(s: *Session, uids: [*]const u32, uid_count: usize, add: c_int, flags: [*]const [*:0]const u8, flag_count: usize) c_int;

pub extern fn tpi_append(s: *Session, mailbox: [*:0]const u8, data: [*]const u8, len: usize) c_int;

pub extern fn tpi_extract_text(msg: [*]const u8, len: usize, subtype: [*:0]const u8, out: *?[*]u8, out_len: *usize, encrypted_protocol: *?[*:0]u8) c_int;
pub extern fn tpi_buf_free(buf: ?[*]u8) void;
```

Insert above the test in `src/imap/session.zig`:

```zig
//! Zig wrapper over the tpi C shim. No C types escape this file: results are
//! copied into caller-provided arena memory and the C buffers freed at once.

const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @import("c.zig");

pub const Error = error{
    /// TCP/TLS connection could not be established.
    ConnectFailed,
    /// Connection dropped mid-command; the session is unusable.
    ConnectionLost,
    /// Server answered NO/BAD; see `Session.lastResponse`.
    ServerRejected,
    /// Server sent something libetpan could not parse.
    ProtocolError,
} || Allocator.Error;

fn check(rc: c_int) Error!void {
    return switch (rc) {
        c.OK => {},
        c.ERR_CONNECT => error.ConnectFailed,
        c.ERR_STREAM => error.ConnectionLost,
        c.ERR_SERVER => error.ServerRejected,
        c.ERR_PARSE => error.ProtocolError,
        c.ERR_MEMORY => error.OutOfMemory,
        else => error.ProtocolError,
    };
}

pub const Mailbox = struct {
    name: []const u8, // raw modified UTF-7
    delimiter: ?u8,
    flags: []const []const u8,
};

pub const Status = c.Status;

pub const What = packed struct {
    header: bool = false,
    body: bool = false,
    size: bool = false,
    flags: bool = false,

    fn bits(w: What) c_int {
        var b: c_int = 0;
        if (w.header) b |= c.FETCH_HEADER;
        if (w.body) b |= c.FETCH_BODY;
        if (w.size) b |= c.FETCH_SIZE;
        if (w.flags) b |= c.FETCH_FLAGS;
        return b;
    }
};

pub const Fetched = struct {
    uid: u32,
    size: u32,
    data: ?[]const u8,
    flags: ?[]const []const u8,
};

pub const Session = struct {
    handle: *c.Session,

    pub fn connect(host: [:0]const u8, port: u16, timeout_sec: c_long) Error!Session {
        const h = c.tpi_new() orelse return error.OutOfMemory;
        errdefer c.tpi_free(h);
        try check(c.tpi_connect(h, host, port, timeout_sec));
        return .{ .handle = h };
    }

    /// Sends LOGOUT (best effort) and frees the session.
    pub fn close(self: *Session) void {
        _ = c.tpi_logout(self.handle);
        c.tpi_free(self.handle);
        self.* = undefined;
    }

    /// Frees without talking to the server (for dead connections).
    pub fn abandon(self: *Session) void {
        c.tpi_free(self.handle);
        self.* = undefined;
    }

    pub fn lastResponse(self: *Session) []const u8 {
        return std.mem.sliceTo(c.tpi_last_response(self.handle), 0);
    }

    pub fn login(self: *Session, user: [:0]const u8, password: [:0]const u8) Error!void {
        try check(c.tpi_login(self.handle, user, password));
    }

    pub fn noop(self: *Session) Error!void {
        try check(c.tpi_noop(self.handle));
    }

    /// Opens `mailbox` read-only; returns its UIDVALIDITY (0 if unreported).
    pub fn examine(self: *Session, mailbox: [:0]const u8) Error!u32 {
        var uv: u32 = 0;
        try check(c.tpi_examine(self.handle, mailbox, &uv));
        return uv;
    }

    /// Opens `mailbox` read-write; returns its UIDVALIDITY (0 if unreported).
    pub fn select(self: *Session, mailbox: [:0]const u8) Error!u32 {
        var uv: u32 = 0;
        try check(c.tpi_select(self.handle, mailbox, &uv));
        return uv;
    }

    /// `criteria` must already be validated (no CR/LF/NUL).
    pub fn uidSearch(self: *Session, arena: Allocator, criteria: [:0]const u8) Error![]u32 {
        var ptr: ?[*]u32 = null;
        var n: usize = 0;
        try check(c.tpi_uid_search(self.handle, criteria, &ptr, &n));
        defer c.tpi_uids_free(ptr);
        const p = ptr orelse return &.{};
        return arena.dupe(u32, p[0..n]);
    }

    pub fn list(self: *Session, arena: Allocator, reference: [:0]const u8, pattern: [:0]const u8) Error![]Mailbox {
        var ptr: ?[*]c.Mailbox = null;
        var n: usize = 0;
        try check(c.tpi_list(self.handle, reference, pattern, &ptr, &n));
        defer c.tpi_mailboxes_free(ptr, n);
        const items = (ptr orelse return &.{})[0..n];
        const out = try arena.alloc(Mailbox, n);
        for (items, out) |src, *dst| dst.* = .{
            .name = try arena.dupe(u8, std.mem.sliceTo(src.name, 0)),
            .delimiter = if (src.delimiter == 0) null else src.delimiter,
            .flags = try splitFlags(arena, std.mem.sliceTo(src.flags, 0)),
        };
        return out;
    }

    pub fn status(self: *Session, mailbox: [:0]const u8) Error!Status {
        var st: c.Status = undefined;
        try check(c.tpi_status_get(self.handle, mailbox, &st));
        return st;
    }

    /// Results are in server order and only for UIDs that exist.
    pub fn uidFetch(self: *Session, arena: Allocator, uids: []const u32, what: What) Error![]Fetched {
        var ptr: ?[*]c.FetchItem = null;
        var n: usize = 0;
        try check(c.tpi_uid_fetch(self.handle, uids.ptr, uids.len, what.bits(), &ptr, &n));
        defer c.tpi_fetch_free(ptr, n);
        const items = (ptr orelse return &.{})[0..n];
        const out = try arena.alloc(Fetched, n);
        for (items, out) |src, *dst| dst.* = .{
            .uid = src.uid,
            .size = src.size,
            .data = if (src.data) |d| try arena.dupe(u8, d[0..src.data_len]) else null,
            .flags = if (src.flags) |f| try splitFlags(arena, std.mem.sliceTo(f, 0)) else null,
        };
        return out;
    }

    /// `flags` must already be validated.
    pub fn uidStoreFlags(self: *Session, arena: Allocator, uids: []const u32, add: bool, flags: []const []const u8) Error!void {
        const zs = try arena.alloc([*:0]const u8, flags.len);
        for (flags, zs) |f, *z| z.* = try arena.dupeSentinel(u8, f, 0);
        try check(c.tpi_uid_store_flags(self.handle, uids.ptr, uids.len, @intFromBool(add), zs.ptr, zs.len));
    }

    pub fn append(self: *Session, mailbox: [:0]const u8, data: []const u8) Error!void {
        try check(c.tpi_append(self.handle, mailbox, data.ptr, data.len));
    }
};

fn splitFlags(arena: Allocator, s: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, s, ' ');
    while (it.next()) |f| try out.append(arena, try arena.dupe(u8, f));
    return out.toOwnedSlice(arena);
}

pub const Extracted = union(enum) {
    text: []const u8, // not yet UTF-8 sanitized
    encrypted: []const u8, // protocol parameter
};

/// MIME body extraction (no network). `subtype` is "plain" or "html".
pub fn extractText(arena: Allocator, message: []const u8, subtype: [:0]const u8) Error!Extracted {
    var out: ?[*]u8 = null;
    var out_len: usize = 0;
    var proto: ?[*:0]u8 = null;
    try check(c.tpi_extract_text(message.ptr, message.len, subtype, &out, &out_len, &proto));
    defer c.tpi_buf_free(out);
    defer c.tpi_buf_free(if (proto) |p| p else null);
    if (proto) |p| return .{ .encrypted = try arena.dupe(u8, std.mem.sliceTo(p, 0)) };
    const o = out orelse return .{ .text = "" };
    return .{ .text = try arena.dupe(u8, o[0..out_len]) };
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 2/2 tests pass (the `splitFlags` test plus `main.zig`'s import block); the C files compile with no warnings.

Also run `zig build` and confirm `zig-out/bin/tp_imap_mcp` exists.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `build: C shim over libetpan and Zig session wrapper`

---
### Task 2: UTF-8 and line-ending helpers
**Files:**
- Create: `src/text.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Produces: `sanitizeUtf8(arena, []const u8) ![]const u8` (returns input unchanged when valid), `toLf(arena, in) ![]const u8`, `toCrlf(arena, in) ![]const u8`.

- [ ] **Step 1: Write the failing tests**

Create `src/text.zig` containing only the tests:

```zig
const testing = std.testing;

test "valid utf-8 is returned as-is" {
    const s = "résumé ✓";
    try testing.expectEqual(s.ptr, (try sanitizeUtf8(testing.allocator, s)).ptr);
}

test "invalid bytes become U+FFFD" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("r\u{FFFD}sum\u{FFFD}", try sanitizeUtf8(a, "r\xe9sum\xe9"));
    try testing.expectEqualStrings("ok\u{FFFD}", try sanitizeUtf8(a, "ok\xe2\x82"));
}

test "toLf collapses CRLF" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("a\nb\nc\r", try toLf(arena_state.allocator(), "a\r\nb\nc\r"));
}

test "toCrlf normalizes bare LF only" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("a\r\nb\r\nc", try toCrlf(a, "a\nb\r\nc"));
    try testing.expectEqualStrings("\r\n", try toCrlf(a, "\n"));
}

test "sanitized bytes always serialize to valid JSON" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const clean = try sanitizeUtf8(a, "Subject: caf\xe9 \xff\xfe \xf0\x9f");
    const json = try std.json.Stringify.valueAlloc(a, clean, .{});
    const back = try std.json.parseFromSliceLeaky([]const u8, a, json, .{});
    try testing.expectEqualStrings(clean, back);
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("text.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/text.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/text.zig`:

```zig
//! UTF-8 helpers for data coming off the wire.

const std = @import("std");
const Allocator = std.mem.Allocator;

const replacement = "\u{FFFD}";

/// Returns `in` unchanged if it is valid UTF-8, otherwise a copy (in `arena`)
/// with each invalid sequence replaced by U+FFFD.
pub fn sanitizeUtf8(arena: Allocator, in: []const u8) Allocator.Error![]const u8 {
    if (std.unicode.utf8ValidateSlice(in)) return in;
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, in.len + 16);
    var i: usize = 0;
    while (i < in.len) {
        const len = std.unicode.utf8ByteSequenceLength(in[i]) catch {
            try out.appendSlice(arena, replacement);
            i += 1;
            continue;
        };
        if (i + len <= in.len and std.unicode.utf8ValidateSlice(in[i .. i + len])) {
            try out.appendSlice(arena, in[i .. i + len]);
            i += len;
        } else {
            // One U+FFFD per broken sequence: skip the lead byte plus any
            // continuation bytes that belonged to it.
            try out.appendSlice(arena, replacement);
            i += 1;
            var k: usize = 1;
            while (k < len and i < in.len and in[i] & 0xC0 == 0x80) : (k += 1) i += 1;
        }
    }
    return out.toOwnedSlice(arena);
}

/// Converts CRLF to LF. Allocated in `arena`.
pub fn toLf(arena: Allocator, in: []const u8) Allocator.Error![]const u8 {
    const out = try arena.alloc(u8, std.mem.replacementSize(u8, in, "\r\n", "\n"));
    _ = std.mem.replace(u8, in, "\r\n", "\n", out);
    return out;
}

/// Converts bare LF to CRLF, leaving existing CRLF alone. Allocated in `arena`.
pub fn toCrlf(arena: Allocator, in: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    try out.ensureTotalCapacity(arena, in.len + in.len / 32 + 2);
    for (in, 0..) |c, i| {
        if (c == '\n' and (i == 0 or in[i - 1] != '\r')) try out.append(arena, '\r');
        try out.append(arena, c);
    }
    return out.toOwnedSlice(arena);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 7/7 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: UTF-8 sanitizing and line-ending helpers`

---
### Task 3: Body rendering and MIME fixtures

**Files:**
- Create: `src/testdata/*.eml` (8 fixtures), `src/mime_test.zig`, `src/body.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Consumes: `session.extractText` (Task 1), `text.sanitizeUtf8`, `text.toLf` (Task 2).
- Produces: `body.Kind = enum { plain, html }`; `body.render(arena, message: []const u8, kind) session.Error![]const u8`.

- [ ] **Step 1: Create the fixtures**

```bash
mkdir -p src/testdata && cd src/testdata
printf 'From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nhello plain\r\n--XX\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>hello html</p>\r\n--XX--\r\n' > alternative.eml
printf 'From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=YY\r\n\r\n--YY\r\nContent-Type: text/plain\r\n\r\nthe body\r\n--YY\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename="notes.txt"\r\n\r\nATTACHED TEXT\r\n--YY--\r\n' > attachment.eml
printf 'From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nr=E9sum=E9\r\n' > latin1_qp.eml
printf 'From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8gYmFzZTY0\r\n' > base64.eml
printf 'From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=QQ\r\n\r\n--QQ\r\nContent-Type: text/plain\r\n\r\nouter\r\n--QQ\r\nContent-Type: message/rfc822\r\n\r\nFrom: b@example.org\r\nContent-Type: text/plain\r\n\r\ninner\r\n--QQ--\r\n' > nested.eml
printf 'From: a@example.org\r\nSubject: plain old message\r\n\r\njust text\r\n' > no_content_type.eml
printf 'From: a@example.org\r\nSubject: undeclared 8-bit\r\n\r\ncaf\xe9\r\n' > bad_utf8.eml
printf 'From: a@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary=ZZ\r\n\r\n--ZZ\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--ZZ\r\nContent-Type: application/octet-stream\r\n\r\n-----BEGIN PGP MESSAGE-----\r\nhQEMA\r\n-----END PGP MESSAGE-----\r\n--ZZ--\r\n' > encrypted.eml
cd ../..
```
These are written with `printf` because they need CRLF line endings and one raw `\xe9` byte; do not
recreate them with an editor that normalizes line endings or encodings.

- [ ] **Step 2: Write the failing tests**

`src/mime_test.zig`:

```zig
//! Body rendering tests against .eml fixtures (exercises src/c/mime.c).

const std = @import("std");
const body = @import("body.zig");

const testing = std.testing;

fn expectBody(comptime fixture: []const u8, kind: body.Kind, expected: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const got = try body.render(arena_state.allocator(), @embedFile("testdata/" ++ fixture), kind);
    try testing.expectEqualStrings(expected, got);
}

test "multipart/alternative picks the requested subtype" {
    try expectBody("alternative.eml", .plain, "hello plain");
    try expectBody("alternative.eml", .html, "<p>hello html</p>");
}

test "text attachment is skipped" {
    try expectBody("attachment.eml", .plain, "the body");
}

test "iso-8859-1 quoted-printable becomes utf-8" {
    try expectBody("latin1_qp.eml", .plain, "r\u{e9}sum\u{e9}\n");
}

test "base64 body is decoded" {
    try expectBody("base64.eml", .plain, "hello base64");
}

test "nested message/rfc822 parts are included in walk order" {
    try expectBody("nested.eml", .plain, "outerinner");
}

test "no matching part yields empty string" {
    try expectBody("base64.eml", .html, "");
}

test "missing Content-Type defaults to text/plain" {
    try expectBody("no_content_type.eml", .plain, "just text\n");
}

test "undeclared 8-bit bytes are replaced, not passed as invalid utf-8" {
    try expectBody("bad_utf8.eml", .plain, "caf\u{FFFD}\n");
}

test "multipart/encrypted yields the not-decrypted marker" {
    try expectBody(
        "encrypted.eml",
        .plain,
        "[encrypted message (multipart/encrypted; protocol=application/pgp-encrypted) — not decrypted]",
    );
}
```

Add to the `test` block in `src/main.zig`:

```zig
    _ = @import("mime_test.zig");
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `unable to load 'src/body.zig'` (file not found).

- [ ] **Step 4: Implement**

`src/body.zig`:

```zig
//! get_text / get_html body rendering (spec §6.4, §6.6).

const std = @import("std");
const Allocator = std.mem.Allocator;
const session = @import("imap/session.zig");
const text = @import("text.zig");

pub const Kind = enum {
    plain,
    html,

    fn subtype(k: Kind) [:0]const u8 {
        return switch (k) {
            .plain => "plain",
            .html => "html",
        };
    }
};

/// Concatenated text/<kind> parts as valid UTF-8 with LF line endings, or the
/// not-decrypted marker for multipart/encrypted messages.
pub fn render(arena: Allocator, message: []const u8, kind: Kind) session.Error![]const u8 {
    return switch (try session.extractText(arena, message, kind.subtype())) {
        .text => |t| text.toLf(arena, try text.sanitizeUtf8(arena, t)),
        .encrypted => |protocol| arena.print(
            "[encrypted message (multipart/encrypted; protocol={s}) — not decrypted]",
            .{try text.sanitizeUtf8(arena, protocol)},
        ),
    };
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 16/16 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: text/plain and text/html body rendering with fixtures`

---
### Task 4: Modified UTF-7 mailbox names
**Files:**
- Create: `src/imap/mutf7.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Produces: `mutf7.decode(gpa, wire) DecodeError![]u8` (`error.InvalidMutf7` on malformed input), `mutf7.encode(gpa, utf8) EncodeError![]u8` (`error.InvalidUtf8`). Caller owns the result.

- [ ] **Step 1: Write the failing tests**

Create `src/imap/mutf7.zig` containing only the tests:

```zig
const testing = std.testing;

fn expectRoundTrip(utf8: []const u8, wire: []const u8) !void {
    const enc = try encode(testing.allocator, utf8);
    defer testing.allocator.free(enc);
    try testing.expectEqualStrings(wire, enc);
    const dec = try decode(testing.allocator, wire);
    defer testing.allocator.free(dec);
    try testing.expectEqualStrings(utf8, dec);
}

test "ascii passes through" {
    try expectRoundTrip("INBOX/Archives 2024", "INBOX/Archives 2024");
}

test "ampersand escapes to &-" {
    try expectRoundTrip("Tom & Jerry", "Tom &- Jerry");
}

test "RFC 3501 example" {
    try expectRoundTrip("~peter/mail/台北/日本語", "~peter/mail/&U,BTFw-/&ZeVnLIqe-");
}

test "latin accents" {
    try expectRoundTrip("Entwürfe", "Entw&APw-rfe");
    try expectRoundTrip("Éléments envoyés", "&AMk-l&AOk-ments envoy&AOk-s");
}

test "non-BMP uses surrogate pairs" {
    try expectRoundTrip("📁", "&2D3cwQ-");
}

test "decode rejects malformed input" {
    try testing.expectError(error.InvalidMutf7, decode(testing.allocator, "&U,BTFw"));
    try testing.expectError(error.InvalidMutf7, decode(testing.allocator, "&!!-"));
    try testing.expectError(error.InvalidMutf7, decode(testing.allocator, "caf\xc3\xa9"));
}

test "encode rejects invalid utf-8" {
    try testing.expectError(error.InvalidUtf8, encode(testing.allocator, "\xff"));
}

test "quoting-sensitive characters pass through unchanged" {
    // libetpan quotes or literal-encodes these on the wire; we must not alter them.
    try expectRoundTrip("Projects \"2024\"\\Q%*", "Projects \"2024\"\\Q%*");
    try expectRoundTrip("", "");
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("imap/mutf7.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/imap/mutf7.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/imap/mutf7.zig`:

```zig
//! IMAP modified UTF-7 mailbox names (RFC 3501 §5.1.3) <-> UTF-8.

const std = @import("std");
const Allocator = std.mem.Allocator;

const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

fn isDirect(c: u8) bool {
    return c >= 0x20 and c <= 0x7e and c != '&';
}

fn sextet(c: u8) ?u6 {
    const i = std.mem.findScalar(u8, alphabet, c) orelse return null;
    return @intCast(i);
}

pub const DecodeError = error{InvalidMutf7} || Allocator.Error;

/// Decode a wire mailbox name. Malformed input is an error so callers can
/// fall back to showing the raw name.
pub fn decode(gpa: Allocator, in: []const u8) DecodeError![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < in.len) {
        const c = in[i];
        if (c != '&') {
            if (c < 0x20 or c > 0x7e) return error.InvalidMutf7;
            try out.append(gpa, c);
            i += 1;
            continue;
        }
        const end = std.mem.findScalarPos(u8, in, i + 1, '-') orelse return error.InvalidMutf7;
        if (end == i + 1) {
            try out.append(gpa, '&');
            i = end + 1;
            continue;
        }
        // Base64 run -> UTF-16BE code units -> UTF-8.
        var bits: u32 = 0;
        var nbits: u5 = 0;
        var high: ?u16 = null;
        for (in[i + 1 .. end]) |b| {
            const v = sextet(b) orelse return error.InvalidMutf7;
            bits = (bits << 6) | v;
            nbits += 6;
            if (nbits >= 16) {
                nbits -= 16;
                const unit: u16 = @truncate(bits >> nbits);
                bits &= (@as(u32, 1) << nbits) - 1;
                if (high) |h| {
                    if (unit < 0xDC00 or unit > 0xDFFF) return error.InvalidMutf7;
                    const cp: u21 = 0x10000 + ((@as(u21, h) - 0xD800) << 10) + (unit - 0xDC00);
                    try appendCodepoint(gpa, &out, cp);
                    high = null;
                } else if (unit >= 0xD800 and unit <= 0xDBFF) {
                    high = unit;
                } else if (unit >= 0xDC00 and unit <= 0xDFFF) {
                    return error.InvalidMutf7;
                } else {
                    try appendCodepoint(gpa, &out, unit);
                }
            }
        }
        if (high != null or bits != 0) return error.InvalidMutf7;
        i = end + 1;
    }
    return out.toOwnedSlice(gpa);
}

fn appendCodepoint(gpa: Allocator, out: *std.ArrayList(u8), cp: u21) Allocator.Error!void {
    var buf: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &buf) catch unreachable;
    try out.appendSlice(gpa, buf[0..n]);
}

pub const EncodeError = error{InvalidUtf8} || Allocator.Error;

/// Encode a UTF-8 mailbox name for the wire.
pub fn encode(gpa: Allocator, in: []const u8) EncodeError![]u8 {
    if (!std.unicode.utf8ValidateSlice(in)) return error.InvalidUtf8;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < in.len) {
        const c = in[i];
        if (c == '&') {
            try out.appendSlice(gpa, "&-");
            i += 1;
            continue;
        }
        if (isDirect(c)) {
            try out.append(gpa, c);
            i += 1;
            continue;
        }
        // Collect a run of non-direct characters and base64 their UTF-16BE.
        try out.append(gpa, '&');
        var bits: u32 = 0;
        var nbits: u5 = 0;
        while (i < in.len and !isDirect(in[i]) and in[i] != '&') {
            const len = std.unicode.utf8ByteSequenceLength(in[i]) catch unreachable;
            const cp = std.unicode.utf8Decode(in[i .. i + len]) catch unreachable;
            i += len;
            var units: [2]u16 = undefined;
            var nunits: usize = 1;
            if (cp >= 0x10000) {
                const v = cp - 0x10000;
                units = .{ @intCast(0xD800 + (v >> 10)), @intCast(0xDC00 + (v & 0x3FF)) };
                nunits = 2;
            } else {
                units[0] = @intCast(cp);
            }
            for (units[0..nunits]) |u| {
                bits = (bits << 16) | u;
                nbits += 16;
                while (nbits >= 6) {
                    nbits -= 6;
                    try out.append(gpa, alphabet[@as(u6, @truncate(bits >> nbits))]);
                }
                bits &= (@as(u32, 1) << nbits) - 1;
            }
        }
        if (nbits > 0) {
            try out.append(gpa, alphabet[@as(u6, @truncate(bits << (6 - nbits)))]);
        }
        try out.append(gpa, '-');
    }
    return out.toOwnedSlice(gpa);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 24/24 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: modified UTF-7 mailbox name codec`

---
### Task 5: Argument validation
**Files:**
- Create: `src/validate.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Produces: `validate.Error`; `message(Error) []const u8`; `criteria(s) Error!void`; `uids(gpa, []const []const u8) Error![]u32` (caller owns); `keywords(list) Error!void`; `field(s) Error!void`; `mailbox(s) Error!void`.

- [ ] **Step 1: Write the failing tests**

Create `src/validate.zig` containing only the tests:

```zig
const testing = std.testing;

test "criteria rejects CR, LF, NUL" {
    try criteria("OR FROM \"a@b\" SINCE 01-Jan-2025");
    try criteria("SUBJECT \"r\xc3\xa9sum\xc3\xa9\"");
    try testing.expectError(error.CriteriaHasControlChars, criteria("ALL\r\nA1 DELETE INBOX"));
    try testing.expectError(error.CriteriaHasControlChars, criteria("ALL\nX"));
    try testing.expectError(error.CriteriaHasControlChars, criteria("ALL\x00"));
}

test "uids parse decimal and reject the rest" {
    const ok = try uids(testing.allocator, &.{ "1", "250735", "4294967295" });
    defer testing.allocator.free(ok);
    try testing.expectEqualSlices(u32, &.{ 1, 250735, 4294967295 }, ok);

    try testing.expectError(error.EmptyUids, uids(testing.allocator, &.{}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"0"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"4294967296"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"1:*"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{"+5"}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{""}));
    try testing.expectError(error.InvalidUid, uids(testing.allocator, &.{ "5", "1 FLAGS" }));
}

test "keywords accept system flags and atoms" {
    try keywords(&.{ "\\Seen", "\\flagged", "$label1", "NonJunk", "AI" });
    try testing.expectError(error.EmptyKeywords, keywords(&.{}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"\\Recent"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"two words"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"a)b"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{"x\r\n"}));
    try testing.expectError(error.InvalidKeyword, keywords(&.{""}));
}

test "field accepts header names only" {
    try field("Message-ID");
    try field("x-gm-labels");
    try testing.expectError(error.InvalidField, field(""));
    try testing.expectError(error.InvalidField, field("Subject:"));
    try testing.expectError(error.InvalidField, field("a b"));
}

test "mailbox rejects NUL" {
    try mailbox("INBOX/Archives");
    try testing.expectError(error.MailboxHasNul, mailbox("IN\x00BOX"));
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("validate.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/validate.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/validate.zig`:

```zig
//! Argument validation. `criteria` is sent to the server verbatim, so these
//! checks are the only barrier against smuggling a second IMAP command (which
//! would also bypass read-only accounts).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    CriteriaHasControlChars,
    EmptyUids,
    InvalidUid,
    EmptyKeywords,
    InvalidKeyword,
    InvalidField,
    MailboxHasNul,
} || Allocator.Error;

pub fn message(err: Error) []const u8 {
    return switch (err) {
        error.CriteriaHasControlChars => "criteria must not contain CR, LF, or NUL",
        error.EmptyUids => "uids must be a non-empty array",
        error.InvalidUid => "each uid must be a decimal string between 1 and 4294967295",
        error.EmptyKeywords => "keywords must be a non-empty array",
        error.InvalidKeyword => "each keyword must be a system flag (\\Seen, \\Answered, \\Flagged, \\Deleted, \\Draft) or an IMAP atom",
        error.InvalidField => "field must be a header name (printable ASCII, no ':' or space)",
        error.MailboxHasNul => "mailbox name must not contain NUL",
        error.OutOfMemory => "out of memory",
    };
}

pub fn criteria(s: []const u8) Error!void {
    if (std.mem.findAny(u8, s, "\r\n\x00") != null) return error.CriteriaHasControlChars;
}

/// Parses decimal UID strings. The result is owned by `gpa`.
pub fn uids(gpa: Allocator, strings: []const []const u8) Error![]u32 {
    if (strings.len == 0) return error.EmptyUids;
    const out = try gpa.alloc(u32, strings.len);
    errdefer gpa.free(out);
    for (strings, out) |s, *u| {
        if (s.len == 0) return error.InvalidUid;
        for (s) |c| if (!std.ascii.isDigit(c)) return error.InvalidUid;
        u.* = std.fmt.parseInt(u32, s, 10) catch return error.InvalidUid;
        if (u.* == 0) return error.InvalidUid;
    }
    return out;
}

const system_flags = [_][]const u8{ "\\Seen", "\\Answered", "\\Flagged", "\\Deleted", "\\Draft" };

fn isAtomChar(c: u8) bool {
    if (c <= 0x20 or c >= 0x7f) return false; // SP, CTL, non-ASCII
    return std.mem.findScalar(u8, "(){%*\"\\]", c) == null;
}

pub fn keywords(list: []const []const u8) Error!void {
    if (list.len == 0) return error.EmptyKeywords;
    for (list) |k| {
        if (k.len == 0) return error.InvalidKeyword;
        if (k[0] == '\\') {
            for (system_flags) |f| {
                if (std.ascii.eqlIgnoreCase(f, k)) break;
            } else return error.InvalidKeyword;
            continue;
        }
        for (k) |c| if (!isAtomChar(c)) return error.InvalidKeyword;
    }
}

pub fn field(s: []const u8) Error!void {
    if (s.len == 0) return error.InvalidField;
    for (s) |c| if (c <= 0x20 or c >= 0x7f or c == ':') return error.InvalidField;
}

pub fn mailbox(s: []const u8) Error!void {
    if (std.mem.findScalar(u8, s, 0) != null) return error.MailboxHasNul;
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 29/29 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: argument validation against IMAP command injection`

---
### Task 6: Header parsing
**Files:**
- Create: `src/headers.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Produces: `headers.Header{ name: []const u8 (lowercased), value: []const u8 (unfolded, raw) }`; `headers.parse(arena, raw) ![]Header`.

- [ ] **Step 1: Write the failing tests**

Create `src/headers.zig` containing only the tests:

```zig
const testing = std.testing;

test "parses, lowercases, unfolds, keeps repeats in order" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const raw =
        "Received: from a\r\n" ++
        "\tby b\r\n" ++
        "Subject: =?UTF-8?B?w6k=?=\r\n" ++
        "Received: from c\r\n" ++
        "X-Empty:\r\n" ++
        "\r\n" ++
        "Body-Looking: not a header\r\n";
    const hs = try parse(arena_state.allocator(), raw);
    try testing.expectEqual(4, hs.len);
    try testing.expectEqualStrings("received", hs[0].name);
    try testing.expectEqualStrings("from a\tby b", hs[0].value);
    try testing.expectEqualStrings("subject", hs[1].name);
    try testing.expectEqualStrings("=?UTF-8?B?w6k=?=", hs[1].value);
    try testing.expectEqualStrings("received", hs[2].name);
    try testing.expectEqualStrings("from c", hs[2].value);
    try testing.expectEqualStrings("x-empty", hs[3].name);
    try testing.expectEqualStrings("", hs[3].value);
}

test "bare LF and missing terminator" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const hs = try parse(arena_state.allocator(), "From: a@b\nTo: c@d");
    try testing.expectEqual(2, hs.len);
    try testing.expectEqualStrings("c@d", hs[1].value);
}

test "leading continuation and colon-less lines are skipped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const hs = try parse(arena_state.allocator(), " orphan continuation\r\nnot a header\r\nFrom: a@b\r\n\r\n");
    try testing.expectEqual(1, hs.len);
    try testing.expectEqualStrings("from", hs[0].name);
    try testing.expectEqualStrings("a@b", hs[0].value);
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("headers.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/headers.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/headers.zig`:

```zig
//! Raw RFC 5322 header block -> ordered (lowercased name, unfolded value)
//! pairs, matching what imap-tools exposes as `message.headers`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Header = struct {
    name: []const u8, // lowercased
    value: []const u8, // unfolded, leading whitespace trimmed, otherwise raw
};

/// All slices are allocated in `arena`.
pub fn parse(arena: Allocator, raw: []const u8) Allocator.Error![]Header {
    var out: std.ArrayList(Header) = .empty;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    var name: ?[]u8 = null;
    var value: std.ArrayList(u8) = .empty;

    while (lines.next()) |line_crlf| {
        const line = std.mem.trimEnd(u8, line_crlf, "\r");
        if (line.len == 0) break; // end of header block
        if (line[0] == ' ' or line[0] == '\t') {
            // Continuation: RFC 5322 unfolding removes only the CRLF.
            if (name != null) try value.appendSlice(arena, line);
            continue;
        }
        if (name) |n| try out.append(arena, .{ .name = n, .value = try value.toOwnedSlice(arena) });
        name = null;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue; // malformed line: skip
        name = try std.ascii.allocLowerString(arena, std.mem.trim(u8, line[0..colon], " \t"));
        value = .empty;
        try value.appendSlice(arena, std.mem.trimStart(u8, line[colon + 1 ..], " \t"));
    }
    if (name) |n| try out.append(arena, .{ .name = n, .value = try value.toOwnedSlice(arena) });
    return out.toOwnedSlice(arena);
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 32/32 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: RFC 5322 header block parsing`

---
### Task 7: Configuration from environment
**Files:**
- Create: `src/config.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Produces: `config.Account{ name, host: [:0]const u8, port: u16, login: [:0]const u8, password: [:0]u8, readonly: bool, drafts: ?[]const u8 }` with `wipe()`; `config.load(arena, env: anytype /* has get([]const u8) ?[]const u8 */, diag: *std.Io.Writer) Error![]Account` (`error.InvalidConfig` with reason in `diag`); `config.find(accounts, name) ?*Account`; `config.Settings{ cache_dir: ?[]const u8, cache_dir_unavailable: bool, mailbox_ttl: i64 }`; `config.loadSettings(arena, env, diag) Error!Settings`; `config.app_dir`.

- [ ] **Step 1: Write the failing tests**

Create `src/config.zig` containing only the tests:

```zig
const testing = std.testing;

const TestEnv = struct {
    map: std.StaticStringMap([]const u8),
    pub fn get(self: TestEnv, key: []const u8) ?[]const u8 {
        return self.map.get(key);
    }
};

fn testEnv(comptime kvs: anytype) TestEnv {
    return .{ .map = .initComptime(kvs) };
}

fn expectInvalid(e: TestEnv, comptime expected_diag: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidConfig, load(arena_state.allocator(), e, &diag));
    try testing.expectEqualStrings(expected_diag, diag.buffered());
    try testing.expect(std.mem.find(u8, diag.buffered(), "s3cret") == null);
}

test "loads two accounts with defaults and overrides" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    const accounts = try load(arena_state.allocator(), testEnv(.{
        .{ "IMAP_ACCOUNTS", "tetra, work" },
        .{ "IMAP_TETRA_HOST", "mail.example.org" },
        .{ "IMAP_TETRA_LOGIN", "me@example.org" },
        .{ "IMAP_TETRA_PASSWORD", "s3cret" },
        .{ "IMAP_WORK_HOST", "imap.work.test" },
        .{ "IMAP_WORK_PORT", "1993" },
        .{ "IMAP_WORK_LOGIN", "me@work.test" },
        .{ "IMAP_WORK_PASSWORD", "s3cret" },
        .{ "IMAP_WORK_READONLY", "yes" },
        .{ "IMAP_WORK_DRAFTS", "INBOX.Drafts" },
    }), &diag);
    try testing.expectEqual(2, accounts.len);
    try testing.expectEqualStrings("tetra", accounts[0].name);
    try testing.expectEqual(993, accounts[0].port);
    try testing.expect(!accounts[0].readonly);
    try testing.expect(accounts[0].drafts == null);
    try testing.expectEqual(1993, accounts[1].port);
    try testing.expect(accounts[1].readonly);
    try testing.expectEqualStrings("INBOX.Drafts", accounts[1].drafts.?);
    try testing.expect(find(accounts, "WORK") == &accounts[1]);
    try testing.expect(find(accounts, "nope") == null);

    accounts[0].wipe();
    for (accounts[0].password) |c| try testing.expectEqual(0, c);
}

test "rejects missing, malformed, duplicate; never leaks values" {
    try expectInvalid(testEnv(.{}), "IMAP_ACCOUNTS is missing or empty");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "" }}), "IMAP_ACCOUNTS is missing or empty");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "a,,b" }}), "IMAP_ACCOUNTS contains an empty name");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "a," }}), "IMAP_ACCOUNTS contains an empty name");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "my-mail" }}), "account name \"my-mail\" must match [A-Za-z0-9_]+");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a,A" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_LOGIN", "l" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
    }), "account name \"A\" is listed twice");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
    }), "IMAP_A_LOGIN is missing or empty");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_LOGIN", "l" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
        .{ "IMAP_A_PORT", "99999" },
    }), "IMAP_A_PORT must be a port number 1-65535");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_LOGIN", "l" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
        .{ "IMAP_A_READONLY", "s3cret" },
    }), "IMAP_A_READONLY must be one of 1/true/yes/0/false/no");
}

fn settingsFrom(arena: Allocator, e: TestEnv) !Settings {
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    return loadSettings(arena, e, &diag);
}

test "settings: XDG cache location, HOME fallback, disable switch, TTL" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const xdg = try settingsFrom(a, testEnv(.{ .{ "XDG_CACHE_HOME", "/x/cache" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/x/cache/tp-imap-mcp", xdg.cache_dir.?);
    try testing.expectEqual(3600, xdg.mailbox_ttl);

    // Relative XDG_CACHE_HOME is ignored per the XDG spec.
    const home = try settingsFrom(a, testEnv(.{ .{ "XDG_CACHE_HOME", "rel" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/home/me/.cache/tp-imap-mcp", home.cache_dir.?);

    const off = try settingsFrom(a, testEnv(.{ .{ "TP_IMAP_MCP_CACHE", "0" }, .{ "HOME", "/home/me" }, .{ "TP_IMAP_MCP_MAILBOX_TTL", "60" } }));
    try testing.expect(off.cache_dir == null and !off.cache_dir_unavailable);
    try testing.expectEqual(60, off.mailbox_ttl);

    const nowhere = try settingsFrom(a, testEnv(.{}));
    try testing.expect(nowhere.cache_dir == null and nowhere.cache_dir_unavailable);

    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_MAILBOX_TTL", "-5" }}), "TP_IMAP_MCP_MAILBOX_TTL must be a number of seconds >= 0");
    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_CACHE", "maybe" }}), "TP_IMAP_MCP_CACHE must be one of 1/true/yes/0/false/no");
}

fn expectInvalidSettings(e: TestEnv, comptime expected_diag: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidConfig, loadSettings(arena_state.allocator(), e, &diag));
    try testing.expectEqualStrings(expected_diag, diag.buffered());
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("config.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/config.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/config.zig`:

```zig
//! Configuration from environment variables: accounts (ADR 0007) and cache
//! settings (ADRs 0013, 0014).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Account = struct {
    name: []const u8, // as written in IMAP_ACCOUNTS
    host: [:0]const u8,
    port: u16,
    login: [:0]const u8,
    password: [:0]u8, // mutable so it can be zeroed
    readonly: bool,
    drafts: ?[]const u8, // UTF-8; null = discover via \Drafts

    pub fn wipe(self: *Account) void {
        std.crypto.secureZero(u8, self.password);
    }
};

pub const Error = error{InvalidConfig} || Allocator.Error;

/// Writes a human-readable reason to `diag` on error.InvalidConfig. Never
/// includes a variable's value. `env` is anything with
/// `fn get(self, []const u8) ?[]const u8`.
pub fn load(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error![]Account {
    const list = nonEmpty(env, "IMAP_ACCOUNTS") orelse
        return fail(diag, "IMAP_ACCOUNTS is missing or empty", .{});

    // Validate the whole name list before reading any per-account variable.
    var names: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |raw_name| {
        const name = std.mem.trim(u8, raw_name, " \t");
        if (name.len == 0) return fail(diag, "IMAP_ACCOUNTS contains an empty name", .{});
        for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_')
            return fail(diag, "account name \"{s}\" must match [A-Za-z0-9_]+", .{name});
        for (names.items) |n| if (std.ascii.eqlIgnoreCase(n, name))
            return fail(diag, "account name \"{s}\" is listed twice", .{name});
        try names.append(arena, name);
    }

    var accounts: std.ArrayList(Account) = .empty;
    for (names.items) |name| {
        const prefix = try std.ascii.allocUpperString(arena, name);
        try accounts.append(arena, .{
            .name = name,
            .host = try required(arena, env, diag, prefix, "HOST"),
            .port = try port(arena, env, diag, prefix),
            .login = try required(arena, env, diag, prefix, "LOGIN"),
            .password = try required(arena, env, diag, prefix, "PASSWORD"),
            .readonly = try flag(arena, env, diag, prefix, "READONLY"),
            .drafts = nonEmpty(env, try varName(arena, prefix, "DRAFTS")),
        });
    }
    return accounts.toOwnedSlice(arena);
}

pub const Settings = struct {
    /// `$XDG_CACHE_HOME/tp-imap-mcp` or `$HOME/.cache/tp-imap-mcp`; null when
    /// caching is disabled or no location could be determined.
    cache_dir: ?[]const u8,
    /// Set when caching was wanted but no cache location could be determined.
    cache_dir_unavailable: bool,
    /// Seconds a cached mailbox list stays fresh.
    mailbox_ttl: i64,
};

pub const app_dir = "tp-imap-mcp";

/// Reads TP_IMAP_MCP_CACHE, TP_IMAP_MCP_MAILBOX_TTL, XDG_CACHE_HOME, HOME.
pub fn loadSettings(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error!Settings {
    const ttl_key = "TP_IMAP_MCP_MAILBOX_TTL";
    const ttl: i64 = if (nonEmpty(env, ttl_key)) |v|
        std.fmt.parseInt(u31, v, 10) catch return fail(diag, "{s} must be a number of seconds >= 0", .{ttl_key})
    else
        3600;

    if (!try boolVar(env, diag, "TP_IMAP_MCP_CACHE", true))
        return .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = ttl };

    const base: ?[]const u8 = blk: {
        if (nonEmpty(env, "XDG_CACHE_HOME")) |x| if (std.fs.path.isAbsolute(x)) break :blk x;
        if (nonEmpty(env, "HOME")) |h| break :blk try std.fs.path.join(arena, &.{ h, ".cache" });
        break :blk null;
    };
    return .{
        .cache_dir = if (base) |b| try std.fs.path.join(arena, &.{ b, app_dir }) else null,
        .cache_dir_unavailable = base == null,
        .mailbox_ttl = ttl,
    };
}

/// Case-insensitive lookup by configured name.
pub fn find(accounts: []Account, name: []const u8) ?*Account {
    for (accounts) |*a| if (std.ascii.eqlIgnoreCase(a.name, name)) return a;
    return null;
}

fn fail(diag: *std.Io.Writer, comptime fmt: []const u8, args: anytype) Error {
    diag.print(fmt, args) catch {};
    return error.InvalidConfig;
}

fn nonEmpty(env: anytype, key: []const u8) ?[]const u8 {
    const v = env.get(key) orelse return null;
    return if (v.len == 0) null else v;
}

fn varName(arena: Allocator, prefix: []const u8, suffix: []const u8) Allocator.Error![]const u8 {
    return std.mem.concat(arena, u8, &.{ "IMAP_", prefix, "_", suffix });
}

fn required(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8, suffix: []const u8) Error![:0]u8 {
    const key = try varName(arena, prefix, suffix);
    const v = nonEmpty(env, key) orelse return fail(diag, "{s} is missing or empty", .{key});
    return arena.dupeSentinel(u8, v, 0);
}

fn port(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8) Error!u16 {
    const key = try varName(arena, prefix, "PORT");
    const v = nonEmpty(env, key) orelse return 993;
    const p = std.fmt.parseInt(u16, v, 10) catch return fail(diag, "{s} must be a port number 1-65535", .{key});
    if (p == 0) return fail(diag, "{s} must be a port number 1-65535", .{key});
    return p;
}

fn flag(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8, suffix: []const u8) Error!bool {
    return boolVar(env, diag, try varName(arena, prefix, suffix), false);
}

fn boolVar(env: anytype, diag: *std.Io.Writer, key: []const u8, default: bool) Error!bool {
    const v = nonEmpty(env, key) orelse return default;
    const truthy = [_][]const u8{ "1", "true", "yes" };
    const falsy = [_][]const u8{ "0", "false", "no" };
    for (truthy) |t| if (std.ascii.eqlIgnoreCase(v, t)) return true;
    for (falsy) |f| if (std.ascii.eqlIgnoreCase(v, f)) return false;
    return fail(diag, "{s} must be one of 1/true/yes/0/false/no", .{key});
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 35/35 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: multi-account configuration and XDG cache settings from the environment`

---
### Task 8: Local LIST pattern matching
**Files:**
- Create: `src/listmatch.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Produces: `listmatch.matches(name: []const u8, reference: []const u8, pattern: []const u8, delimiter: ?u8) bool` (all UTF-8).

- [ ] **Step 1: Write the failing tests**

Create `src/listmatch.zig` containing only the tests:

```zig
const testing = std.testing;

test "star matches across levels, percent stops at the delimiter" {
    try testing.expect(matches("Archives/2024/Q1", "", "*", '/'));
    try testing.expect(matches("Archives/2024/Q1", "Archives/", "*", '/'));
    try testing.expect(!matches("Archives/2024/Q1", "Archives/", "%", '/'));
    try testing.expect(matches("Archives/2024", "Archives/", "%", '/'));
    try testing.expect(matches("Archives", "", "Archives*", '/'));
    try testing.expect(matches("Archives2", "", "Archives*", '/'));
    try testing.expect(!matches("Sent", "", "Archives*", '/'));
    try testing.expect(matches("Queue", "", "Q%", '/'));
    try testing.expect(!matches("Queue/Sub", "", "Q%", '/'));
}

test "reference and pattern concatenate without an inserted delimiter" {
    try testing.expect(matches("INBOX.Foo", "INBOX.", "*", '.'));
    try testing.expect(matches("INBOXed", "INBOX", "*", '.'));
    try testing.expect(matches("Archives", "Arch", "ives", '/'));
}

test "INBOX is case-insensitive, other names are not" {
    try testing.expect(matches("INBOX", "", "inbox", '/'));
    try testing.expect(matches("INBOX/Sub", "", "Inbox/%", '/'));
    try testing.expect(matches("INBOX/Sub", "inbox/", "%", '/'));
    try testing.expect(!matches("Sent", "", "sent", '/'));
}

test "empty pattern matches nothing; nil delimiter means flat" {
    try testing.expect(!matches("INBOX", "", "", '/'));
    try testing.expect(matches("a/b", "", "%", null));
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("listmatch.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/listmatch.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/listmatch.zig`:

```zig
//! Local evaluation of IMAP LIST arguments against a cached mailbox list
//! (RFC 3501 §6.3.8): the reference and pattern are concatenated; `*` matches
//! anything, `%` matches anything except the hierarchy delimiter; the name
//! INBOX is case-insensitive.

const std = @import("std");

/// `name`, `reference`, and `pattern` are all UTF-8.
pub fn matches(name: []const u8, reference: []const u8, pattern: []const u8, delimiter: ?u8) bool {
    var nbuf: [5]u8 = undefined;
    var pbuf: [5]u8 = undefined;
    const n = canonicalInbox(name, delimiter, &nbuf);
    // Canonicalize INBOX in the combined pattern only when it starts the reference
    // or (with an empty reference) the pattern.
    if (reference.len > 0) {
        const r = canonicalInbox(reference, delimiter, &pbuf);
        return glob(.{ .a = r.head, .b = r.tail, .c = pattern }, 0, n, delimiter);
    }
    const p = canonicalInbox(pattern, delimiter, &pbuf);
    return glob(.{ .a = p.head, .b = p.tail, .c = "" }, 0, n, delimiter);
}

const Split = struct { head: []const u8, tail: []const u8 };

/// Splits off a leading "inbox" (any case, followed by end or delimiter) as
/// "INBOX"; otherwise head is empty.
fn canonicalInbox(s: []const u8, delimiter: ?u8, buf: *[5]u8) Split {
    if (s.len >= 5 and std.ascii.eqlIgnoreCase(s[0..5], "INBOX") and
        (s.len == 5 or (delimiter != null and s[5] == delimiter.?)))
    {
        buf.* = "INBOX".*;
        return .{ .head = buf, .tail = s[5..] };
    }
    return .{ .head = "", .tail = s };
}

/// A pattern made of three concatenated slices, indexed without allocating.
const Pat = struct {
    a: []const u8,
    b: []const u8,
    c: []const u8,

    fn len(p: Pat) usize {
        return p.a.len + p.b.len + p.c.len;
    }

    fn at(p: Pat, i: usize) u8 {
        if (i < p.a.len) return p.a[i];
        if (i < p.a.len + p.b.len) return p.b[i - p.a.len];
        return p.c[i - p.a.len - p.b.len];
    }
};

fn glob(p: Pat, pi: usize, n: Split, delimiter: ?u8) bool {
    // Treat the canonicalized name as head ++ tail.
    const name: Pat = .{ .a = n.head, .b = n.tail, .c = "" };
    return globAt(p, pi, name, 0, delimiter);
}

fn globAt(p: Pat, pi: usize, n: Pat, ni: usize, delimiter: ?u8) bool {
    if (pi == p.len()) return ni == n.len();
    switch (p.at(pi)) {
        '*' => {
            var i = ni;
            while (i <= n.len()) : (i += 1) if (globAt(p, pi + 1, n, i, delimiter)) return true;
            return false;
        },
        '%' => {
            var i = ni;
            while (i <= n.len()) : (i += 1) {
                if (globAt(p, pi + 1, n, i, delimiter)) return true;
                if (i < n.len() and delimiter != null and n.at(i) == delimiter.?) return false;
            }
            return false;
        },
        else => |ch| return ni < n.len() and n.at(ni) == ch and globAt(p, pi + 1, n, ni + 1, delimiter),
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 39/39 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: local evaluation of IMAP LIST patterns`

---
### Task 9: SQLite binding
**Files:**
- Create: `src/cache/sqlite.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Produces: `sqlite.Error = error{SqliteFailed, SqliteCorrupt}`; `Db.open(path: [:0]const u8) Error!Db` (":memory:" allowed), `close`, `exec(sql: [:0]const u8)`, `prepare(sql) Error!Stmt`; `Stmt.bindText/bindBlob/bindInt` (1-based), `step() Error!bool`, `run()`, `reset()`, `finalize()`, `int/text/blob(col)` (0-based; slices valid until next step).
- Relies on: `linkSystemLibrary("sqlite3")` already in `build.zig` (Task 1).

- [ ] **Step 1: Write the failing tests**

Create `src/cache/sqlite.zig` containing only the tests:

```zig
const testing = std.testing;

test "round-trips text, blob, and integers" {
    var db: Db = try .open(":memory:");
    defer db.close();
    try db.exec("CREATE TABLE t (a TEXT, b BLOB, c INTEGER)");
    const ins = try db.prepare("INSERT INTO t VALUES (?1, ?2, ?3)");
    defer ins.finalize();
    try ins.bindText(1, "héllo");
    try ins.bindBlob(2, "\x00\xff");
    try ins.bindInt(3, 4294967295);
    try ins.run();

    const sel = try db.prepare("SELECT a, b, c FROM t");
    defer sel.finalize();
    try testing.expect(try sel.step());
    try testing.expectEqualStrings("héllo", sel.text(0));
    try testing.expectEqualSlices(u8, "\x00\xff", sel.blob(1));
    try testing.expectEqual(4294967295, sel.int(2));
    try testing.expect(!try sel.step());
}

test "SQL errors surface as SqliteFailed" {
    var db: Db = try .open(":memory:");
    defer db.close();
    try testing.expectError(error.SqliteFailed, db.exec("NOT SQL"));
    try testing.expectError(error.SqliteFailed, db.prepare("SELECT * FROM missing"));
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("cache/sqlite.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/cache/sqlite.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/cache/sqlite.zig`:

```zig
//! Minimal SQLite binding: hand-written externs for the system libsqlite3
//! (ADR 0015) plus a thin wrapper. Only what the cache needs.

const std = @import("std");

const sqlite3 = opaque {};
const sqlite3_stmt = opaque {};
/// SQLITE_STATIC (null): SQLite does not copy bound data, so it must outlive
/// the statement's next step/reset. Every caller binds, steps, then resets.
const Destructor = ?*const fn (?*anyopaque) callconv(.c) void;

extern fn sqlite3_open_v2(filename: [*:0]const u8, db: *?*sqlite3, flags: c_int, vfs: ?[*:0]const u8) c_int;
extern fn sqlite3_close_v2(db: ?*sqlite3) c_int;
extern fn sqlite3_errmsg(db: *sqlite3) [*:0]const u8;
extern fn sqlite3_exec(db: *sqlite3, sql: [*:0]const u8, callback: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_busy_timeout(db: *sqlite3, ms: c_int) c_int;
extern fn sqlite3_prepare_v2(db: *sqlite3, sql: [*]const u8, nbyte: c_int, stmt: *?*sqlite3_stmt, tail: ?*?[*]const u8) c_int;
extern fn sqlite3_bind_text(stmt: *sqlite3_stmt, idx: c_int, text: [*]const u8, n: c_int, destructor: Destructor) c_int;
extern fn sqlite3_bind_blob(stmt: *sqlite3_stmt, idx: c_int, data: ?*const anyopaque, n: c_int, destructor: Destructor) c_int;
extern fn sqlite3_bind_int64(stmt: *sqlite3_stmt, idx: c_int, value: i64) c_int;
extern fn sqlite3_step(stmt: *sqlite3_stmt) c_int;
extern fn sqlite3_reset(stmt: *sqlite3_stmt) c_int;
extern fn sqlite3_finalize(stmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_int64(stmt: *sqlite3_stmt, col: c_int) i64;
extern fn sqlite3_column_text(stmt: *sqlite3_stmt, col: c_int) ?[*]const u8;
extern fn sqlite3_column_blob(stmt: *sqlite3_stmt, col: c_int) ?[*]const u8;
extern fn sqlite3_column_bytes(stmt: *sqlite3_stmt, col: c_int) c_int;

const SQLITE_OK = 0;
const SQLITE_CORRUPT = 11;
const SQLITE_NOTADB = 26;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_OPEN_READWRITE = 0x00000002;
const SQLITE_OPEN_CREATE = 0x00000004;

pub const Error = error{
    SqliteFailed,
    /// The file exists but is not a usable database; safe to delete (cache).
    SqliteCorrupt,
};

fn check(db: *sqlite3, rc: c_int) Error!void {
    if (rc == SQLITE_OK) return;
    std.log.debug("sqlite: {s}", .{sqlite3_errmsg(db)});
    return if (rc == SQLITE_CORRUPT or rc == SQLITE_NOTADB) error.SqliteCorrupt else error.SqliteFailed;
}

fn len(n: usize) c_int {
    return std.math.cast(c_int, n) orelse std.math.maxInt(c_int);
}

pub const Db = struct {
    handle: *sqlite3,

    pub fn open(path: [:0]const u8) Error!Db {
        var h: ?*sqlite3 = null;
        const rc = sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, null);
        const handle = h orelse return error.SqliteFailed;
        errdefer _ = sqlite3_close_v2(handle);
        try check(handle, rc);
        _ = sqlite3_busy_timeout(handle, 5000);
        return .{ .handle = handle };
    }

    pub fn close(self: *Db) void {
        _ = sqlite3_close_v2(self.handle);
        self.* = undefined;
    }

    pub fn exec(self: Db, sql: [:0]const u8) Error!void {
        try check(self.handle, sqlite3_exec(self.handle, sql, null, null, null));
    }

    pub fn prepare(self: Db, sql: []const u8) Error!Stmt {
        var s: ?*sqlite3_stmt = null;
        try check(self.handle, sqlite3_prepare_v2(self.handle, sql.ptr, len(sql.len), &s, null));
        return .{ .handle = s orelse return error.SqliteFailed, .db = self.handle };
    }
};

pub const Stmt = struct {
    handle: *sqlite3_stmt,
    db: *sqlite3,

    pub fn finalize(self: Stmt) void {
        _ = sqlite3_finalize(self.handle);
    }

    /// Parameters are 1-based, as in SQL (`?1`, `?2`, ...).
    pub fn bindText(self: Stmt, idx: c_int, value: []const u8) Error!void {
        try check(self.db, sqlite3_bind_text(self.handle, idx, value.ptr, len(value.len), null));
    }

    pub fn bindBlob(self: Stmt, idx: c_int, data: []const u8) Error!void {
        try check(self.db, sqlite3_bind_blob(self.handle, idx, data.ptr, len(data.len), null));
    }

    pub fn bindInt(self: Stmt, idx: c_int, value: i64) Error!void {
        try check(self.db, sqlite3_bind_int64(self.handle, idx, value));
    }

    /// True when a row is available, false when the statement is done.
    pub fn step(self: Stmt) Error!bool {
        const rc = sqlite3_step(self.handle);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        try check(self.db, rc);
        return error.SqliteFailed;
    }

    /// Steps a statement that returns no rows.
    pub fn run(self: Stmt) Error!void {
        while (try self.step()) {}
        try self.reset();
    }

    pub fn reset(self: Stmt) Error!void {
        try check(self.db, sqlite3_reset(self.handle));
    }

    /// Columns are 0-based.
    pub fn int(self: Stmt, col: c_int) i64 {
        return sqlite3_column_int64(self.handle, col);
    }

    /// Valid until the next step/reset/finalize; copy if kept.
    pub fn text(self: Stmt, col: c_int) []const u8 {
        const p = sqlite3_column_text(self.handle, col) orelse return "";
        return p[0..@intCast(sqlite3_column_bytes(self.handle, col))];
    }

    /// Valid until the next step/reset/finalize; copy if kept.
    pub fn blob(self: Stmt, col: c_int) []const u8 {
        const p = sqlite3_column_blob(self.handle, col) orelse return "";
        return p[0..@intCast(sqlite3_column_bytes(self.handle, col))];
    }
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 41/41 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: minimal SQLite binding over system libsqlite3`

---
### Task 10: Cache store
**Files:**
- Create: `src/cache/store.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Consumes: `sqlite.Db` (Task 9), `imap.Mailbox`, `imap.Fetched` (Task 1).
- Produces: `store.Error = sqlite.Error || Allocator.Error`; `Store.open(path) Error!Store` (rebuilds on schema mismatch; `error.SqliteCorrupt` for non-databases), `close`, `mailboxesFresh(ttl_sec: i64) Error!bool`, `loadMailboxes(arena) Error![]imap.Mailbox`, `replaceMailboxes(arena, boxes) Error!void`, `markMailboxesStale()`, `syncUidvalidity(mailbox, uidvalidity: u32)`, `getMessages(arena, mailbox, uidvalidity, uids) Error![]imap.Fetched`, `putMessages(mailbox, uidvalidity, items)`, `clear()`.

- [ ] **Step 1: Write the failing tests**

Create `src/cache/store.zig` containing only the tests:

```zig
const testing = std.testing;

fn box(name: []const u8, flags: []const []const u8) imap.Mailbox {
    return .{ .name = name, .delimiter = '/', .flags = flags };
}

test "mailbox list round-trip, freshness, and staleness" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s: Store = try .open(":memory:");
    defer s.close();

    try testing.expect(!try s.mailboxesFresh(3600));
    try s.replaceMailboxes(a, &.{ box("INBOX", &.{"\\HasChildren"}), box("Drafts", &.{ "\\Drafts", "\\HasNoChildren" }) });
    try testing.expect(try s.mailboxesFresh(3600));
    try testing.expect(!try s.mailboxesFresh(0));

    const got = try s.loadMailboxes(a);
    try testing.expectEqual(2, got.len);
    try testing.expectEqualStrings("Drafts", got[0].name);
    try testing.expectEqual('/', got[0].delimiter.?);
    try testing.expectEqualStrings("\\HasNoChildren", got[0].flags[1]);

    try s.markMailboxesStale();
    try testing.expect(!try s.mailboxesFresh(3600));
}

test "messages: hit, miss, UIDVALIDITY change, vanished mailbox, clear" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s: Store = try .open(":memory:");
    defer s.close();
    try s.replaceMailboxes(a, &.{ box("INBOX", &.{}), box("Old", &.{}) });

    try s.putMessages("INBOX", 7, &.{
        .{ .uid = 1, .size = 100, .data = "Subject: a\r\n\r\n", .flags = null },
        .{ .uid = 2, .size = 200, .data = null, .flags = null }, // no header: skipped
    });
    try s.putMessages("Old", 1, &.{.{ .uid = 9, .size = 9, .data = "X: y\r\n\r\n", .flags = null }});

    const hit = try s.getMessages(a, "INBOX", 7, &.{ 2, 1, 3 });
    try testing.expectEqual(1, hit.len);
    try testing.expectEqual(1, hit[0].uid);
    try testing.expectEqual(100, hit[0].size);
    try testing.expectEqualStrings("Subject: a\r\n\r\n", hit[0].data.?);

    try s.syncUidvalidity("INBOX", 8);
    try testing.expectEqual(0, (try s.getMessages(a, "INBOX", 7, &.{1})).len);

    try s.replaceMailboxes(a, &.{box("INBOX", &.{})}); // "Old" vanished
    try testing.expectEqual(0, (try s.getMessages(a, "Old", 1, &.{9})).len);

    try s.putMessages("INBOX", 8, &.{.{ .uid = 1, .size = 1, .data = "A: b\r\n\r\n", .flags = null }});
    try s.clear();
    try testing.expectEqual(0, (try s.getMessages(a, "INBOX", 8, &.{1})).len);
    try testing.expectEqual(0, (try s.loadMailboxes(a)).len);
}

test "schema version mismatch rebuilds the file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testing.allocator.printSentinel(".zig-cache/tmp/{s}/c.sqlite3", .{&tmp.sub_path}, 0);
    defer testing.allocator.free(path);
    {
        var db: sqlite.Db = try .open(path);
        defer db.close();
        try db.exec("CREATE TABLE junk (x); PRAGMA user_version = 99;");
    }
    var s: Store = try .open(path);
    defer s.close();
    try testing.expect(!try s.mailboxesFresh(3600));
}

test "a non-database file reports SqliteCorrupt" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "bad.sqlite3", .data = "this is not a database, just text padding" });
    const path = try testing.allocator.printSentinel(".zig-cache/tmp/{s}/bad.sqlite3", .{&tmp.sub_path}, 0);
    defer testing.allocator.free(path);
    try testing.expectError(error.SqliteCorrupt, Store.open(path));
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("cache/store.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/cache/store.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/cache/store.zig`:

```zig
//! Per-account on-disk cache (ADR 0013): mailbox list plus message headers
//! and sizes keyed by (mailbox, UIDVALIDITY, UID). Mailbox names are stored in
//! wire form (modified UTF-7).

const std = @import("std");
const Allocator = std.mem.Allocator;
const sqlite = @import("sqlite.zig");
const imap = @import("../imap/session.zig");

pub const Error = sqlite.Error || Allocator.Error;

const schema_version = 1;

const schema =
    \\PRAGMA journal_mode = WAL;
    \\DROP TABLE IF EXISTS meta;
    \\DROP TABLE IF EXISTS mailboxes;
    \\DROP TABLE IF EXISTS messages;
    \\CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
    \\CREATE TABLE mailboxes (name TEXT PRIMARY KEY, delimiter TEXT NOT NULL, flags TEXT NOT NULL);
    \\CREATE TABLE messages (
    \\  mailbox TEXT NOT NULL, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
    \\  size INTEGER NOT NULL, header BLOB NOT NULL,
    \\  PRIMARY KEY (mailbox, uidvalidity, uid)
    \\) WITHOUT ROWID;
    \\PRAGMA user_version = 1;
;

const now_sql = "CAST(strftime('%s','now') AS INTEGER)";

pub const Store = struct {
    db: sqlite.Db,

    /// Opens or creates the cache at `path` (":memory:" in tests). A file with
    /// a different schema version is rebuilt; it is only a cache.
    pub fn open(path: [:0]const u8) Error!Store {
        var db: sqlite.Db = try .open(path);
        errdefer db.close();
        const v = try db.prepare("PRAGMA user_version");
        defer v.finalize();
        const version = if (try v.step()) v.int(0) else 0;
        try v.reset();
        if (version != schema_version) try db.exec(schema);
        return .{ .db = db };
    }

    pub fn close(self: *Store) void {
        self.db.close();
        self.* = undefined;
    }

    /// True if the mailbox list was stored less than `ttl_sec` seconds ago.
    pub fn mailboxesFresh(self: *Store, ttl_sec: i64) Error!bool {
        const q = try self.db.prepare("SELECT 1 FROM meta WHERE key = 'mailboxes_fetched_at' AND value > " ++ now_sql ++ " - ?1");
        defer q.finalize();
        try q.bindInt(1, ttl_sec);
        return q.step();
    }

    pub fn loadMailboxes(self: *Store, arena: Allocator) Error![]imap.Mailbox {
        const q = try self.db.prepare("SELECT name, delimiter, flags FROM mailboxes ORDER BY name");
        defer q.finalize();
        var out: std.ArrayList(imap.Mailbox) = .empty;
        while (try q.step()) {
            const delim = q.text(1);
            var flags: std.ArrayList([]const u8) = .empty;
            var it = std.mem.tokenizeScalar(u8, q.text(2), ' ');
            while (it.next()) |f| try flags.append(arena, try arena.dupe(u8, f));
            try out.append(arena, .{
                .name = try arena.dupe(u8, q.text(0)),
                .delimiter = if (delim.len == 1) delim[0] else null,
                .flags = flags.items,
            });
        }
        return out.items;
    }

    /// Replaces the stored list, drops cached messages of mailboxes that no
    /// longer exist, and marks the list fresh — all in one transaction.
    pub fn replaceMailboxes(self: *Store, arena: Allocator, boxes: []const imap.Mailbox) Error!void {
        try self.db.exec("BEGIN IMMEDIATE");
        errdefer self.db.exec("ROLLBACK") catch {};
        try self.db.exec("DELETE FROM mailboxes");
        const ins = try self.db.prepare("INSERT OR REPLACE INTO mailboxes (name, delimiter, flags) VALUES (?1, ?2, ?3)");
        defer ins.finalize();
        for (boxes) |b| {
            try ins.bindText(1, b.name);
            try ins.bindText(2, if (b.delimiter) |*d| d[0..1] else "");
            try ins.bindText(3, try std.mem.join(arena, " ", b.flags));
            try ins.run();
        }
        try self.db.exec("DELETE FROM messages WHERE mailbox NOT IN (SELECT name FROM mailboxes)");
        try self.db.exec("INSERT OR REPLACE INTO meta (key, value) VALUES ('mailboxes_fetched_at', " ++ now_sql ++ ")");
        try self.db.exec("COMMIT");
    }

    /// Forces the next mailbox-list read to go to the server.
    pub fn markMailboxesStale(self: *Store) Error!void {
        try self.db.exec("DELETE FROM meta WHERE key = 'mailboxes_fetched_at'");
    }

    /// Drops cached messages of `mailbox` whose UIDVALIDITY differs from `uidvalidity`.
    pub fn syncUidvalidity(self: *Store, mailbox: []const u8, uidvalidity: u32) Error!void {
        const q = try self.db.prepare("DELETE FROM messages WHERE mailbox = ?1 AND uidvalidity <> ?2");
        defer q.finalize();
        try q.bindText(1, mailbox);
        try q.bindInt(2, uidvalidity);
        try q.run();
    }

    /// Cached rows for `uids` (missing UIDs are simply absent).
    pub fn getMessages(self: *Store, arena: Allocator, mailbox: []const u8, uidvalidity: u32, uids: []const u32) Error![]imap.Fetched {
        const q = try self.db.prepare("SELECT size, header FROM messages WHERE mailbox = ?1 AND uidvalidity = ?2 AND uid = ?3");
        defer q.finalize();
        var out: std.ArrayList(imap.Fetched) = .empty;
        for (uids) |uid| {
            try q.bindText(1, mailbox);
            try q.bindInt(2, uidvalidity);
            try q.bindInt(3, uid);
            if (try q.step()) try out.append(arena, .{
                .uid = uid,
                .size = @intCast(q.int(0)),
                .data = try arena.dupe(u8, q.blob(1)),
                .flags = null,
            });
            try q.reset();
        }
        return out.items;
    }

    /// Stores header + size rows; items without header data are skipped.
    pub fn putMessages(self: *Store, mailbox: []const u8, uidvalidity: u32, items: []const imap.Fetched) Error!void {
        try self.db.exec("BEGIN IMMEDIATE");
        errdefer self.db.exec("ROLLBACK") catch {};
        const ins = try self.db.prepare("INSERT OR REPLACE INTO messages (mailbox, uidvalidity, uid, size, header) VALUES (?1, ?2, ?3, ?4, ?5)");
        defer ins.finalize();
        for (items) |item| {
            const header = item.data orelse continue;
            try ins.bindText(1, mailbox);
            try ins.bindInt(2, uidvalidity);
            try ins.bindInt(3, item.uid);
            try ins.bindInt(4, item.size);
            try ins.bindBlob(5, header);
            try ins.run();
        }
        try self.db.exec("COMMIT");
    }

    pub fn clear(self: *Store) Error!void {
        try self.db.exec("BEGIN IMMEDIATE; DELETE FROM messages; DELETE FROM mailboxes; DELETE FROM meta; COMMIT;");
    }
};
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 45/45 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: SQLite cache for mailbox list and message headers/sizes`

---
### Task 11: Account registry with reconnect and cache
**Files:**
- Create: `src/accounts.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Consumes: `config.Account`, `config.Settings` (Task 7), `imap.Session` (Task 1), `mutf7.encode` (Task 4), `Store` (Task 10).
- Produces: `accounts.Error = imap.Error || error{LoginFailed}`; `Registry.init(gpa, []config.Account, config.Settings) !Registry`; `deinit()` (logs out, closes caches, wipes passwords); `find(name) ?usize` (case-insensitive); `run(idx, op: anytype) Error!void` where `op` is a pointer to a struct with `pub fn run(self, *Session) accounts.Error!void`; `diag() []const u8`; `cache(idx) ?*Store`; `cacheFailed(idx, anyerror)`; `clearCache(idx) bool`; `mailboxList(idx, arena, refresh: bool) Error![]imap.Mailbox`; `drafts(idx, arena) Error![:0]const u8`; field `slots[idx].session: ?Session` (used by itest).

- [ ] **Step 1: Write the failing tests**

Create `src/accounts.zig` containing only the tests:

```zig
const testing = std.testing;

const Noop = struct {
    pub fn run(_: *Noop, _: *Session) Error!void {}
};

const no_cache: config.Settings = .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600 };

fn localAccount(password: [:0]u8, drafts_name: ?[]const u8) config.Account {
    return .{
        .name = "local",
        .host = "127.0.0.1",
        .port = 1, // nothing listens here
        .login = "me",
        .password = password,
        .readonly = false,
        .drafts = drafts_name,
    };
}

test "unreachable server reports a connect diagnostic without the password" {
    const pw = try testing.allocator.dupeSentinel(u8, "s3cret", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, &accounts, no_cache);
    defer reg.deinit();

    try testing.expectEqual(0, reg.find("LOCAL").?);
    try testing.expect(reg.find("other") == null);

    var op: Noop = .{};
    try testing.expectError(error.ConnectFailed, reg.run(0, &op));
    try testing.expectEqualStrings("account \"local\": cannot connect to 127.0.0.1:1", reg.diag());
    try testing.expect(std.mem.find(u8, reg.diag(), "s3cret") == null);
}

test "configured drafts override is encoded without contacting the server" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, "Entwürfe")};
    var reg: Registry = try .init(testing.allocator, &accounts, no_cache);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("Entw&APw-rfe", try reg.drafts(0, arena_state.allocator()));
}

test "fresh cached mailbox list is served without the server; clearCache empties it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}/nested/cache", .{&tmp.sub_path});
    defer testing.allocator.free(dir);

    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600 });
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Seed the cache as if a LIST had happened.
    const store = reg.cache(0).?;
    try store.replaceMailboxes(a, &.{.{ .name = "Brouillons", .delimiter = '/', .flags = &.{"\\Drafts"} }});

    // Served from cache: the server (127.0.0.1:1) is never contacted.
    const boxes = try reg.mailboxList(0, a, false);
    try testing.expectEqualStrings("Brouillons", boxes[0].name);
    try testing.expectEqualStrings("Brouillons", try reg.drafts(0, a));

    // refresh forces the server, which is unreachable here.
    try testing.expectError(error.ConnectFailed, reg.mailboxList(0, a, true));

    try testing.expect(reg.clearCache(0));
    try testing.expectError(error.ConnectFailed, reg.mailboxList(0, a, false));
}

test "corrupt cache file is rebuilt" {
    // The rebuild logs a warning by design; keep test output clean.
    testing.log_level = .err;
    defer testing.log_level = .warn;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "local.sqlite3", .data = "not a database, just some text" });
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    defer testing.allocator.free(dir);

    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600 });
    defer reg.deinit();
    try testing.expect(reg.cache(0) != null);
}

test "caching disabled: no store, clearCache reports false" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, &accounts, no_cache);
    defer reg.deinit();
    try testing.expect(reg.cache(0) == null);
    try testing.expect(!reg.clearCache(0));
}
```

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("accounts.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/accounts.zig`.

- [ ] **Step 3: Implement**

Insert above the tests, at the very top of `src/accounts.zig`:

```zig
//! Account registry: lazily connected sessions, health check, one
//! reconnect-and-retry, per-account cache, mailbox list, drafts discovery
//! (spec §5; ADRs 0006, 0013).

const std = @import("std");
const Allocator = std.mem.Allocator;
const config = @import("config.zig");
const imap = @import("imap/session.zig");
const mutf7 = @import("imap/mutf7.zig");
const Store = @import("cache/store.zig").Store;

pub const Session = imap.Session;
pub const Error = imap.Error || error{LoginFailed};

pub const timeout_sec: c_long = 60;

const log = std.log.scoped(.accounts);

pub const Registry = struct {
    gpa: Allocator,
    accounts: []config.Account,
    settings: config.Settings,
    slots: []Slot,
    /// Human-readable cause of the most recent failure (no secrets).
    diag_buf: [512]u8 = undefined,
    diag_len: usize = 0,

    const CacheState = union(enum) { unopened, open: Store, disabled };

    const Slot = struct {
        session: ?Session = null,
        drafts: ?[:0]u8 = null, // wire-encoded, owned by gpa
        cache: CacheState = .unopened,
    };

    pub fn init(gpa: Allocator, accounts: []config.Account, settings: config.Settings) Allocator.Error!Registry {
        const slots = try gpa.alloc(Slot, accounts.len);
        @memset(slots, .{});
        return .{ .gpa = gpa, .accounts = accounts, .settings = settings, .slots = slots };
    }

    pub fn deinit(self: *Registry) void {
        for (self.slots, self.accounts) |*slot, *account| {
            if (slot.session) |*s| s.close();
            if (slot.drafts) |d| self.gpa.free(d);
            switch (slot.cache) {
                .open => |*store| store.close(),
                else => {},
            }
            account.wipe();
        }
        self.gpa.free(self.slots);
        self.* = undefined;
    }

    pub fn find(self: *Registry, name: []const u8) ?usize {
        for (self.accounts, 0..) |a, i| if (std.ascii.eqlIgnoreCase(a.name, name)) return i;
        return null;
    }

    pub fn diag(self: *const Registry) []const u8 {
        return self.diag_buf[0..self.diag_len];
    }

    fn setDiag(self: *Registry, comptime fmt: []const u8, args: anytype) void {
        const out = std.mem.print(&self.diag_buf, fmt, args) catch blk: {
            const ellipsis = "...";
            @memcpy(self.diag_buf[self.diag_buf.len - ellipsis.len ..], ellipsis);
            break :blk self.diag_buf[0..];
        };
        self.diag_len = out.len;
    }

    /// Runs `op.run(*Session) Error!void` on a live session for account `idx`.
    /// If the connection drops mid-call, reconnects once and retries.
    pub fn run(self: *Registry, idx: usize, op: anytype) Error!void {
        self.diag_len = 0;
        var attempt: u2 = 0;
        while (true) : (attempt += 1) {
            const s = try self.live(idx);
            if (op.run(s)) |_| {
                return;
            } else |err| switch (err) {
                error.ConnectionLost => {
                    self.drop(idx);
                    if (attempt == 0) continue;
                    self.setDiag("account \"{s}\": connection lost twice; giving up", .{self.accounts[idx].name});
                    return err;
                },
                error.ServerRejected => {
                    self.setDiag("IMAP server rejected the command: {s}", .{s.lastResponse()});
                    // The mailbox may have been renamed or deleted elsewhere.
                    if (self.cache(idx)) |store| store.markMailboxesStale() catch |e| self.cacheFailed(idx, e);
                    return err;
                },
                error.ProtocolError => {
                    self.drop(idx);
                    self.setDiag("account \"{s}\": unparseable server response", .{self.accounts[idx].name});
                    return err;
                },
                else => return err,
            }
        }
    }

    /// Returns a connected, logged-in session, reconnecting if the cached one
    /// fails NOOP.
    fn live(self: *Registry, idx: usize) Error!*Session {
        const slot = &self.slots[idx];
        if (slot.session) |*s| {
            if (s.noop()) |_| return s else |_| self.drop(idx);
        }
        const a = &self.accounts[idx];
        var s = Session.connect(a.host, a.port, timeout_sec) catch |err| {
            self.setDiag("account \"{s}\": cannot connect to {s}:{d}", .{ a.name, a.host, a.port });
            return err;
        };
        s.login(a.login, a.password) catch |err| {
            self.setDiag("account \"{s}\": login failed: {s}", .{ a.name, s.lastResponse() });
            s.abandon();
            return switch (err) {
                error.ServerRejected => error.LoginFailed,
                else => err,
            };
        };
        slot.session = s;
        return &slot.session.?;
    }

    fn drop(self: *Registry, idx: usize) void {
        if (self.slots[idx].session) |*s| s.abandon();
        self.slots[idx].session = null;
    }

    // ---- cache ------------------------------------------------------------

    /// The account's cache, opened on first use; null when caching is
    /// disabled or the cache failed. Never fails a tool call.
    pub fn cache(self: *Registry, idx: usize) ?*Store {
        const slot = &self.slots[idx];
        switch (slot.cache) {
            .open => |*store| return store,
            .disabled => return null,
            .unopened => {},
        }
        slot.cache = .disabled;
        const dir = self.settings.cache_dir orelse return null;
        const store = openCache(self.gpa, dir, self.accounts[idx].name) catch |err| {
            log.warn("account \"{s}\": cache unavailable ({t}); continuing without it", .{ self.accounts[idx].name, err });
            return null;
        };
        slot.cache = .{ .open = store };
        return &slot.cache.open;
    }

    /// Logs a cache failure once and stops using that account's cache.
    pub fn cacheFailed(self: *Registry, idx: usize, err: anyerror) void {
        const slot = &self.slots[idx];
        log.warn("account \"{s}\": cache error ({t}); continuing without it", .{ self.accounts[idx].name, err });
        switch (slot.cache) {
            .open => |*store| store.close(),
            else => {},
        }
        slot.cache = .disabled;
    }

    /// Deletes all cached rows for the account. False if caching is off.
    pub fn clearCache(self: *Registry, idx: usize) bool {
        const store = self.cache(idx) orelse return false;
        store.clear() catch |err| {
            self.cacheFailed(idx, err);
            return false;
        };
        return true;
    }

    /// Every mailbox on the account (`LIST "" "*"`), from the cache when it is
    /// fresh and `refresh` is false. Names are in wire form.
    pub fn mailboxList(self: *Registry, idx: usize, arena: Allocator, refresh: bool) Error![]imap.Mailbox {
        if (!refresh) if (self.cache(idx)) |store| {
            const cached: ?[]imap.Mailbox = blk: {
                const fresh = store.mailboxesFresh(self.settings.mailbox_ttl) catch |e| break :blk self.cacheMiss(idx, e);
                if (!fresh) break :blk null;
                break :blk store.loadMailboxes(arena) catch |e| self.cacheMiss(idx, e);
            };
            if (cached) |boxes| return boxes;
        };
        var op: ListAll = .{ .arena = arena };
        try self.run(idx, &op);
        if (self.cache(idx)) |store| store.replaceMailboxes(arena, op.result) catch |e| self.cacheFailed(idx, e);
        return op.result;
    }

    fn cacheMiss(self: *Registry, idx: usize, err: anyerror) ?[]imap.Mailbox {
        self.cacheFailed(idx, err);
        return null;
    }

    /// Wire-encoded drafts mailbox: IMAP_<NAME>_DRAFTS, else the \Drafts
    /// special-use mailbox, else "Drafts". Cached per process.
    pub fn drafts(self: *Registry, idx: usize, arena: Allocator) Error![:0]const u8 {
        const slot = &self.slots[idx];
        if (slot.drafts) |d| return d;
        const name: []const u8 = if (self.accounts[idx].drafts) |utf8|
            mutf7.encode(arena, utf8) catch |err| switch (err) {
                error.InvalidUtf8 => utf8,
                error.OutOfMemory => return error.OutOfMemory,
            }
        else blk: {
            for (try self.mailboxList(idx, arena, false)) |b| for (b.flags) |f| {
                if (std.ascii.eqlIgnoreCase(f, "\\Drafts")) break :blk b.name;
            };
            break :blk "Drafts";
        };
        slot.drafts = try self.gpa.dupeSentinel(u8, name, 0);
        return slot.drafts.?;
    }
};

const ListAll = struct {
    arena: Allocator,
    result: []imap.Mailbox = &.{},

    pub fn run(self: *ListAll, s: *Session) Error!void {
        self.result = try s.list(self.arena, "", "*");
    }
};

/// Creates `dir` (mode 0700) and opens `<dir>/<account>.sqlite3` with a
/// 0077 umask so the database and its WAL files are private. A corrupt file is
/// deleted and recreated once.
fn openCache(gpa: Allocator, dir: []const u8, account: []const u8) !Store {
    try makePath(gpa, dir);
    const lower = try std.ascii.allocLowerString(gpa, account);
    defer gpa.free(lower);
    const path = try gpa.printSentinel("{s}/{s}.sqlite3", .{ dir, lower }, 0);
    defer gpa.free(path);

    const old_mask = std.c.umask(0o077);
    defer _ = std.c.umask(old_mask);
    return Store.open(path) catch |err| switch (err) {
        error.SqliteCorrupt => {
            log.warn("cache file {s} is corrupt; rebuilding", .{path});
            _ = std.c.unlink(path);
            return Store.open(path);
        },
        else => return err,
    };
}

/// mkdir -p with mode 0700 for any component it creates.
fn makePath(gpa: Allocator, dir: []const u8) !void {
    const z = try gpa.dupeSentinel(u8, dir, 0);
    defer gpa.free(z);
    var i: usize = 1;
    while (i <= z.len) : (i += 1) {
        if (i < z.len and z[i] != '/') continue;
        const saved = z[i];
        z[i] = 0;
        defer z[i] = saved;
        if (std.c.mkdir(z[0..i :0], 0o700) != 0) {
            switch (std.c.errno(-1)) {
                .EXIST => {},
                else => |e| {
                    log.warn("cannot create {s}: {t}", .{ z[0..i], e });
                    return error.CacheDirUnavailable;
                },
            }
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 50/50 tests pass (one test connects to 127.0.0.1:1 and expects refusal; the corrupt-cache test silences its expected warning).

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: account registry with reconnect, per-account cache, mailbox list`

---
### Task 12: Tool descriptions, schemas, and handlers

**Files:**
- Create: `src/descriptions.zig`, `src/tools.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Consumes: everything from Tasks 1–11.
- Produces: `tools.Outcome = union(enum){ content: []const u8, tool_error: []const u8, invalid_params: []const u8 }`;
  `tools.call(registry: *Registry, arena, name, args: ?std.json.ObjectMap) Allocator.Error!?Outcome` (null = unknown tool);
  `tools.writeList(jw: *std.json.Stringify) Stringify.Error!void`; `tools.tools` (14 entries, `search` at index 4, `clear_cache` last);
  `tools.alignToUids(arena, uids, fetched) ![]?*const Fetched`.

- [ ] **Step 1: Write the descriptions** (data only, no tests)

`src/descriptions.zig`:

```zig
//! Tool descriptions, adapted from vivier/imap-mcp-server docstrings with an
//! `account` argument added. These are what the model reads; edit with care.

pub const account_param = "Account name, as returned by list_accounts().";

pub const list_accounts =
    \\Lists the configured IMAP accounts. Every other tool takes one of these
    \\names as its `account` argument.
    \\
    \\Return:
    \\    [ {"name": "tetra", "login": "me@example.org", "readonly": false}, ... ]
    \\    readonly accounts refuse change_keywords and create_message.
;

pub const whoami =
    \\Returns the configured email address (login) for the given account.
    \\Use it to confirm which mailbox the other commands will operate on.
;

pub const list_mailboxes =
    \\Enumerates mailboxes under a given folder.
    \\
    \\Args:
    \\    directory: base folder to search (e.g. "INBOX" for standard inbox,
    \\               INBOX/Trash for standard trash folder, ...)
    \\               if empty - get from root, includes "Sent", "Trash", "Drafts", "Junk", ...
    \\    pattern:   glob-like match for names directory (e.g., "*" for all children,
    \\               and for instance "Archives*" to match all archives folders
    \\               * is a wildcard, and matches zero or more characters at this position
    \\               % is similar to * but it does not match a hierarchy delimiter
    \\
    \\Examples:
    \\    - All folders: list_mailboxes(account, "", "*")
    \\    - Only Archives tree: list_mailboxes(account, "Archives", "*")
    \\    - Root-level folders starting with "Q": list_mailboxes(account, "", "Q%")
    \\
    \\Return:
    \\    a list of mailboxes: PATH for the full path, DELIMITER for the path
    \\    delimiter and FLAGS for the list of the flags of the mailbox.
    \\
    \\    Flags (RFC 6154):
    \\        \HasNoChildren     mailbox has no child mailbox
    \\        \Sent              mailbox is the Sent mailbox
    \\        \Junk              mailbox is the Junk mailbox
    \\        \Drafts            mailbox is the Drafts mailbox
    \\        \Flagged           mailbox presents all messages marked in some way as "important"
    \\        \Archive           mailbox is used to archive messages
    \\        \All               mailbox presents all messages in the user's message store
    \\        \Trash             mailbox is the Trash mailbox
    \\Notes:
    \\    - Paths in results are absolute from the root (so use INBOX/...).
    \\    - The delimiter varies by server ("/" or ".").
    \\    - Results come from a cached mailbox list (refreshed hourly by
    \\      default). Pass refresh=true if a folder was just created, renamed,
    \\      or deleted in another mail client.
;

pub const mailboxes_status =
    \\Get the status of a mailbox: the number of messages, recent messages and
    \\unseen messages.
    \\
    \\Args:
    \\    directory: mailbox to get the status of
    \\
    \\Return a status like:
    \\    { "MESSAGES": 41, "RECENT": 0, "UNSEEN": 5 }
;

pub const search =
    \\Search for messages in a given mailbox with given criteria.
    \\Return a list of message UIDs (strings), ascending.
    \\
    \\Args:
    \\    directory: mailbox to search; search doesn't include child folders.
    \\               Like "INBOX", "Sent", "Drafts", "Trash"; get the list with
    \\               list_mailboxes(account, "", "*")
    \\    criteria: IMAP SEARCH criteria (RFC 3501), sent to the server as-is
    \\
    \\    Possible criteria:
    \\        ALL                     all emails
    \\        ANSWERED/UNANSWERED     with/without the Answered flag
    \\        SEEN/UNSEEN             with/without the Seen flag
    \\        FLAGGED/UNFLAGGED       with/without the Flagged flag
    \\        DRAFT/UNDRAFT           with/without the Draft flag
    \\        DELETED/UNDELETED       with/without the Deleted flag
    \\        NEW/OLD                 with/without the recent flag
    \\        FROM "email"            with email address in the FROM field
    \\        TO "email"              with email address in the TO field
    \\        SUBJECT "subject"       with subject in the SUBJECT field
    \\        BODY "string"           with string in the BODY of the message
    \\        TEXT "string"           with string in the HEADER or the BODY
    \\        KEYWORD keyword         message has the given keyword/label (atom, no quotes: KEYWORD AI)
    \\        BCC "email"             with email in the BCC field
    \\        CC "email"              with email in the CC field
    \\        ON DD-Mon-YYYY          internal date is within that day (e.g. 15-Mar-2000)
    \\        SINCE DD-Mon-YYYY       internal date is within or later than that day
    \\        BEFORE DD-Mon-YYYY      internal date is earlier than that day
    \\        SENTON DD-Mon-YYYY      Date: header is within that day
    \\        SENTSINCE DD-Mon-YYYY   Date: header is within or later than that day
    \\        SENTBEFORE DD-Mon-YYYY  Date: header is earlier than that day
    \\        LARGER SIZE             size is larger than SIZE bytes
    \\        SMALLER SIZE            size is smaller than SIZE bytes
    \\        HEADER "tag" "string"   header tag contains string
    \\        X-GM-LABELS "string"    has this Gmail label (Gmail only)
    \\        UID uid_list            has a UID in uid_list (like 1,2,23)
    \\
    \\    Criteria use prefix notation. Criteria at the same level are AND-ed:
    \\        SEEN UNANSWERED FLAGGED
    \\    NOT negates one key, which may be a parenthesized group:
    \\        NOT (SEEN UNANSWERED FLAGGED)
    \\    OR takes exactly two keys; nest it for more:
    \\        OR FROM "a@example" OR FROM "b@example" FROM "c@example"
    \\    Keys after an OR are AND-ed with it:
    \\        OR FROM "a@example" FROM "b@example" ON 01-Jan-2025
    \\
    \\Notes:
    \\    UIDs are only valid relative to the given directory.
    \\    Sent, Drafts, Trash are usually at root level, not under INBOX/.
    \\    Never show UIDs to the user; they are not useful to them.
    \\    Pass keywords as atoms: search(account, "INBOX", "KEYWORD AI"), not KEYWORD "AI".
    \\    Some servers return nothing for NOT on header keys (NOT FROM "x");
    \\    if a negated header search is unexpectedly empty, search the positive
    \\    form and subtract.
;

const uids_note =
    \\    uids: an array of UID strings from search()
    \\
    \\Results are aligned with `uids`: one entry per input UID, in the same
    \\order, null for a UID that does not exist in the mailbox.
;

pub const get_header =
    \\Read message headers for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++
    \\
    \\Return:
    \\    list of {lowercased header name: [raw values]} (RFC 2047
    \\    encoded-words are not decoded)
;

pub const get_header_field =
    \\Read one header field for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
    \\    field: header field name (case-insensitive), e.g. "Message-ID"
++ "\n" ++ uids_note ++
    \\
    \\Return:
    \\    list of [raw values]; [] when the message lacks the field
;

pub const get_text =
    \\Read the plain text body for the given UIDs in directory. Concatenates
    \\every text/plain part that is not an attachment. Charset is UTF-8.
    \\Encrypted (PGP/MIME) messages are not decrypted; a marker is returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note;

pub const get_html =
    \\Read the HTML body for the given UIDs in directory. Concatenates every
    \\text/html part that is not an attachment. Charset is UTF-8.
    \\Encrypted (PGP/MIME) messages are not decrypted; a marker is returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note;

pub const get_size =
    \\Read the message size in bytes (RFC822.SIZE) for the given UIDs.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note;

pub const get_keywords =
    \\Read the keywords (IMAP flags) for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++
    \\
    \\Return, e.g. for get_keywords(account, "INBOX", ["250855", "999"]):
    \\    [ {"250855": ["\\Flagged", "\\Seen", "NonJunk"]}, {"999": null} ]
    \\
    \\Notes:
    \\    keyword | general meaning
    \\    --------+-----------------
    \\    $label1 | Important
    \\    $label2 | Work
    \\    $label3 | Personal
    \\    $label4 | To Do
    \\    $label5 | Later
    \\
    \\    To search messages with a keyword use search() with criteria
    \\    KEYWORD, for instance search(account, "INBOX", "KEYWORD $label2")
;

pub const change_keywords =
    \\Add or remove keywords (IMAP flags) on the given UIDs. Refused for
    \\read-only accounts.
    \\
    \\Args:
    \\    directory: directory containing the messages
    \\    uids: an array of UID strings
    \\    keywords: keywords to add or remove, e.g. ["\\Flagged", "$label2"]
    \\    set: true to add the keywords, false to remove them
    \\
    \\Return:
    \\    the resulting keywords for each UID (same format as get_keywords())
;

pub const create_message =
    \\Create a message in the account's Drafts folder. Refused for read-only
    \\accounts.
    \\
    \\Args:
    \\    content: raw RFC 822 content of the mail (headers, blank line, body)
    \\
    \\Return:
    \\    {"status": "OK", "data": [server response text]}
    \\
    \\Notes:
    \\    In the header, use the current date and time.
    \\    Check the date in the header before calling create_message.
    \\    If the message is a reply to another one, its "In-Reply-To" header
    \\    must contain the "Message-ID" of the original message.
;

pub const clear_cache =
    \\Deletes this account's local cache (mailbox list, message headers and
    \\sizes). Use when the user asks to clear cached data or results look
    \\stale. Nothing on the IMAP server is changed.
    \\
    \\Return:
    \\    {"status": "OK"} (with a "note" when caching is disabled)
;
```

- [ ] **Step 2: Write the failing tests**

Create `src/tools.zig` containing only the tests:

```zig
const testing = std.testing;
const config = @import("config.zig");

test "alignToUids follows input order, repeats duplicates, nulls missing" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const fetched = [_]Fetched{
        .{ .uid = 3, .size = 30, .data = null, .flags = null },
        .{ .uid = 5, .size = 50, .data = null, .flags = null },
    };
    const out = try alignToUids(arena_state.allocator(), &.{ 5, 4, 3, 5 }, &fetched);
    try testing.expectEqual(50, out[0].?.size);
    try testing.expect(out[1] == null);
    try testing.expectEqual(30, out[2].?.size);
    try testing.expectEqual(50, out[3].?.size);
}

fn testRegistry(accts: []config.Account) !Registry {
    return Registry.init(testing.allocator, accts, .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600 });
}

fn testAccounts() [2]config.Account {
    return .{
        .{ .name = "rw", .host = "127.0.0.1", .port = 1, .login = "rw@example.org", .password = @constCast(&[_:0]u8{}), .readonly = false, .drafts = null },
        .{ .name = "ro", .host = "127.0.0.1", .port = 1, .login = "ro@example.org", .password = @constCast(&[_:0]u8{}), .readonly = true, .drafts = null },
    };
}

fn callJson(reg: *Registry, arena: Allocator, name: []const u8, json_args: []const u8) !?Outcome {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, json_args, .{});
    return call(reg, arena, name, v.object);
}

test "offline tools: list_accounts, whoami" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try testing.expectEqualStrings(
        "[{\"name\":\"rw\",\"login\":\"rw@example.org\",\"readonly\":false},{\"name\":\"ro\",\"login\":\"ro@example.org\",\"readonly\":true}]",
        (try callJson(&reg, a, "list_accounts", "{}")).?.content,
    );
    try testing.expectEqualStrings("ro@example.org", (try callJson(&reg, a, "whoami", "{\"account\":\"RO\"}")).?.content);
    try testing.expect((try callJson(&reg, a, "nope", "{}")) == null);
}

test "errors that never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try testing.expectEqualStrings(
        "unknown account \"x\"; configured accounts: rw, ro",
        (try callJson(&reg, a, "whoami", "{\"account\":\"x\"}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "account \"ro\" is read-only",
        (try callJson(&reg, a, "create_message", "{\"account\":\"ro\",\"content\":\"x\"}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "account \"ro\" is read-only",
        (try callJson(&reg, a, "change_keywords", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"uids\":[\"1\"],\"keywords\":[\"\\\\Seen\"],\"set\":true}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "missing required argument \"account\"",
        (try callJson(&reg, a, "whoami", "{}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "criteria must not contain CR, LF, or NUL",
        (try callJson(&reg, a, "search", "{\"account\":\"rw\",\"criteria\":\"ALL\\r\\nA1 DELETE INBOX\"}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "each uid must be a decimal string between 1 and 4294967295",
        (try callJson(&reg, a, "get_size", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"uids\":[\"1:*\"]}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "argument \"uids\" must be an array of strings",
        (try callJson(&reg, a, "get_size", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"uids\":\"1\"}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "account \"rw\": cannot connect to 127.0.0.1:1",
        (try callJson(&reg, a, "search", "{\"account\":\"rw\"}")).?.tool_error,
    );
}

test "tools/list schema shape" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const list = parsed.value.array.items;
    try testing.expectEqual(tools.len, list.len);
    const s = list[4].object; // search
    try testing.expectEqualStrings("search", s.get("name").?.string);
    const schema = s.get("inputSchema").?.object;
    try testing.expectEqualStrings("INBOX", schema.get("properties").?.object.get("directory").?.object.get("default").?.string);
    const req = schema.get("required").?.array.items;
    try testing.expectEqual(1, req.len);
    try testing.expectEqualStrings("account", req[0].string);
}
```

Add to the `test` block in `src/main.zig`:

```zig
    _ = @import("tools.zig");
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile error `use of undeclared identifier 'std'` in `src/tools.zig`.

- [ ] **Step 4: Implement**

Insert above the tests, at the very top of `src/tools.zig`:

```zig
//! MCP tools (spec §6): schemas, argument handling, and handlers.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;

const accounts = @import("accounts.zig");
const body = @import("body.zig");
const desc = @import("descriptions.zig");
const headers = @import("headers.zig");
const listmatch = @import("listmatch.zig");
const mutf7 = @import("imap/mutf7.zig");
const imap = @import("imap/session.zig");
const text = @import("text.zig");
const validate = @import("validate.zig");

const Registry = accounts.Registry;
const Session = imap.Session;
const Fetched = imap.Fetched;

pub const Outcome = union(enum) {
    /// Successful result text (JSON, or plain text for whoami).
    content: []const u8,
    /// Tool-level failure: returned as a result with isError: true.
    tool_error: []const u8,
    /// Protocol-level failure: JSON-RPC -32602.
    invalid_params: []const u8,
};

const Failure = error{ InvalidParams, ToolFailed } || Allocator.Error;

const Ctx = struct {
    registry: *Registry,
    arena: Allocator,
    args: ?std.json.ObjectMap,
    problem: []const u8 = "",

    fn invalid(ctx: *Ctx, comptime fmt: []const u8, a: anytype) Failure {
        ctx.problem = try ctx.arena.print(fmt, a);
        return error.InvalidParams;
    }

    fn failed(ctx: *Ctx, comptime fmt: []const u8, a: anytype) Failure {
        ctx.problem = try ctx.arena.print(fmt, a);
        return error.ToolFailed;
    }

    fn get(ctx: *Ctx, key: []const u8) ?std.json.Value {
        const obj = ctx.args orelse return null;
        return obj.get(key);
    }

    fn string(ctx: *Ctx, key: []const u8) Failure![]const u8 {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .string) return ctx.invalid("argument \"{s}\" must be a string", .{key});
        return v.string;
    }

    fn stringOr(ctx: *Ctx, key: []const u8, default: []const u8) Failure![]const u8 {
        if (ctx.get(key) == null) return default;
        return ctx.string(key);
    }

    fn strings(ctx: *Ctx, key: []const u8) Failure![]const []const u8 {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .array) return ctx.invalid("argument \"{s}\" must be an array of strings", .{key});
        const out = try ctx.arena.alloc([]const u8, v.array.items.len);
        for (v.array.items, out) |item, *o| {
            if (item != .string) return ctx.invalid("argument \"{s}\" must be an array of strings", .{key});
            o.* = item.string;
        }
        return out;
    }

    fn booleanOr(ctx: *Ctx, key: []const u8, default: bool) Failure!bool {
        if (ctx.get(key) == null) return default;
        return ctx.boolean(key);
    }

    fn boolean(ctx: *Ctx, key: []const u8) Failure!bool {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .bool) return ctx.invalid("argument \"{s}\" must be a boolean", .{key});
        return v.bool;
    }

    fn check(ctx: *Ctx, result: validate.Error!void) Failure!void {
        result catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return ctx.invalid("{s}", .{validate.message(err)}),
        };
    }

    fn uids(ctx: *Ctx) Failure![]u32 {
        const list = try ctx.strings("uids");
        return validate.uids(ctx.arena, list) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return ctx.invalid("{s}", .{validate.message(err)}),
        };
    }

    fn account(ctx: *Ctx) Failure!usize {
        const name = try ctx.string("account");
        if (ctx.registry.find(name)) |idx| return idx;
        var names: std.ArrayList(u8) = .empty;
        for (ctx.registry.accounts, 0..) |a, i| {
            if (i > 0) try names.appendSlice(ctx.arena, ", ");
            try names.appendSlice(ctx.arena, a.name);
        }
        return ctx.failed("unknown account \"{s}\"; configured accounts: {s}", .{ name, names.items });
    }

    fn writable(ctx: *Ctx, idx: usize) Failure!void {
        const a = ctx.registry.accounts[idx];
        if (a.readonly) return ctx.failed("account \"{s}\" is read-only", .{a.name});
    }

    /// UTF-8 mailbox argument -> wire (modified UTF-7), NUL-terminated.
    fn mailbox(ctx: *Ctx, key: []const u8, default: ?[]const u8) Failure![:0]const u8 {
        const utf8 = if (default) |d| try ctx.stringOr(key, d) else try ctx.string(key);
        try ctx.check(validate.mailbox(utf8));
        const wire = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        return ctx.arena.dupeSentinel(u8, wire, 0);
    }

    /// Runs an IMAP operation; maps failures to a tool error.
    fn imapRun(ctx: *Ctx, idx: usize, op: anytype) Failure!void {
        ctx.registry.run(idx, op) catch |err| return ctx.imapFailed(err);
    }

    fn imapFailed(ctx: *Ctx, err: accounts.Error) Failure {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const d = ctx.registry.diag();
        return ctx.failed("{s}", .{if (d.len > 0) d else @errorName(err)});
    }

    fn json(ctx: *Ctx, value: anytype) Failure![]const u8 {
        return Stringify.valueAlloc(ctx.arena, value, .{});
    }
};

const ParamKind = enum { string, string_array, boolean };

const Param = struct {
    name: []const u8,
    kind: ParamKind,
    description: []const u8,
    default: ?[]const u8 = null,
    required: bool = true,
};

const Tool = struct {
    name: []const u8,
    description: []const u8,
    params: []const Param,
    handler: *const fn (*Ctx) Failure![]const u8,
};

const p_account: Param = .{ .name = "account", .kind = .string, .description = desc.account_param };
const p_directory: Param = .{ .name = "directory", .kind = .string, .description = "Mailbox path, e.g. \"INBOX\" or \"Archives/2024\"" };
const p_uids: Param = .{ .name = "uids", .kind = .string_array, .description = "Message UIDs from search()" };

pub const tools = [_]Tool{
    .{ .name = "list_accounts", .description = desc.list_accounts, .params = &.{}, .handler = listAccounts },
    .{ .name = "whoami", .description = desc.whoami, .params = &.{p_account}, .handler = whoami },
    .{ .name = "list_mailboxes", .description = desc.list_mailboxes, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "Base folder; \"\" for the root" },
        .{ .name = "pattern", .kind = .string, .description = "LIST pattern, e.g. \"*\" or \"Archives%\"" },
        .{ .name = "refresh", .kind = .boolean, .description = "true to bypass the cached mailbox list", .required = false },
    }, .handler = listMailboxes },
    .{ .name = "mailboxes_status", .description = desc.mailboxes_status, .params = &.{ p_account, p_directory }, .handler = mailboxesStatus },
    .{ .name = "search", .description = desc.search, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "Mailbox to search", .default = "INBOX" },
        .{ .name = "criteria", .kind = .string, .description = "IMAP SEARCH criteria", .default = "ALL" },
    }, .handler = search },
    .{ .name = "get_header", .description = desc.get_header, .params = &.{ p_account, p_directory, p_uids }, .handler = getHeader },
    .{ .name = "get_header_field", .description = desc.get_header_field, .params = &.{
        p_account, p_directory, p_uids,
        .{ .name = "field", .kind = .string, .description = "Header field name, e.g. \"Message-ID\"" },
    }, .handler = getHeaderField },
    .{ .name = "get_text", .description = desc.get_text, .params = &.{ p_account, p_directory, p_uids }, .handler = getText },
    .{ .name = "get_html", .description = desc.get_html, .params = &.{ p_account, p_directory, p_uids }, .handler = getHtml },
    .{ .name = "get_size", .description = desc.get_size, .params = &.{ p_account, p_directory, p_uids }, .handler = getSize },
    .{ .name = "get_keywords", .description = desc.get_keywords, .params = &.{ p_account, p_directory, p_uids }, .handler = getKeywords },
    .{ .name = "change_keywords", .description = desc.change_keywords, .params = &.{
        p_account, p_directory, p_uids,
        .{ .name = "keywords", .kind = .string_array, .description = "Keywords to add or remove" },
        .{ .name = "set", .kind = .boolean, .description = "true to add, false to remove" },
    }, .handler = changeKeywords },
    .{ .name = "create_message", .description = desc.create_message, .params = &.{
        p_account,
        .{ .name = "content", .kind = .string, .description = "Raw RFC 822 message" },
    }, .handler = createMessage },
    .{ .name = "clear_cache", .description = desc.clear_cache, .params = &.{p_account}, .handler = clearCache },
};

/// Writes the `tools/list` result array.
pub fn writeList(jw: *Stringify) Stringify.Error!void {
    try jw.beginArray();
    for (tools) |t| {
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(t.name);
        try jw.objectField("description");
        try jw.write(t.description);
        try jw.objectField("inputSchema");
        try jw.beginObject();
        try jw.objectField("type");
        try jw.write("object");
        try jw.objectField("properties");
        try jw.beginObject();
        for (t.params) |p| {
            try jw.objectField(p.name);
            try jw.beginObject();
            switch (p.kind) {
                .string => {
                    try jw.objectField("type");
                    try jw.write("string");
                },
                .boolean => {
                    try jw.objectField("type");
                    try jw.write("boolean");
                },
                .string_array => {
                    try jw.objectField("type");
                    try jw.write("array");
                    try jw.objectField("items");
                    try jw.write(.{ .type = "string" });
                },
            }
            try jw.objectField("description");
            try jw.write(p.description);
            if (p.default) |d| {
                try jw.objectField("default");
                try jw.write(d);
            }
            try jw.endObject();
        }
        try jw.endObject();
        try jw.objectField("required");
        try jw.beginArray();
        for (t.params) |p| if (p.required and p.default == null) try jw.write(p.name);
        try jw.endArray();
        try jw.objectField("additionalProperties");
        try jw.write(false);
        try jw.endObject();
        try jw.endObject();
    }
    try jw.endArray();
}

/// Dispatches `tools/call`. Returns null for an unknown tool name.
pub fn call(registry: *Registry, arena: Allocator, name: []const u8, args: ?std.json.ObjectMap) Allocator.Error!?Outcome {
    for (tools) |t| {
        if (!std.mem.eql(u8, t.name, name)) continue;
        var ctx: Ctx = .{ .registry = registry, .arena = arena, .args = args };
        const result = t.handler(&ctx) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidParams => .{ .invalid_params = ctx.problem },
            error.ToolFailed => .{ .tool_error = ctx.problem },
        };
        return .{ .content = result };
    }
    return null;
}

// ---- handlers -------------------------------------------------------------

fn listAccounts(ctx: *Ctx) Failure![]const u8 {
    const Entry = struct { name: []const u8, login: []const u8, readonly: bool };
    const out = try ctx.arena.alloc(Entry, ctx.registry.accounts.len);
    for (ctx.registry.accounts, out) |a, *e| e.* = .{ .name = a.name, .login = a.login, .readonly = a.readonly };
    return ctx.json(out);
}

fn whoami(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    return ctx.registry.accounts[idx].login;
}

fn listMailboxes(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const directory = try ctx.string("directory");
    const pattern = try ctx.string("pattern");
    try ctx.check(validate.mailbox(directory));
    try ctx.check(validate.mailbox(pattern));
    const refresh = try ctx.booleanOr("refresh", false);
    const all = ctx.registry.mailboxList(idx, ctx.arena, refresh) catch |err| return ctx.imapFailed(err);

    const Entry = struct { PATH: []const u8, DELIMITER: ?[]const u8, FLAGS: []const []const u8 };
    var out: std.ArrayList(Entry) = .empty;
    for (all) |m| {
        const path = mutf7.decode(ctx.arena, m.name) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidMutf7 => try text.sanitizeUtf8(ctx.arena, m.name),
        };
        if (!listmatch.matches(path, directory, pattern, m.delimiter)) continue;
        try out.append(ctx.arena, .{
            .PATH = path,
            .DELIMITER = if (m.delimiter) |d| try ctx.arena.dupe(u8, &.{d}) else null,
            .FLAGS = m.flags,
        });
    }
    return ctx.json(out.items);
}

fn mailboxesStatus(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    var op: StatusOp = .{ .mailbox = try ctx.mailbox("directory", null) };
    try ctx.imapRun(idx, &op);
    return ctx.json(.{ .MESSAGES = op.result.messages, .RECENT = op.result.recent, .UNSEEN = op.result.unseen });
}

fn search(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", "INBOX");
    const criteria = try ctx.stringOr("criteria", "ALL");
    try ctx.check(validate.criteria(criteria));
    var op: SearchOp = .{
        .arena = ctx.arena,
        .mailbox = mailbox,
        .command = try ctx.arena.printSentinel("CHARSET UTF-8 {s}", .{criteria}, 0),
    };
    try ctx.imapRun(idx, &op);
    std.mem.sort(u32, op.result, {}, std.sort.asc(u32));
    const out = try ctx.arena.alloc([]const u8, op.result.len);
    for (op.result, out) |u, *s| s.* = try ctx.arena.print("{d}", .{u});
    return ctx.json(out);
}

/// Fetches and aligns results to the input UIDs (spec §6.2).
fn fetchAligned(ctx: *Ctx, what: imap.What) Failure!struct { uids: []u32, items: []?*const Fetched } {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: FetchOp = .{ .arena = ctx.arena, .mailbox = mailbox, .uids = uids, .what = what };
    try ctx.imapRun(idx, &op);
    return .{ .uids = uids, .items = try alignToUids(ctx.arena, uids, op.result) };
}

/// Header + size for each UID, from the cache where possible (ADR 0013).
fn fetchHeaders(ctx: *Ctx) Failure![]?*const Fetched {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: CachedHeadersOp = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = uids };
    try ctx.imapRun(idx, &op);
    return alignToUids(ctx.arena, uids, op.result);
}

fn getHeader(ctx: *Ctx) Failure![]const u8 {
    const items = try fetchHeaders(ctx);
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    jw.beginArray() catch return error.OutOfMemory;
    for (items) |maybe| {
        const item = maybe orelse {
            jw.write(null) catch return error.OutOfMemory;
            continue;
        };
        const hs = try headers.parse(ctx.arena, item.data orelse "");
        // Group values by name, preserving first-appearance order.
        var groups: std.array_hash_map.String(std.ArrayList([]const u8)) = .empty;
        for (hs) |h| {
            const g = try groups.getOrPut(ctx.arena, h.name);
            if (!g.found_existing) g.value_ptr.* = .empty;
            try g.value_ptr.append(ctx.arena, try text.sanitizeUtf8(ctx.arena, h.value));
        }
        jw.beginObject() catch return error.OutOfMemory;
        var it = groups.iterator();
        while (it.next()) |e| {
            jw.objectField(e.key_ptr.*) catch return error.OutOfMemory;
            jw.write(e.value_ptr.items) catch return error.OutOfMemory;
        }
        jw.endObject() catch return error.OutOfMemory;
    }
    jw.endArray() catch return error.OutOfMemory;
    return aw.written();
}

fn getHeaderField(ctx: *Ctx) Failure![]const u8 {
    const field = try ctx.string("field");
    try ctx.check(validate.field(field));
    const items = try fetchHeaders(ctx);
    const out = try ctx.arena.alloc(?[]const []const u8, items.len);
    for (items, out) |maybe, *o| {
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        var values: std.ArrayList([]const u8) = .empty;
        for (try headers.parse(ctx.arena, item.data orelse "")) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, field))
                try values.append(ctx.arena, try text.sanitizeUtf8(ctx.arena, h.value));
        }
        o.* = values.items;
    }
    return ctx.json(out);
}

fn bodies(ctx: *Ctx, kind: body.Kind) Failure![]const u8 {
    const r = try fetchAligned(ctx, .{ .body = true });
    const out = try ctx.arena.alloc(?[]const u8, r.items.len);
    for (r.items, out) |maybe, *o| {
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        o.* = body.render(ctx.arena, item.data orelse "", kind) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return ctx.failed("UID {d}: message could not be parsed as MIME", .{item.uid}),
        };
    }
    return ctx.json(out);
}

fn getText(ctx: *Ctx) Failure![]const u8 {
    return bodies(ctx, .plain);
}

fn getHtml(ctx: *Ctx) Failure![]const u8 {
    return bodies(ctx, .html);
}

fn getSize(ctx: *Ctx) Failure![]const u8 {
    const items = try fetchHeaders(ctx);
    const out = try ctx.arena.alloc(?u32, items.len);
    for (items, out) |maybe, *o| o.* = if (maybe) |item| item.size else null;
    return ctx.json(out);
}

fn keywordsJson(ctx: *Ctx, uids: []const u32, items: []const ?*const Fetched) Failure![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    jw.beginArray() catch return error.OutOfMemory;
    for (uids, items) |uid, maybe| {
        jw.beginObject() catch return error.OutOfMemory;
        jw.objectField(try ctx.arena.print("{d}", .{uid})) catch return error.OutOfMemory;
        if (maybe) |item| {
            jw.write(item.flags orelse &[_][]const u8{}) catch return error.OutOfMemory;
        } else {
            jw.write(null) catch return error.OutOfMemory;
        }
        jw.endObject() catch return error.OutOfMemory;
    }
    jw.endArray() catch return error.OutOfMemory;
    return aw.written();
}

fn getKeywords(ctx: *Ctx) Failure![]const u8 {
    const r = try fetchAligned(ctx, .{ .flags = true });
    return keywordsJson(ctx, r.uids, r.items);
}

fn changeKeywords(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    const keywords = try ctx.strings("keywords");
    try ctx.check(validate.keywords(keywords));
    const add = try ctx.boolean("set");
    var op: StoreOp = .{ .arena = ctx.arena, .mailbox = mailbox, .uids = uids, .keywords = keywords, .add = add };
    try ctx.imapRun(idx, &op);
    return keywordsJson(ctx, uids, try alignToUids(ctx.arena, uids, op.result));
}

fn createMessage(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    const content = try ctx.string("content");
    const drafts = ctx.registry.drafts(idx, ctx.arena) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return ctx.failed("{s}", .{ctx.registry.diag()}),
    };
    var op: AppendOp = .{ .mailbox = drafts, .data = try text.toCrlf(ctx.arena, content) };
    try ctx.imapRun(idx, &op);
    return ctx.json(.{ .status = "OK", .data = .{try text.sanitizeUtf8(ctx.arena, op.response)} });
}

fn clearCache(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    if (!ctx.registry.clearCache(idx)) return ctx.json(.{ .status = "OK", .note = "caching is disabled for this account" });
    return ctx.json(.{ .status = "OK" });
}

// ---- IMAP operations run through Registry.run --------------------------------

const StatusOp = struct {
    mailbox: [:0]const u8,
    result: imap.Status = undefined,

    pub fn run(self: *StatusOp, s: *Session) accounts.Error!void {
        self.result = try s.status(self.mailbox);
    }
};

const SearchOp = struct {
    arena: Allocator,
    mailbox: [:0]const u8,
    command: [:0]const u8,
    result: []u32 = &.{},

    pub fn run(self: *SearchOp, s: *Session) accounts.Error!void {
        _ = try s.examine(self.mailbox);
        self.result = try s.uidSearch(self.arena, self.command);
    }
};

const FetchOp = struct {
    arena: Allocator,
    mailbox: [:0]const u8,
    uids: []const u32,
    what: imap.What,
    result: []Fetched = &.{},

    pub fn run(self: *FetchOp, s: *Session) accounts.Error!void {
        _ = try s.examine(self.mailbox);
        self.result = try s.uidFetch(self.arena, self.uids, self.what);
    }
};

const CachedHeadersOp = struct {
    arena: Allocator,
    registry: *Registry,
    idx: usize,
    mailbox: [:0]const u8,
    uids: []const u32,
    result: []Fetched = &.{},

    pub fn run(self: *CachedHeadersOp, s: *Session) accounts.Error!void {
        const uidvalidity = try s.examine(self.mailbox);
        // Without a UIDVALIDITY, cached UIDs cannot be trusted: go live.
        const store = if (uidvalidity != 0) self.registry.cache(self.idx) else null;

        var cached: []Fetched = &.{};
        if (store) |st| {
            if (st.syncUidvalidity(self.mailbox, uidvalidity)) |_| {
                cached = st.getMessages(self.arena, self.mailbox, uidvalidity, self.uids) catch |e| blk: {
                    self.registry.cacheFailed(self.idx, e);
                    break :blk &.{};
                };
            } else |e| self.registry.cacheFailed(self.idx, e);
        }

        var missing: std.ArrayList(u32) = .empty;
        for (self.uids) |u| {
            for (cached) |c| {
                if (c.uid == u) break;
            } else try missing.append(self.arena, u);
        }
        var fetched: []Fetched = &.{};
        if (missing.items.len > 0) {
            fetched = try s.uidFetch(self.arena, missing.items, .{ .header = true, .size = true });
            if (self.registry.cache(self.idx)) |st| if (uidvalidity != 0)
                st.putMessages(self.mailbox, uidvalidity, fetched) catch |e| self.registry.cacheFailed(self.idx, e);
        }
        self.result = try std.mem.concat(self.arena, Fetched, &.{ cached, fetched });
    }
};

const StoreOp = struct {
    arena: Allocator,
    mailbox: [:0]const u8,
    uids: []const u32,
    keywords: []const []const u8,
    add: bool,
    result: []Fetched = &.{},

    pub fn run(self: *StoreOp, s: *Session) accounts.Error!void {
        _ = try s.select(self.mailbox);
        try s.uidStoreFlags(self.arena, self.uids, self.add, self.keywords);
        self.result = try s.uidFetch(self.arena, self.uids, .{ .flags = true });
    }
};

const AppendOp = struct {
    mailbox: [:0]const u8,
    data: []const u8,
    response: []const u8 = "",

    pub fn run(self: *AppendOp, s: *Session) accounts.Error!void {
        try s.append(self.mailbox, self.data);
        self.response = s.lastResponse();
    }
};

/// One entry per input UID (duplicates repeat), null where the server
/// returned nothing for that UID.
pub fn alignToUids(arena: Allocator, uids: []const u32, fetched: []const Fetched) Allocator.Error![]?*const Fetched {
    var by_uid: std.AutoHashMapUnmanaged(u32, *const Fetched) = .empty;
    for (fetched) |*f| try by_uid.put(arena, f.uid, f);
    const out = try arena.alloc(?*const Fetched, uids.len);
    for (uids, out) |u, *o| o.* = by_uid.get(u);
    return out;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 54/54 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: IMAP tools with cached headers, clear_cache, read-only accounts`

---
### Task 13: Prompts and the JSON-RPC stdio loop

**Files:**
- Create: `src/prompts.zig`, `src/mcp.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Consumes: `tools.call`, `tools.writeList` (Task 12), `Registry` (Task 11).
- Produces: `mcp.serve(gpa, registry: *Registry, in: *std.Io.Reader, out: *std.Io.Writer) !void` (returns at EOF);
  `mcp.handle(arena, registry, msg) Allocator.Error!?[]const u8`; `mcp.server_name`, `mcp.server_version`;
  `prompts.writeList`, `prompts.render(arena, name, args) GetError![]const u8`.

- [ ] **Step 1: Write the failing tests**

Create `src/prompts.zig` containing only its tests:

```zig
const testing = std.testing;

test "render" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var args: std.json.ObjectMap = .empty;
    try args.put(a, "cover_letter", .{ .string = "<cover@x>" });
    try testing.expectEqualStrings(
        "Search emails with In-Reply-To equal to Message-ID of <cover@x>",
        try render(a, "list_patches_of_a_series", args),
    );
    try testing.expectError(error.MissingArgument, render(a, "list_patches_of_a_series", null));
    try testing.expectError(error.UnknownPrompt, render(a, "nope", null));
}
```

Create `src/mcp.zig` containing only its tests:

```zig
const testing = std.testing;

fn roundTrip(input: []const u8) ![]u8 {
    var reg: Registry = try .init(testing.allocator, &.{}, .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600 });
    defer reg.deinit();
    var in: std.Io.Reader = .fixed(input);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    try serve(testing.allocator, &reg, &in, &out.writer);
    return out.toOwnedSlice();
}

test "initialize negotiates version; notifications get no response" {
    const got = try roundTrip(
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
        \\{"jsonrpc":"2.0","id":"p","method":"ping"}
        \\
    );
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"tp-imap-mcp","version":"0.1.0"}}}
        \\{"jsonrpc":"2.0","id":"p","result":{}}
        \\
    , got);
}

test "unknown protocol version falls back to newest" {
    const got = try roundTrip("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}");
    defer testing.allocator.free(got);
    try testing.expect(std.mem.find(u8, got, "\"protocolVersion\":\"2025-11-25\"") != null);
}

test "protocol errors" {
    const got = try roundTrip(
        \\not json
        \\[1,2]
        \\{"jsonrpc":"2.0","id":2,"method":"nope"}
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}
        \\{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"whoami","arguments":{}}}
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"whoami","arguments":{"account":"x"}}}
    );
    defer testing.allocator.free(got);
    var lines = std.mem.splitScalar(u8, got, '\n');
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request must be a JSON object"}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"method not found: nope"}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"unknown tool \"nope\""}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"missing required argument \"account\""}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"unknown account \"x\"; configured accounts: "}],"isError":true}}
    , lines.next().?);
}

test "tools/list and prompts round-trip" {
    const got = try roundTrip(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
        \\{"jsonrpc":"2.0","id":2,"method":"prompts/list"}
        \\{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"review_a_patch_series"}}
        \\
    );
    defer testing.allocator.free(got);
    var lines = std.mem.splitScalar(u8, got, '\n');
    const list = try std.json.parseFromSlice(std.json.Value, testing.allocator, lines.next().?, .{});
    defer list.deinit();
    try testing.expectEqual(14, list.value.object.get("result").?.object.get("tools").?.array.items.len);
    try testing.expect(std.mem.find(u8, lines.next().?, "list_patches_of_a_series") != null);
    try testing.expect(std.mem.find(u8, lines.next().?, "\"role\":\"user\"") != null);
}

test "very long line is read whole" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"pad\":\"");
    try buf.appendNTimes(testing.allocator, 'a', 200_000);
    try buf.appendSlice(testing.allocator, "\"}}\n");
    const got = try roundTrip(buf.items);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n", got);
}

test "id 0 is echoed and arguments may be omitted" {
    const got = try roundTrip(
        \\{"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"list_accounts"}}
        \\
    );
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"[]"}],"isError":false}}
        \\
    , got);
}
```

Add to the `test` block in `src/main.zig`:

```zig
    _ = @import("prompts.zig");
    _ = @import("mcp.zig");
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `zig build test --summary all`
Expected: compile errors `use of undeclared identifier 'std'` in `src/prompts.zig` and `src/mcp.zig`.

- [ ] **Step 3: Implement prompts**

Insert at the top of `src/prompts.zig`:

```zig
//! MCP prompts, carried over verbatim from vivier/imap-mcp-server (spec §6.1).

const std = @import("std");
const Stringify = std.json.Stringify;

const Prompt = struct {
    name: []const u8,
    description: []const u8,
    argument: ?[]const u8,
};

pub const prompts = [_]Prompt{
    .{
        .name = "list_patches_of_a_series",
        .description = "Generates a user message to list all patches in a series given a cover letter.\nFor a cover letter [PATCH 0/X], this will find patches [PATCH 1/X] to [PATCH X/X]",
        .argument = "cover_letter",
    },
    .{
        .name = "review_a_patch_series",
        .description = "Generates a user message with instructions on how to properly review a patch series",
        .argument = null,
    },
};

pub fn writeList(jw: *Stringify) Stringify.Error!void {
    try jw.beginArray();
    for (prompts) |p| {
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(p.name);
        try jw.objectField("description");
        try jw.write(p.description);
        try jw.objectField("arguments");
        try jw.beginArray();
        if (p.argument) |a| try jw.write(.{ .name = a, .required = true });
        try jw.endArray();
        try jw.endObject();
    }
    try jw.endArray();
}

pub const GetError = error{ UnknownPrompt, MissingArgument } || std.mem.Allocator.Error;

/// Returns the user-message text for `prompts/get`.
pub fn render(arena: std.mem.Allocator, name: []const u8, args: ?std.json.ObjectMap) GetError![]const u8 {
    if (std.mem.eql(u8, name, "list_patches_of_a_series")) {
        const v = (if (args) |a| a.get("cover_letter") else null) orelse return error.MissingArgument;
        if (v != .string) return error.MissingArgument;
        return arena.print("Search emails with In-Reply-To equal to Message-ID of {s}", .{v.string});
    }
    if (std.mem.eql(u8, name, "review_a_patch_series")) {
        return "When replying to reviews or patch series: reply to each message individually, include the full original message inline, and place your comment directly beneath the specific line you are annotating. Format your answer on 80 columns";
    }
    return error.UnknownPrompt;
}
```

- [ ] **Step 4: Implement the JSON-RPC loop**

Insert at the top of `src/mcp.zig`:

```zig
//! MCP over stdio: newline-delimited JSON-RPC 2.0 (spec §3, §8).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;

const Registry = @import("accounts.zig").Registry;
const prompts = @import("prompts.zig");
const tools = @import("tools.zig");

pub const server_name = "tp-imap-mcp";
pub const server_version = "0.1.0";

/// Newest first; the first entry is offered when the client asks for an
/// unknown version.
const protocol_versions = [_][]const u8{ "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05" };

const parse_error = -32700;
const invalid_request = -32600;
const method_not_found = -32601;
const invalid_params = -32602;

/// Serves requests until `in` reaches EOF. Each request gets a fresh arena.
pub fn serve(gpa: Allocator, registry: *Registry, in: *std.Io.Reader, out: *std.Io.Writer) !void {
    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    while (true) {
        line.clearRetainingCapacity();
        const at_eof = if (in.streamDelimiter(&line.writer, '\n')) |_| blk: {
            in.toss(1); // the '\n'
            break :blk false;
        } else |err| switch (err) {
            error.EndOfStream => true, // final line without '\n' is still handled
            else => return err,
        };

        const msg = std.mem.trim(u8, line.written(), " \t\r");
        if (msg.len > 0) {
            _ = arena_state.reset(.retain_capacity);
            if (try handle(arena_state.allocator(), registry, msg)) |response| {
                try out.writeAll(response);
                try out.writeByte('\n');
                try out.flush();
            }
        }
        if (at_eof) return;
    }
}

/// Returns the serialized response, or null for notifications.
pub fn handle(arena: Allocator, registry: *Registry, msg: []const u8) Allocator.Error!?[]const u8 {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, msg, .{}) catch
        return try errorResponse(arena, .null, parse_error, "parse error");
    if (root != .object) return try errorResponse(arena, .null, invalid_request, "request must be a JSON object");
    const req = root.object;
    const id = req.get("id");
    const method_v = req.get("method") orelse
        return if (id) |i| try errorResponse(arena, i, invalid_request, "missing method") else null;
    if (method_v != .string)
        return if (id) |i| try errorResponse(arena, i, invalid_request, "method must be a string") else null;
    const method = method_v.string;
    const params: ?std.json.ObjectMap = if (req.get("params")) |p| (if (p == .object) p.object else null) else null;

    // Notifications (no id) never get a response.
    const rid = id orelse return null;

    var aw: std.Io.Writer.Allocating = .init(arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    const W = Stringify.Error;
    const write = struct {
        fn begin(j: *Stringify, i: std.json.Value) W!void {
            try j.beginObject();
            try j.objectField("jsonrpc");
            try j.write("2.0");
            try j.objectField("id");
            try j.write(i);
            try j.objectField("result");
        }
    };

    if (std.mem.eql(u8, method, "initialize")) {
        const requested: ?[]const u8 = if (params) |p| (if (p.get("protocolVersion")) |v| (if (v == .string) v.string else null) else null) else null;
        var version = protocol_versions[0];
        if (requested) |r| for (protocol_versions) |pv| if (std.mem.eql(u8, pv, r)) {
            version = pv;
        };
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.write(.{
            .protocolVersion = version,
            .capabilities = .{ .tools = .{ .listChanged = false }, .prompts = .{ .listChanged = false } },
            .serverInfo = .{ .name = server_name, .version = server_version },
        }) catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "ping")) {
        write.begin(&jw, rid) catch return error.OutOfMemory;
        // `.{}` would serialize as `[]`; the result must be an empty object.
        jw.beginObject() catch return error.OutOfMemory;
        jw.endObject() catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "tools/list")) {
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.beginObject() catch return error.OutOfMemory;
        jw.objectField("tools") catch return error.OutOfMemory;
        tools.writeList(&jw) catch return error.OutOfMemory;
        jw.endObject() catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "tools/call")) {
        const p = params orelse return try errorResponse(arena, rid, invalid_params, "missing params");
        const name_v = p.get("name") orelse return try errorResponse(arena, rid, invalid_params, "missing tool name");
        if (name_v != .string) return try errorResponse(arena, rid, invalid_params, "tool name must be a string");
        const args: ?std.json.ObjectMap = if (p.get("arguments")) |a| switch (a) {
            .object => |o| o,
            .null => null,
            else => return try errorResponse(arena, rid, invalid_params, "arguments must be an object"),
        } else null;
        const outcome = (try tools.call(registry, arena, name_v.string, args)) orelse
            return try errorResponse(arena, rid, invalid_params, try arena.print("unknown tool \"{s}\"", .{name_v.string}));
        const text, const is_error = switch (outcome) {
            .content => |t| .{ t, false },
            .tool_error => |t| .{ t, true },
            .invalid_params => |t| return try errorResponse(arena, rid, invalid_params, t),
        };
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.write(.{
            .content = .{.{ .type = "text", .text = text }},
            .isError = is_error,
        }) catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "prompts/list")) {
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.beginObject() catch return error.OutOfMemory;
        jw.objectField("prompts") catch return error.OutOfMemory;
        prompts.writeList(&jw) catch return error.OutOfMemory;
        jw.endObject() catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "prompts/get")) {
        const p = params orelse return try errorResponse(arena, rid, invalid_params, "missing params");
        const name_v = p.get("name") orelse return try errorResponse(arena, rid, invalid_params, "missing prompt name");
        if (name_v != .string) return try errorResponse(arena, rid, invalid_params, "prompt name must be a string");
        const args: ?std.json.ObjectMap = if (p.get("arguments")) |a| (if (a == .object) a.object else null) else null;
        const text = prompts.render(arena, name_v.string, args) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnknownPrompt => return try errorResponse(arena, rid, invalid_params, "unknown prompt"),
            error.MissingArgument => return try errorResponse(arena, rid, invalid_params, "missing required argument"),
        };
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.write(.{
            .messages = .{.{ .role = "user", .content = .{ .type = "text", .text = text } }},
        }) catch return error.OutOfMemory;
    } else {
        return try errorResponse(arena, rid, method_not_found, try arena.print("method not found: {s}", .{method}));
    }

    jw.endObject() catch return error.OutOfMemory;
    return aw.written();
}

fn errorResponse(arena: Allocator, id: std.json.Value, code: i32, message: []const u8) Allocator.Error![]const u8 {
    return Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .id = id,
        .@"error" = .{ .code = code, .message = message },
    }, .{}) catch error.OutOfMemory;
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `zig build test --summary all`
Expected: 61/61 tests pass.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: MCP JSON-RPC stdio loop and prompts`

---
### Task 14: Entry point, live checks, and client registration

**Files:**
- Replace: `src/main.zig`, `src/itest.zig`
- Create: `imap.env.example`

**Interfaces:**
- Consumes: `config.load`, `config.loadSettings`, `Registry`, `mcp.serve`, `tools.call`, `imap/c.zig` `tpi_logout`.

- [ ] **Step 1: Replace `src/main.zig`**

```zig
//! tp-imap-mcp: an MCP server exposing IMAP mailboxes over stdio.

const std = @import("std");
const config = @import("config.zig");
const mcp = @import("mcp.zig");
const Registry = @import("accounts.zig").Registry;

pub fn main(init: std.process.Init) !u8 {
    var err_buf: [1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &err_buf);
    const stderr = &stderr_writer.interface;

    const arena = init.arena.allocator();
    try stderr.writeAll(mcp.server_name ++ ": ");
    const accounts, const settings = blk: {
        const accounts = config.load(arena, init.environ_map, stderr) catch |err| break :blk err;
        const settings = config.loadSettings(arena, init.environ_map, stderr) catch |err| break :blk err;
        break :blk .{ accounts, settings };
    } catch |err| switch (err) {
        error.InvalidConfig => {
            try stderr.writeAll("\n");
            try stderr.flush();
            return 1;
        },
        error.OutOfMemory => return err,
    };
    try stderr.print("serving {d} account(s) on stdio; cache: {s}\n", .{
        accounts.len,
        settings.cache_dir orelse if (settings.cache_dir_unavailable) "off (set HOME or XDG_CACHE_HOME)" else "off",
    });
    try stderr.flush();

    var registry: Registry = try .init(init.gpa, accounts, settings);
    defer registry.deinit();

    var in_buf: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(init.io, &in_buf);
    var out_buf: [64 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &out_buf);

    try mcp.serve(init.gpa, &registry, &stdin_reader.interface, &stdout_writer.interface);
    return 0;
}

test {
    _ = @import("accounts.zig");
    _ = @import("cache/sqlite.zig");
    _ = @import("cache/store.zig");
    _ = @import("listmatch.zig");
    _ = @import("config.zig");
    _ = @import("headers.zig");
    _ = @import("imap/mutf7.zig");
    _ = @import("imap/session.zig");
    _ = @import("mcp.zig");
    _ = @import("mime_test.zig");
    _ = @import("prompts.zig");
    _ = @import("text.zig");
    _ = @import("tools.zig");
    _ = @import("validate.zig");
}
```

- [ ] **Step 2: Replace `src/itest.zig`**

```zig
//! Live integration checks against a real IMAP account (spec §9).
//!
//!   op run --env-file imap.env -- zig build itest -- <account> [--write <scratch-mailbox>]
//!
//! Read-only by default. Prints only counts and shapes, never message content.
//! Uses a throwaway cache in .zig-cache/itest-cache, never ~/.cache.
//! `--write` adds then removes the keyword $TpImapMcpTest on the newest
//! message of <scratch-mailbox>; use a folder you do not care about.

const std = @import("std");
const config = @import("config.zig");
const tools = @import("tools.zig");
const c = @import("imap/c.zig");
const Registry = @import("accounts.zig").Registry;

var failures: usize = 0;

fn report(ok: bool, comptime what: []const u8, args: anytype) void {
    std.debug.print("{s} " ++ what ++ "\n", .{if (ok) "PASS" else "FAIL"} ++ args);
    if (!ok) failures += 1;
}

const Harness = struct {
    reg: *Registry,
    arena: std.mem.Allocator,
    account: []const u8,

    /// Calls a tool; returns parsed JSON content (or a JSON string for whoami).
    fn call(h: Harness, name: []const u8, comptime args_fmt: []const u8, args: anytype) !?std.json.Value {
        const args_json = try h.arena.print(args_fmt, args);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, h.arena, args_json, .{});
        const outcome = (try tools.call(h.reg, h.arena, name, parsed.object)) orelse return error.UnknownTool;
        switch (outcome) {
            .content => |t| return std.json.parseFromSliceLeaky(std.json.Value, h.arena, t, .{}) catch
                std.json.Value{ .string = t },
            .tool_error, .invalid_params => |t| {
                std.debug.print("     {s}: {s}\n", .{ name, t });
                return null;
            },
        }
    }
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: itest <account> [--write <scratch-mailbox>]\n", .{});
        return 2;
    }
    const account = args[1];
    const write_box: ?[]const u8 = if (args.len >= 4 and std.mem.eql(u8, args[2], "--write")) args[3] else null;

    var diag_buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&diag_buf);
    const accounts = config.load(arena, init.environ_map, &diag) catch |err| {
        std.debug.print("config: {s} ({t})\n", .{ diag.buffered(), err });
        return 2;
    };
    const cache_dir = ".zig-cache/itest-cache";
    var reg: Registry = try .init(init.gpa, accounts, .{ .cache_dir = cache_dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600 });
    defer reg.deinit();
    const idx = reg.find(account) orelse {
        std.debug.print("unknown account {s}\n", .{account});
        return 2;
    };
    const h: Harness = .{ .reg = &reg, .arena = arena, .account = account };
    const acct = try std.json.Stringify.valueAlloc(arena, account, .{});

    const cleared = try h.call("clear_cache", "{{\"account\":{s}}}", .{acct});
    report(cleared != null and reg.cache(idx) != null, "clear_cache (start from an empty cache)", .{});

    const who = try h.call("whoami", "{{\"account\":{s}}}", .{acct});
    report(who != null and who.? == .string, "whoami", .{});

    const boxes = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"*\"}}", .{acct});
    report(boxes != null and boxes.? == .array and boxes.?.array.items.len > 0, "list_mailboxes: {d} mailboxes", .{if (boxes) |b| b.array.items.len else 0});

    const fresh = if (reg.cache(idx)) |store| store.mailboxesFresh(3600) catch false else false;
    report(fresh, "mailbox list cached after first list_mailboxes", .{});
    const again_boxes = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"*\"}}", .{acct});
    report(again_boxes != null and boxes != null and again_boxes.?.array.items.len == boxes.?.array.items.len, "list_mailboxes from cache matches server", .{});
    const inbox = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"inbox\"}}", .{acct});
    report(inbox != null and inbox.?.array.items.len == 1, "local LIST matching: pattern \"inbox\" finds exactly INBOX", .{});
    const refreshed = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"%\",\"refresh\":true}}", .{acct});
    report(refreshed != null and refreshed.?.array.items.len > 0, "list_mailboxes refresh=true", .{});

    const st = try h.call("mailboxes_status", "{{\"account\":{s},\"directory\":\"INBOX\"}}", .{acct});
    report(st != null and st.?.object.get("MESSAGES") != null, "mailboxes_status INBOX", .{});

    const found = try h.call("search", "{{\"account\":{s},\"directory\":\"INBOX\",\"criteria\":\"ALL\"}}", .{acct});
    const uids = if (found) |f| f.array.items else &.{};
    report(found != null, "search ALL: {d} uids", .{uids.len});

    const bad = try h.call("search", "{{\"account\":{s},\"criteria\":\"BOGUSKEY\"}}", .{acct});
    report(bad == null, "search BOGUSKEY is a tool error", .{});

    if (uids.len > 0) {
        // Newest two UIDs plus one that cannot exist, to check alignment.
        const last = uids[uids.len - 1].string;
        const prev = uids[if (uids.len > 1) uids.len - 2 else 0].string;
        const set = try arena.print("[\"{s}\",\"4294967295\",\"{s}\"]", .{ last, prev });
        const per_uid = [_][]const u8{ "get_header", "get_size", "get_keywords", "get_text", "get_html" };
        for (per_uid) |tool| {
            const r = try h.call(tool, "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
            const ok = r != null and r.? == .array and r.?.array.items.len == 3 and
                (if (std.mem.eql(u8, tool, "get_keywords"))
                    r.?.array.items[1].object.get("4294967295").? == .null
                else
                    r.?.array.items[1] == .null) and
                r.?.array.items[0] != .null;
            report(ok, "{s}: aligned, null for missing uid", .{tool});
        }
        // The header/size calls above populated the cache; a second call must
        // agree with the first and the rows must be on disk.
        const h1 = try h.call("get_header_field", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"],\"field\":\"Message-ID\"}}", .{ acct, last });
        const h2 = try h.call("get_header_field", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"],\"field\":\"Message-ID\"}}", .{ acct, last });
        const same = h1 != null and h2 != null and std.mem.eql(u8,
            try std.json.Stringify.valueAlloc(arena, h1.?, .{}),
            try std.json.Stringify.valueAlloc(arena, h2.?, .{}));
        report(same, "cached header matches live header", .{});
        const cached_rows = if (reg.cache(idx)) |store| blk: {
            const wanted = [_]u32{ try std.fmt.parseInt(u32, last, 10), try std.fmt.parseInt(u32, prev, 10) };
            const rows = store.getMessages(arena, "INBOX", uidvalidityOf(&reg, idx), &wanted) catch break :blk 0;
            break :blk rows.len;
        } else 0;
        report(cached_rows == 2 or (cached_rows == 1 and std.mem.eql(u8, last, prev)), "header rows stored in cache: {d}", .{cached_rows});

        const subj = try h.call("get_header_field", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"],\"field\":\"Subject\"}}", .{ acct, last });
        report(subj != null and subj.?.array.items[0] == .array, "get_header_field Subject", .{});

        // Kill the socket behind the registry's back; the next call must reconnect.
        _ = c.tpi_logout(reg.slots[idx].session.?.handle);
        const again = try h.call("get_size", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"]}}", .{ acct, last });
        report(again != null, "reconnects after server-side logout", .{});
    }

    if (write_box) |box| try writeChecks(h, acct, box);

    const wiped = try h.call("clear_cache", "{{\"account\":{s}}}", .{acct});
    const empty = if (reg.cache(idx)) |store| !(store.mailboxesFresh(3600) catch true) else false;
    report(wiped != null and empty, "clear_cache empties the cache", .{});

    std.debug.print("{d} failure(s)\n", .{failures});
    return if (failures == 0) 0 else 1;
}

fn writeChecks(h: Harness, acct: []const u8, box: []const u8) !void {
    const boxj = try std.json.Stringify.valueAlloc(h.arena, box, .{});
    const found = (try h.call("search", "{{\"account\":{s},\"directory\":{s}}}", .{ acct, boxj })) orelse {
        report(false, "write: search {s}", .{box});
        return;
    };
    if (found.array.items.len == 0) {
        report(false, "write: {s} has no messages to test with", .{box});
        return;
    }
    const uid = found.array.items[found.array.items.len - 1].string;
    const base = "{{\"account\":{s},\"directory\":{s},\"uids\":[\"{s}\"],\"keywords\":[\"$TpImapMcpTest\"],\"set\":{s}}}";
    const added = try h.call("change_keywords", base, .{ acct, boxj, uid, "true" });
    report(added != null and hasKeyword(added.?, uid), "change_keywords set", .{});
    const removed = try h.call("change_keywords", base, .{ acct, boxj, uid, "false" });
    report(removed != null and !hasKeyword(removed.?, uid), "change_keywords unset", .{});
}

fn hasKeyword(v: std.json.Value, uid: []const u8) bool {
    const flags = v.array.items[0].object.get(uid) orelse return false;
    if (flags != .array) return false;
    for (flags.array.items) |f| if (std.mem.eql(u8, f.string, "$TpImapMcpTest")) return true;
    return false;
}

/// UIDVALIDITY of INBOX, read through the registry's live session.
fn uidvalidityOf(reg: *Registry, idx: usize) u32 {
    const s = &(reg.slots[idx].session orelse return 0);
    return s.examine("INBOX") catch 0;
}
```

- [ ] **Step 3: Create `imap.env.example`**

```
# Copy to imap.env (git-ignored) and adjust. Values may be op:// references;
# `op run --env-file imap.env -- ...` resolves them before the process starts.
IMAP_ACCOUNTS=tetra
IMAP_TETRA_HOST=op://Tetrapyloctomy/IMAP Tetrapyloctomy/host
IMAP_TETRA_LOGIN=op://Tetrapyloctomy/IMAP Tetrapyloctomy/username
IMAP_TETRA_PASSWORD=op://Tetrapyloctomy/IMAP Tetrapyloctomy/password
# IMAP_TETRA_PORT=993
# IMAP_TETRA_READONLY=1
# IMAP_TETRA_DRAFTS=Drafts

# Cache (ADRs 0013-0015): $XDG_CACHE_HOME/tp-imap-mcp or ~/.cache/tp-imap-mcp
# TP_IMAP_MCP_CACHE=0            # disable caching
# TP_IMAP_MCP_MAILBOX_TTL=3600   # seconds a cached mailbox list stays fresh
```

- [ ] **Step 4: Unit tests and offline smoke tests**

Run: `zig build test --summary all`
Expected: 61/61 pass.

Run: `zig build && env -i ./zig-out/bin/tp_imap_mcp </dev/null; echo "exit=$?"`
Expected: stderr `tp-imap-mcp: IMAP_ACCOUNTS is missing or empty`, then `exit=1`.

Run: `env -i IMAP_ACCOUNTS=a IMAP_A_HOST=h IMAP_A_LOGIN=l IMAP_A_PASSWORD=p HOME=/tmp/tp-imap-mcp-smoke ./zig-out/bin/tp_imap_mcp </dev/null`
Expected: stderr `tp-imap-mcp: serving 1 account(s) on stdio; cache: /tmp/tp-imap-mcp-smoke/.cache/tp-imap-mcp`. (No cache file is created until a tool needs it.)

Run:
```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' \
  | env -i IMAP_ACCOUNTS=a IMAP_A_HOST=h IMAP_A_LOGIN=l IMAP_A_PASSWORD=p ./zig-out/bin/tp_imap_mcp \
  | head -c 120; echo
```
Expected: output starts with `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"list_accounts"`.

- [ ] **Step 5: Live read-only checks (the user runs this)**

The checks need the user's 1Password session. Ask the user to create `imap.env` from the example and run:

```
! op run --env-file imap.env -- zig build itest -- tetra
```

Expected: 20 `PASS` lines (12 read/reconnect checks plus 8 cache checks) and `0 failure(s)`. The cache used is `.zig-cache/itest-cache`. Do not run `--write` unless the user explicitly asks for it and names a scratch mailbox.

If a cache check fails, stop and report it with the output; the cache has not been verified live before this step.

- [ ] **Step 6: Register with an MCP client (the user does this)**

Give the user this registration (absolute paths filled in):

```json
{
  "mcpServers": {
    "imap": {
      "command": "op",
      "args": ["run", "--env-file", "/Users/pablo/code/posiczko/tp-imap-mcp/imap.env", "--",
               "/Users/pablo/code/posiczko/tp-imap-mcp/zig-out/bin/tp_imap_mcp"]
    }
  }
}
```

For Claude Code the equivalent is:
`claude mcp add imap -- op run --env-file /Users/pablo/code/posiczko/tp-imap-mcp/imap.env -- /Users/pablo/code/posiczko/tp-imap-mcp/zig-out/bin/tp_imap_mcp`

After the first real session, confirm the cache file exists with mode 0600: `ls -l ~/.cache/tp-imap-mcp/` (or under `$XDG_CACHE_HOME`).

Verify `create_message` manually (MCP Inspector or the client) only against an account whose drafts folder the user is happy to receive a test message in.

- [ ] **Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is
ready and suggest the message: `feat: entry point, live integration checks, env example`

