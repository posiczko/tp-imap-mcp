# Mailbox Organization Tools — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the assistant organize mail: `create_mailbox`, `rename_mailbox`, `delete_mailbox`, `move_messages` and `copy_messages`, with safe moves, protected system folders, and dry runs for criteria-based selection.

**Architecture:** New libetpan calls behind the flat C shim (CREATE/RENAME/DELETE/SUBSCRIBE, CAPABILITY, UID MOVE/COPY with COPYUID, UID EXPUNGE). A pure `src/organize.zig` holds the rules (protection, move strategy, batching, UID-map pairing). `src/tools.zig` adds five tools whose IMAP work runs as non-retryable registry operations; the registry refreshes the mailbox list after folder changes and drops cached headers of moved messages.

**Tech Stack:** Zig 0.17.0, libetpan 1.10.1 (incl. its UIDPLUS extension), SQLite cache (unchanged schema).

**Spec:** `docs/superpowers/specs/2026-10-08-mailbox-organization-design.md` (base: `docs/superpowers/specs/2026-10-07-tp-imap-mcp-design.md`). Decision: ADR 0021 (written in Task 6).

**Provenance:** Every code block below was compiled and tested before this plan was written: 180/180 unit tests, and 43/43 live checks against the user's Dovecot server with `--organize` (29 existing + 14 organization checks: create, duplicate refusal, append, copy with UID map, criteria dry run, move, rename under a parent, non-empty delete refusal, INBOX protection, delete, cleanup). The plan was replayed task by task on a fresh copy of the repository: each task's tests fail before and pass after (except Task 2, see its note), and the end state is byte-identical to the verified sources. Copy code exactly; if something does not match the stated expectation, stop and report.

## Global Constraints

- Zig 0.17.0; no `@cImport`; C only through `src/imap/c.zig` externs mirroring `src/c/tpi.h`; C compiled `-std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror`.
- No new dependencies.
- All five tools are refused on read-only accounts, except `move_messages`/`copy_messages` with `dry_run=true` (spec §2).
- Plain `EXPUNGE` is never sent; without MOVE, moves use `UID EXPUNGE` (UIDPLUS) or are refused (spec §4.2).
- INBOX, special-use folders and their ancestors are never renamed or deleted; nothing is created or renamed into `[Gmail]/` or `[Google Mail]/` (spec §3.2).
- Criteria default to `dry_run=true`, uids to `false`; at most 5000 messages per call; batches of 500 (spec §2.1, §4.2).
- None of the five operations is retried after a lost connection (spec §5).
- Never run git; each task ends with a hand-off.

## Review Focus

1. **Server without MOVE but with UIDPLUS.** The live server (Dovecot) has MOVE, so the `copy_expunge` path in `TransferOp.run` (COPY, then STORE `\Deleted`, then UID EXPUNGE per batch) is only covered by the strategy unit test and by the live cleanup's use of `uidStoreFlags`/`uidExpunge`. Check that a STORE or EXPUNGE failure sets `copied_not_removed` and that the reported count stays a prefix of `matched`.
2. **A malicious or broken COPYUID** (`1:4294967295`, `*`, mismatched lengths) must not allocate without bound or produce a wrong map. This is pinned by the `organize.zig` test "uidMap pairs COPYUID ranges and rejects malformed data". Also confirm that `tpi_uid_transfer` frees libetpan's sets on every path.
3. **Gmail semantics** (labels; `[Gmail]/All Mail`; moving into `[Gmail]/Trash`) are not exercised live yet. This is a manual check once XOAUTH2 works. Check that the descriptions state them and that protection uses LIST flags rather than English names, since Gmail localizes `[Gmail]/…` names.
4. **Partial failure in the middle of a batched move.** If batch 3 of 10 fails, the error must say how many were already moved, and the cache must forget exactly those UIDs. Check the `catch` block in `transfer`.
5. **Names that differ only by invisible characters, or by INBOX case.** `ctx.mailbox` resolves cleaned names to wire names, and `organize.find` matches INBOX case-insensitively. Check that a rename or delete cannot reach a different folder than the one the model named.

---

### Task 1: Folder-name validation

**Files:**
- Modify: `src/validate.zig`

**Interfaces:**
- Produces: `validate.mailboxName(name, delimiter: ?u8) Error!void`; `validate.mailbox_name_max = 512`; errors `MailboxNameEmpty`, `MailboxNameTooLong`, `MailboxNameInvalid`, `MailboxNameWildcard`, `MailboxNameDelimiter` with `validate.message` texts.

- [ ] **Step 1: Write the failing tests**

In `src/validate.zig`, replace everything from the line `const testing = std.testing;` to the end of the file with:

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

test "mailboxName accepts folder paths and rejects unsafe names" {
    try mailboxName("Receipts/2026", '/');
    try mailboxName("Projets/R\u{e9}sum\u{e9}s", '/');
    try mailboxName("Archive.2025", '.');
    try mailboxName("/odd", null); // no delimiter: no delimiter rules
    try testing.expectError(error.MailboxNameEmpty, mailboxName("", '/'));
    const long: [513]u8 = @splat('a');
    try testing.expectError(error.MailboxNameTooLong, mailboxName(&long, '/'));
    try mailboxName(long[0..512], '/');
    try testing.expectError(error.MailboxNameInvalid, mailboxName("bad\xff", '/'));
    try testing.expectError(error.MailboxNameInvalid, mailboxName("two\r\nlines", '/'));
    try testing.expectError(error.MailboxNameInvalid, mailboxName("tab\there", '/'));
    try testing.expectError(error.MailboxNameInvalid, mailboxName("nul\x00", '/'));
    try testing.expectError(error.MailboxNameWildcard, mailboxName("All*", '/'));
    try testing.expectError(error.MailboxNameWildcard, mailboxName("50%", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("/Receipts", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("Receipts/", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("A//B", '/'));
    try testing.expectError(error.MailboxNameDelimiter, mailboxName("A..B", '.'));
}

test "todo: criteria cannot end in an IMAP literal marker" {
    try testing.expectError(error.CriteriaEndsWithLiteral, criteria("SUBJECT {5}"));
    try testing.expectError(error.CriteriaEndsWithLiteral, criteria("SUBJECT {12+}  "));
    try criteria("SUBJECT \"{5}\" FROM x"); // braces elsewhere are fine
    try criteria("SUBJECT {x}");
}
```
- [ ] **Step 2: Run the tests and confirm they fail**

Run: `zig build test --summary all`
Expected: compilation fails (the code under test does not exist yet).

- [ ] **Step 3: Implement**

In `src/validate.zig`, replace everything **above** the line `const testing = std.testing;` with:

```zig
//! Argument validation. `criteria` is sent to the server verbatim, so these
//! checks are the only barrier against smuggling a second IMAP command (which
//! would also bypass read-only accounts).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Error = error{
    CriteriaHasControlChars,
    CriteriaEndsWithLiteral,
    EmptyUids,
    InvalidUid,
    EmptyKeywords,
    InvalidKeyword,
    InvalidField,
    MailboxHasNul,
    MailboxNameEmpty,
    MailboxNameTooLong,
    MailboxNameInvalid,
    MailboxNameWildcard,
    MailboxNameDelimiter,
} || Allocator.Error;

pub fn message(err: Error) []const u8 {
    return switch (err) {
        error.CriteriaHasControlChars => "criteria must not contain CR, LF, or NUL",
        error.CriteriaEndsWithLiteral => "criteria must not end with an IMAP literal marker like {5}",
        error.EmptyUids => "uids must be a non-empty array",
        error.InvalidUid => "each uid must be a decimal string between 1 and 4294967295",
        error.EmptyKeywords => "keywords must be a non-empty array",
        error.InvalidKeyword => "each keyword must be a system flag (\\Seen, \\Answered, \\Flagged, \\Deleted, \\Draft) or an IMAP atom",
        error.InvalidField => "field must be a header name (printable ASCII, no ':' or space)",
        error.MailboxHasNul => "mailbox name must not contain NUL",
        error.MailboxNameEmpty => "mailbox name must not be empty",
        error.MailboxNameTooLong => "mailbox name must be at most 512 bytes",
        error.MailboxNameInvalid => "mailbox name must be valid UTF-8 without control characters",
        error.MailboxNameWildcard => "mailbox name must not contain * or %",
        error.MailboxNameDelimiter => "mailbox name must not start or end with the hierarchy delimiter or contain it twice in a row",
        error.OutOfMemory => "out of memory",
    };
}

pub fn criteria(s: []const u8) Error!void {
    if (std.mem.findAny(u8, s, "\r\n\x00") != null) return error.CriteriaHasControlChars;
    // `{N}` / `{N+}` at the very end would announce an IMAP literal; today
    // libetpan's trailing space defuses it, but do not rely on that.
    const t = std.mem.trimEnd(u8, s, " \t");
    if (t.len > 0 and t[t.len - 1] == '}') {
        if (std.mem.findScalarLast(u8, t, '{')) |open| {
            var inner = t[open + 1 .. t.len - 1];
            if (inner.len > 0 and inner[inner.len - 1] == '+') inner = inner[0 .. inner.len - 1];
            if (inner.len > 0) {
                for (inner) |ch| {
                    if (!std.ascii.isDigit(ch)) break;
                } else return error.CriteriaEndsWithLiteral;
            }
        }
    }
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

pub const mailbox_name_max = 512;

/// A folder name to create or rename to (ADR 0021), in UTF-8 before
/// modified UTF-7 encoding. `delimiter` is the account's hierarchy delimiter
/// (null when the server has none).
pub fn mailboxName(s: []const u8, delimiter: ?u8) Error!void {
    if (s.len == 0) return error.MailboxNameEmpty;
    if (s.len > mailbox_name_max) return error.MailboxNameTooLong;
    if (!std.unicode.utf8ValidateSlice(s)) return error.MailboxNameInvalid;
    for (s) |c| if (c < 0x20 or c == 0x7f) return error.MailboxNameInvalid;
    if (std.mem.findAny(u8, s, "*%") != null) return error.MailboxNameWildcard;
    const d = delimiter orelse return;
    if (s[0] == d or s[s.len - 1] == d) return error.MailboxNameDelimiter;
    if (std.mem.find(u8, s, &.{ d, d }) != null) return error.MailboxNameDelimiter;
}
```
- [ ] **Step 4: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `166/166 tests passed`.

- [ ] **Step 5: Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is ready and suggest the message: `feat(organize): validate folder names for create and rename`

---

### Task 2: Mailbox and move/copy commands in the C shim

**Files:**
- Modify: `src/c/tpi.h`, `src/c/session.c`, `src/imap/c.zig`, `src/imap/session.zig`

**Interfaces:**
- Produces: C `tpi_create`, `tpi_rename`, `tpi_delete`, `tpi_subscribe`, `tpi_unsubscribe`, `tpi_capabilities` (`TPI_CAP_MOVE`, `TPI_CAP_UIDPLUS`), `tpi_uid_transfer` + `tpi_copyuid` + `tpi_copyuid_free`, `tpi_uid_expunge`; Zig `imap.Caps{ move, uidplus }`, `imap.CopyUid{ uidvalidity, src: []const [2]u32, dst: []const [2]u32 }`, `Session.create/rename/delete/subscribe/unsubscribe`, `Session.capabilities() Error!Caps`, `Session.uidTransfer(arena, uids, mailbox, move: bool) Error!?CopyUid`, `Session.uidExpunge(uids) Error!void`.
- Note: these need a live server; they are exercised by Task 3's types, Task 5's tools and Task 6's live checks. No unit test can fail first here, so the step is "compiles and the suite stays green".

- [ ] **Step 1: Write `src/c/tpi.h`**

Replace (or create) the whole file:

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
  TPI_ERR_TLS = 7,      /* TLS handshake failed, e.g. untrusted certificate */
};

typedef struct tpi_session tpi_session;

tpi_session *tpi_new(void);
void tpi_free(tpi_session *s);

/* Implicit TLS connect. The server certificate chain is verified against the
 * PEM bundle ca_file and SNI is set to host; a failure returns TPI_ERR_TLS.
 * The certificate's host name is NOT checked here: the caller must check it
 * (tpi_peer_certificate) before sending credentials. timeout_sec applies to
 * every network operation. */
int tpi_connect(tpi_session *s, const char *host, uint16_t port, long timeout_sec,
                const char *ca_file);

/* DER encoding of the connected server's certificate. Returns its length, or
 * -1 if unavailable. Release *der with tpi_buf_free. */
long tpi_peer_certificate(tpi_session *s, char **der);
int tpi_login(tpi_session *s, const char *user, const char *password);
/* SASL XOAUTH2 with a bearer access token (ADR 0020). */
int tpi_oauth2_login(tpi_session *s, const char *user, const char *access_token);
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

/* Mailbox management (ADR 0021). Names are wire (modified UTF-7), validated. */
int tpi_create(tpi_session *s, const char *mailbox);
int tpi_rename(tpi_session *s, const char *from, const char *to);
int tpi_delete(tpi_session *s, const char *mailbox);
int tpi_subscribe(tpi_session *s, const char *mailbox);
int tpi_unsubscribe(tpi_session *s, const char *mailbox);

enum {
  TPI_CAP_MOVE = 1,    /* RFC 6851 */
  TPI_CAP_UIDPLUS = 2, /* RFC 4315 */
};

/* Bit mask of TPI_CAP_* from a CAPABILITY command, sent once per session. */
int tpi_capabilities(tpi_session *s, int *caps);

/* COPYUID response code (UIDPLUS). Ranges are (first, last) pairs, so each
 * length is twice the number of ranges; a last of 0 stands for "*".
 * uidvalidity is 0 and both arrays NULL when the server sent none. */
typedef struct {
  uint32_t uidvalidity;
  uint32_t *src;
  size_t src_len;
  uint32_t *dst;
  size_t dst_len;
} tpi_copyuid;

/* UID MOVE (move != 0) or UID COPY of uids from the selected mailbox to
 * mailbox. *out is filled on success; release it with tpi_copyuid_free. */
int tpi_uid_transfer(tpi_session *s, const uint32_t *uids, size_t uid_count,
                     const char *mailbox, int move, tpi_copyuid *out);
void tpi_copyuid_free(tpi_copyuid *c);

/* UID EXPUNGE (UIDPLUS): expunges only these UIDs, if flagged \Deleted. */
int tpi_uid_expunge(tpi_session *s, const uint32_t *uids, size_t uid_count);

/* MIME: concatenate every non-attachment text/<subtype> part of a full
 * RFC 822 message, transfer-decoded and converted to UTF-8 where possible.
 * *parts_found counts the matching parts (so "no part" and "empty part" can
 * be told apart).
 * If the top-level type is multipart/encrypted, *encrypted_protocol is set to
 * a malloc'd copy of its protocol parameter ("" if absent) and *out is NULL.
 * Release *out and *encrypted_protocol with tpi_buf_free. */
int tpi_extract_text(const char *msg, size_t len, const char *subtype,
                     char **out, size_t *out_len, size_t *parts_found,
                     char **encrypted_protocol);
void tpi_buf_free(char *buf);

/* RFC 2047: decode encoded-words in a header value to UTF-8 (unencoded text
 * is taken as UTF-8). Release *out with tpi_buf_free. */
int tpi_decode_header_value(const char *raw, size_t len, char **out, size_t *out_len);

/* BODYSTRUCTURE leaf parts for list_attachments. Strings are malloc'd;
 * params/disp_params are "name\x1fvalue" pairs joined by \x1e. */
typedef struct {
  uint32_t uid;
  uint32_t size;      /* encoded size in bytes */
  int base64;         /* 1 if Content-Transfer-Encoding is base64 */
  char *content_type; /* "type/subtype" as sent */
  char *disposition;  /* "" when absent */
  char *params;       /* content-type parameters */
  char *disp_params;  /* disposition parameters */
} tpi_part;

/* UID FETCH (UID BODYSTRUCTURE); forwarded messages are single leaves. */
int tpi_uid_bodystructure(tpi_session *s, const uint32_t *uids, size_t uid_count,
                          tpi_part **out, size_t *count);
void tpi_parts_free(tpi_part *items, size_t count);

/* POSIX extended regex, case-insensitive, match/no-match only (ADR 0017). */
typedef struct tpi_regex tpi_regex;

/* Returns NULL on failure with a message in err (always NUL-terminated when
 * errlen > 0). */
tpi_regex *tpi_regex_compile(const char *pattern, char *err, size_t errlen);
/* 1 if `text` (NUL-terminated) contains a match, else 0. */
int tpi_regex_match(const tpi_regex *r, const char *text);
void tpi_regex_free(tpi_regex *r);

#endif
```
- [ ] **Step 2: Write `src/c/session.c`**

Replace (or create) the whole file:

```c
/* IMAP session half of the tpi shim. See tpi.h for the contract. */
#include "tpi.h"

#include <libetpan/libetpan.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct tpi_session {
  mailimap *imap;
  int caps;       /* TPI_CAP_* mask */
  int caps_known; /* caps fetched on this connection */
};

int tpi_map_error(int r);
static int map_error(int r) { return tpi_map_error(r); }

/* Internal: shared with attach.c. */
struct mailimap *tpi_imap(tpi_session *s) { return s->imap; }

int tpi_map_error(int r) {
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

struct tls_options {
  const char *host;
  const char *ca_file;
  int ca_failed;
};

/* Runs before the handshake: SNI plus chain verification (SSL_VERIFY_PEER). */
static void tls_setup(struct mailstream_ssl_context *ctx, void *data) {
  struct tls_options *o = data;
  mailstream_ssl_set_server_name(ctx, (char *)o->host);
  if (mailstream_ssl_set_server_certicate(ctx, (char *)o->ca_file, NULL) < 0)
    o->ca_failed = 1;
}

int tpi_connect(tpi_session *s, const char *host, uint16_t port, long timeout_sec,
                const char *ca_file) {
  mailimap_set_timeout(s->imap, (time_t)timeout_sec);
  struct tls_options opts = {host, ca_file, 0};
  int r = mailimap_ssl_connect_with_callback(s->imap, host, port, tls_setup, &opts);
  if (opts.ca_failed)
    return TPI_ERR_TLS;
  if (r == MAILIMAP_NO_ERROR_AUTHENTICATED || r == MAILIMAP_NO_ERROR_NON_AUTHENTICATED)
    return TPI_OK;
  switch (r) {
  case MAILIMAP_ERROR_MEMORY: return TPI_ERR_MEMORY;
  case MAILIMAP_ERROR_SSL: return TPI_ERR_TLS;
  default: return TPI_ERR_CONNECT;
  }
}

/* Uses the certificate-chain API: mailstream_ssl_get_certificate (libetpan
 * 1.10.1) returns a pointer advanced past the end of its buffer by i2d_X509,
 * so it can be neither read nor freed. Element 0 is the server's own cert. */
long tpi_peer_certificate(tpi_session *s, char **der) {
  *der = NULL;
  carray *chain = mailstream_get_certificate_chain(s->imap->imap_stream);
  if (chain == NULL)
    return -1;
  long n = -1;
  if (carray_count(chain) > 0) {
    MMAPString *leaf = carray_get(chain, 0);
    char *copy = malloc(leaf->len > 0 ? leaf->len : 1);
    if (copy != NULL) {
      memcpy(copy, leaf->str, leaf->len);
      *der = copy;
      n = (long)leaf->len;
    }
  }
  mailstream_certificate_chain_free(chain);
  return n;
}

int tpi_login(tpi_session *s, const char *user, const char *password) {
  return map_error(mailimap_login(s->imap, user, password));
}

int tpi_oauth2_login(tpi_session *s, const char *user, const char *access_token) {
  return map_error(mailimap_oauth2_authenticate(s->imap, user, access_token));
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
  /* libetpan returns OK with st == NULL when the server's tagged OK carried
   * no untagged STATUS data. */
  if (st == NULL)
    return TPI_ERR_PARSE;
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

int tpi_create(tpi_session *s, const char *mailbox) {
  return map_error(mailimap_create(s->imap, mailbox));
}

int tpi_rename(tpi_session *s, const char *from, const char *to) {
  return map_error(mailimap_rename(s->imap, from, to));
}

int tpi_delete(tpi_session *s, const char *mailbox) {
  return map_error(mailimap_delete(s->imap, mailbox));
}

int tpi_subscribe(tpi_session *s, const char *mailbox) {
  return map_error(mailimap_subscribe(s->imap, mailbox));
}

int tpi_unsubscribe(tpi_session *s, const char *mailbox) {
  return map_error(mailimap_unsubscribe(s->imap, mailbox));
}

int tpi_capabilities(tpi_session *s, int *caps) {
  *caps = 0;
  if (!s->caps_known) {
    /* The result is a copy; libetpan keeps its own for mailimap_has_extension. */
    struct mailimap_capability_data *data = NULL;
    int r = mailimap_capability(s->imap, &data);
    if (r != MAILIMAP_NO_ERROR)
      return map_error(r);
    mailimap_capability_data_free(data);
    s->caps = (mailimap_has_extension(s->imap, "MOVE") ? TPI_CAP_MOVE : 0) |
              (mailimap_has_extension(s->imap, "UIDPLUS") ? TPI_CAP_UIDPLUS : 0);
    s->caps_known = 1;
  }
  *caps = s->caps;
  return TPI_OK;
}

/* Flattens a set into (first, last) pairs. Returns 0, or -1 on memory. */
static int set_ranges(struct mailimap_set *set, uint32_t **out, size_t *len) {
  *out = NULL;
  *len = 0;
  if (set == NULL || set->set_list == NULL || clist_count(set->set_list) == 0)
    return 0;
  uint32_t *v = malloc(sizeof(uint32_t) * 2 * (size_t)clist_count(set->set_list));
  if (v == NULL)
    return -1;
  size_t n = 0;
  for (clistiter *it = clist_begin(set->set_list); it != NULL; it = clist_next(it)) {
    struct mailimap_set_item *item = clist_content(it);
    v[n++] = item->set_first;
    v[n++] = item->set_last;
  }
  *out = v;
  *len = n;
  return 0;
}

int tpi_uid_transfer(tpi_session *s, const uint32_t *uids, size_t uid_count,
                     const char *mailbox, int move, tpi_copyuid *out) {
  memset(out, 0, sizeof(*out));
  struct mailimap_set *set = uid_set(uids, uid_count);
  if (set == NULL)
    return TPI_ERR_MEMORY;
  uint32_t uidvalidity = 0;
  struct mailimap_set *src = NULL, *dst = NULL;
  /* The uidplus variants send plain UID MOVE / UID COPY and only read a
   * COPYUID code if the server sent one, so they suit every server. */
  int r = move ? mailimap_uidplus_uid_move(s->imap, set, mailbox, &uidvalidity, &src, &dst)
               : mailimap_uidplus_uid_copy(s->imap, set, mailbox, &uidvalidity, &src, &dst);
  mailimap_set_free(set);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);
  int rc = TPI_OK;
  if (uidvalidity != 0 && src != NULL && dst != NULL) {
    if (set_ranges(src, &out->src, &out->src_len) != 0 ||
        set_ranges(dst, &out->dst, &out->dst_len) != 0) {
      tpi_copyuid_free(out);
      rc = TPI_ERR_MEMORY;
    } else {
      out->uidvalidity = uidvalidity;
    }
  }
  if (src != NULL)
    mailimap_set_free(src);
  if (dst != NULL)
    mailimap_set_free(dst);
  return rc;
}

void tpi_copyuid_free(tpi_copyuid *c) {
  free(c->src);
  free(c->dst);
  memset(c, 0, sizeof(*c));
}

int tpi_uid_expunge(tpi_session *s, const uint32_t *uids, size_t uid_count) {
  struct mailimap_set *set = uid_set(uids, uid_count);
  if (set == NULL)
    return TPI_ERR_MEMORY;
  int r = mailimap_uid_expunge(s->imap, set);
  mailimap_set_free(set);
  return map_error(r);
}
```
- [ ] **Step 3: Write `src/imap/c.zig`**

Replace (or create) the whole file:

```zig
//! Hand-written externs for src/c/tpi.h. Keep in sync with that header.

pub const OK: c_int = 0;
pub const ERR_CONNECT: c_int = 1;
pub const ERR_STREAM: c_int = 2;
pub const ERR_SERVER: c_int = 3;
pub const ERR_PARSE: c_int = 4;
pub const ERR_MEMORY: c_int = 5;
pub const ERR_OTHER: c_int = 6;
pub const ERR_TLS: c_int = 7;

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
pub extern fn tpi_connect(s: *Session, host: [*:0]const u8, port: u16, timeout_sec: c_long, ca_file: [*:0]const u8) c_int;
pub extern fn tpi_peer_certificate(s: *Session, der: *?[*]u8) c_long;
pub extern fn tpi_login(s: *Session, user: [*:0]const u8, password: [*:0]const u8) c_int;
pub extern fn tpi_oauth2_login(s: *Session, user: [*:0]const u8, access_token: [*:0]const u8) c_int;
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

pub extern fn tpi_create(s: *Session, mailbox: [*:0]const u8) c_int;
pub extern fn tpi_rename(s: *Session, from: [*:0]const u8, to: [*:0]const u8) c_int;
pub extern fn tpi_delete(s: *Session, mailbox: [*:0]const u8) c_int;
pub extern fn tpi_subscribe(s: *Session, mailbox: [*:0]const u8) c_int;
pub extern fn tpi_unsubscribe(s: *Session, mailbox: [*:0]const u8) c_int;

pub const CAP_MOVE: c_int = 1;
pub const CAP_UIDPLUS: c_int = 2;
pub extern fn tpi_capabilities(s: *Session, caps: *c_int) c_int;

pub const CopyUid = extern struct {
    uidvalidity: u32,
    src: ?[*]u32,
    src_len: usize,
    dst: ?[*]u32,
    dst_len: usize,
};
pub extern fn tpi_uid_transfer(s: *Session, uids: [*]const u32, uid_count: usize, mailbox: [*:0]const u8, move: c_int, out: *CopyUid) c_int;
pub extern fn tpi_copyuid_free(c: *CopyUid) void;
pub extern fn tpi_uid_expunge(s: *Session, uids: [*]const u32, uid_count: usize) c_int;

pub extern fn tpi_extract_text(msg: [*]const u8, len: usize, subtype: [*:0]const u8, out: *?[*]u8, out_len: *usize, parts_found: *usize, encrypted_protocol: *?[*:0]u8) c_int;
pub extern fn tpi_buf_free(buf: ?[*]u8) void;

pub extern fn tpi_decode_header_value(raw: [*]const u8, len: usize, out: *?[*]u8, out_len: *usize) c_int;

pub const Part = extern struct {
    uid: u32,
    size: u32,
    base64: c_int,
    content_type: [*:0]u8,
    disposition: [*:0]u8,
    params: [*:0]u8,
    disp_params: [*:0]u8,
};
pub extern fn tpi_uid_bodystructure(s: *Session, uids: [*]const u32, uid_count: usize, out: *?[*]Part, count: *usize) c_int;
pub extern fn tpi_parts_free(items: ?[*]Part, count: usize) void;

pub const Regex = opaque {};
pub extern fn tpi_regex_compile(pattern: [*:0]const u8, err: [*]u8, errlen: usize) ?*Regex;
pub extern fn tpi_regex_match(r: *const Regex, text: [*:0]const u8) c_int;
pub extern fn tpi_regex_free(r: ?*Regex) void;
```
- [ ] **Step 4: Implement**

In `src/imap/session.zig`, replace everything **above** the line `const testing = std.testing;` with:

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
    /// TLS handshake failed: certificate chain not trusted by the CA bundle.
    TlsFailed,
    /// The server certificate is not valid for the host we connected to.
    HostnameMismatch,
} || Allocator.Error;

fn check(rc: c_int) Error!void {
    return switch (rc) {
        c.OK => {},
        c.ERR_CONNECT => error.ConnectFailed,
        c.ERR_STREAM => error.ConnectionLost,
        c.ERR_SERVER => error.ServerRejected,
        c.ERR_PARSE => error.ProtocolError,
        c.ERR_MEMORY => error.OutOfMemory,
        c.ERR_TLS => error.TlsFailed,
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

pub const BodyPart = struct {
    uid: u32,
    size: u32,
    base64: bool,
    content_type: []const u8,
    disposition: []const u8,
    params: []const u8,
    disp_params: []const u8,
};

pub const Fetched = struct {
    uid: u32,
    size: u32,
    data: ?[]const u8,
    flags: ?[]const []const u8,
};

/// Server extensions the organization tools depend on (ADR 0021).
pub const Caps = struct {
    move: bool = false,
    uidplus: bool = false,
};

/// COPYUID response code: UID ranges as (first, last); a last of 0 is "*".
pub const CopyUid = struct {
    uidvalidity: u32,
    src: []const [2]u32,
    dst: []const [2]u32,
};

pub const Session = struct {
    handle: *c.Session,

    /// Implicit-TLS connect: chain verified against `ca_file`, SNI set, and
    /// the certificate's host name checked before any credential is sent.
    pub fn connect(host: [:0]const u8, port: u16, timeout_sec: c_long, ca_file: [:0]const u8) Error!Session {
        const h = c.tpi_new() orelse return error.OutOfMemory;
        errdefer c.tpi_free(h);
        try check(c.tpi_connect(h, host, port, timeout_sec, ca_file));
        var der: ?[*]u8 = null;
        const n = c.tpi_peer_certificate(h, &der);
        defer c.tpi_buf_free(der);
        const cert = der orelse return error.HostnameMismatch;
        if (n < 0) return error.HostnameMismatch;
        try checkHostName(cert[0..@intCast(n)], host);
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

    pub fn oauth2Login(self: *Session, user: [:0]const u8, access_token: [:0]const u8) Error!void {
        try check(c.tpi_oauth2_login(self.handle, user, access_token));
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

    /// Leaf MIME parts per UID from BODYSTRUCTURE (no content downloaded).
    pub fn uidBodyParts(self: *Session, arena: Allocator, uids: []const u32) Error![]BodyPart {
        var ptr: ?[*]c.Part = null;
        var n: usize = 0;
        try check(c.tpi_uid_bodystructure(self.handle, uids.ptr, uids.len, &ptr, &n));
        defer c.tpi_parts_free(ptr, n);
        const items = (ptr orelse return &.{})[0..n];
        const out = try arena.alloc(BodyPart, n);
        for (items, out) |src, *dst| dst.* = .{
            .uid = src.uid,
            .size = src.size,
            .base64 = src.base64 != 0,
            .content_type = try arena.dupe(u8, std.mem.sliceTo(src.content_type, 0)),
            .disposition = try arena.dupe(u8, std.mem.sliceTo(src.disposition, 0)),
            .params = try arena.dupe(u8, std.mem.sliceTo(src.params, 0)),
            .disp_params = try arena.dupe(u8, std.mem.sliceTo(src.disp_params, 0)),
        };
        return out;
    }

    pub fn append(self: *Session, mailbox: [:0]const u8, data: []const u8) Error!void {
        try check(c.tpi_append(self.handle, mailbox, data.ptr, data.len));
    }

    pub fn create(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_create(self.handle, mailbox));
    }

    pub fn rename(self: *Session, from: [:0]const u8, to: [:0]const u8) Error!void {
        try check(c.tpi_rename(self.handle, from, to));
    }

    pub fn delete(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_delete(self.handle, mailbox));
    }

    pub fn subscribe(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_subscribe(self.handle, mailbox));
    }

    pub fn unsubscribe(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_unsubscribe(self.handle, mailbox));
    }

    /// MOVE / UIDPLUS support (one CAPABILITY command per connection).
    pub fn capabilities(self: *Session) Error!Caps {
        var mask: c_int = 0;
        try check(c.tpi_capabilities(self.handle, &mask));
        return .{ .move = mask & c.CAP_MOVE != 0, .uidplus = mask & c.CAP_UIDPLUS != 0 };
    }

    /// UID MOVE (`move`) or UID COPY from the selected mailbox. Returns the
    /// server's COPYUID data, or null if it sent none.
    pub fn uidTransfer(self: *Session, arena: Allocator, uids: []const u32, mailbox: [:0]const u8, move: bool) Error!?CopyUid {
        var out: c.CopyUid = undefined;
        try check(c.tpi_uid_transfer(self.handle, uids.ptr, uids.len, mailbox, @intFromBool(move), &out));
        defer c.tpi_copyuid_free(&out);
        if (out.uidvalidity == 0) return null;
        return .{
            .uidvalidity = out.uidvalidity,
            .src = try pairs(arena, out.src, out.src_len),
            .dst = try pairs(arena, out.dst, out.dst_len),
        };
    }

    /// UID EXPUNGE (UIDPLUS) of exactly these UIDs.
    pub fn uidExpunge(self: *Session, uids: []const u32) Error!void {
        try check(c.tpi_uid_expunge(self.handle, uids.ptr, uids.len));
    }
};

/// Checks that the DER certificate `der` is valid for `host` (SAN DNS/IP
/// entries, else CN), using Zig's X.509 parser.
/// Precondition: `der` is a certificate OpenSSL already verified against the
/// CA bundle (re-encoded by i2d_X509), so it is well-formed; std's parser may
/// panic on arbitrary malformed bytes.
pub fn checkHostName(der: []const u8, host: []const u8) error{HostnameMismatch}!void {
    const cert: std.crypto.Certificate = .{ .buffer = der, .index = 0 };
    const parsed = cert.parse() catch return error.HostnameMismatch;
    parsed.verifyHostName(host) catch return error.HostnameMismatch;
}

fn pairs(arena: Allocator, ptr: ?[*]const u32, len: usize) Allocator.Error![]const [2]u32 {
    const p = ptr orelse return &.{};
    const out = try arena.alloc([2]u32, len / 2);
    for (out, 0..) |*o, i| o.* = .{ p[2 * i], p[2 * i + 1] };
    return out;
}

fn splitFlags(arena: Allocator, s: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, s, ' ');
    while (it.next()) |f| try out.append(arena, try arena.dupe(u8, f));
    return out.toOwnedSlice(arena);
}

pub const Extracted = union(enum) {
    text: struct {
        bytes: []const u8, // not yet UTF-8 sanitized
        parts: usize, // matching parts found (0 = none of that subtype)
    },
    encrypted: []const u8, // protocol parameter
};

/// MIME body extraction (no network). `subtype` is "plain" or "html".
pub fn extractText(arena: Allocator, message: []const u8, subtype: [:0]const u8) Error!Extracted {
    var out: ?[*]u8 = null;
    var out_len: usize = 0;
    var parts: usize = 0;
    var proto: ?[*:0]u8 = null;
    try check(c.tpi_extract_text(message.ptr, message.len, subtype, &out, &out_len, &parts, &proto));
    defer c.tpi_buf_free(out);
    defer c.tpi_buf_free(if (proto) |p| p else null);
    if (proto) |p| return .{ .encrypted = try arena.dupe(u8, std.mem.sliceTo(p, 0)) };
    const o = out orelse return .{ .text = .{ .bytes = "", .parts = parts } };
    return .{ .text = .{ .bytes = try arena.dupe(u8, o[0..out_len]), .parts = parts } };
}

/// RFC 2047-decodes a header value to UTF-8 for matching (ADR 0017). Falls
/// back to the raw value if libetpan cannot parse it. Result is in `arena`.
pub fn decodeHeaderValue(arena: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    var out: ?[*]u8 = null;
    var out_len: usize = 0;
    if (c.tpi_decode_header_value(raw.ptr, raw.len, &out, &out_len) != c.OK) return raw;
    defer c.tpi_buf_free(out);
    const o = out orelse return raw;
    // An encoded NUL truncates libetpan's C string; never turn a non-empty
    // value into an empty one (filters would then see nothing).
    if (out_len == 0 and std.mem.trim(u8, raw, " \t").len > 0) return raw;
    return arena.dupe(u8, o[0..out_len]);
}
```
- [ ] **Step 5: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `166/166 tests passed`.

- [ ] **Step 6: Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is ready and suggest the message: `feat(organize): CREATE/RENAME/DELETE/SUBSCRIBE, MOVE/COPY with COPYUID, UID EXPUNGE in the shim`

---

### Task 3: Organization rules

**Files:**
- Create: `src/organize.zig`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Consumes: `imap.Mailbox`, `imap.Caps`, `imap.CopyUid` (Task 2), `mutf7.decode`.
- Produces: `organize.max_messages = 5000`, `batch_size = 500`, `dry_run_preview = 100`, `special_use`, `trash_note`, `junk_note`; `specialUse(flags) ?[]const u8`; `find(boxes, wire) ?imap.Mailbox`; `selectable(box) bool`; `delimiterOf(boxes, wire) ?u8`; `isBelow(name, parent, delimiter) bool`; `protectedReason(arena, boxes, wire) !?[]const u8`; `targetReason(arena, target, target_wire, source_wire: ?[]const u8, delimiter) !?[]const u8`; `destinationNote(?imap.Mailbox) ?[]const u8`; `MoveStrategy = enum { move, copy_expunge, unsupported }`; `moveStrategy(imap.Caps) MoveStrategy`; `batchCount(n) usize`; `batch(uids, i) []const u32`; `selectionProblem(has_uids, has_criteria) ?[]const u8`; `UidPair{ from, to }`; `uidMap(arena, ?imap.CopyUid) !?[]UidPair`.

- [ ] **Step 1: Write the failing tests**

Create `src/organize.zig` containing only its tests:

```zig
const testing = std.testing;

fn mbox(name: []const u8, flags: []const []const u8) imap.Mailbox {
    return .{ .name = name, .delimiter = '/', .flags = flags };
}

const gmail_boxes = [_]imap.Mailbox{
    mbox("INBOX", &.{"\\HasNoChildren"}),
    mbox("Receipts", &.{"\\HasChildren"}),
    mbox("Receipts/2026", &.{"\\HasNoChildren"}),
    mbox("[Gmail]", &.{ "\\HasChildren", "\\Noselect" }),
    mbox("[Gmail]/All Mail", &.{ "\\All", "\\HasNoChildren" }),
    mbox("[Gmail]/Sent Mail", &.{ "\\HasNoChildren", "\\Sent" }),
    mbox("[Gmail]/Trash", &.{ "\\HasNoChildren", "\\Trash" }),
    mbox("[Gmail]/Spam", &.{ "\\HasNoChildren", "\\Junk" }),
    mbox("Old", &.{"\\HasChildren"}),
    mbox("Old/Drafts", &.{ "\\Drafts", "\\HasNoChildren" }),
    mbox("R&AOk-sum&AOk-s", &.{"\\HasNoChildren"}),
};

test "protectedReason: INBOX, special-use folders and their ancestors" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("\"inbox\" is protected and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "inbox")).?);
    try testing.expectEqualStrings("\"[Gmail]/Sent Mail\" is a special-use folder (\\Sent) and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "[Gmail]/Sent Mail")).?);
    for (special_use) |su| {
        const boxes = [_]imap.Mailbox{mbox("X", &.{su})};
        try testing.expect((try protectedReason(a, &boxes, "X")) != null);
    }
    try testing.expectEqualStrings("\"[Gmail]\" contains the special-use folder \"[Gmail]/All Mail\" (\\All) and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "[Gmail]")).?);
    try testing.expectEqualStrings("\"Old\" contains the special-use folder \"Old/Drafts\" (\\Drafts) and cannot be renamed or deleted", (try protectedReason(a, &gmail_boxes, "Old")).?);
    try testing.expect((try protectedReason(a, &gmail_boxes, "Receipts")) == null);
    try testing.expect((try protectedReason(a, &gmail_boxes, "Receipts/2026")) == null);
    try testing.expect((try protectedReason(a, &gmail_boxes, "R&AOk-sum&AOk-s")) == null);
    // "Ol" is a name prefix of "Old/Drafts" but not its ancestor.
    try testing.expect((try protectedReason(a, &gmail_boxes, "Ol")) == null);
}

test "targetReason: Gmail system trees, INBOX, renaming into itself" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("\"[Gmail]/Mine\" is inside Gmail's system folders; choose a name outside [Gmail]", (try targetReason(a, "[Gmail]/Mine", "[Gmail]/Mine", null, '/')).?);
    try testing.expect((try targetReason(a, "[gmail]", "[gmail]", null, '/')) != null);
    try testing.expect((try targetReason(a, "[Google Mail]/X", "[Google Mail]/X", null, '/')) != null);
    try testing.expect((try targetReason(a, "[Gmail]Notes", "[Gmail]Notes", null, '/')) == null);
    try testing.expectEqualStrings("\"Inbox\" is reserved for the inbox", (try targetReason(a, "Inbox", "Inbox", null, '/')).?);
    try testing.expectEqualStrings("new_name is the same as name", (try targetReason(a, "A", "A", "A", '/')).?);
    try testing.expectEqualStrings("cannot move \"A\" inside itself", (try targetReason(a, "A/B", "A/B", "A", '/')).?);
    try testing.expect((try targetReason(a, "AB", "AB", "A", '/')) == null);
    try testing.expect((try targetReason(a, "Archive/2025/X", "Archive/2025/X", "Projects/X", '/')) == null);
}

test "find, selectable, delimiterOf, destinationNote" {
    try testing.expectEqualStrings("INBOX", find(&gmail_boxes, "Inbox").?.name);
    try testing.expect(find(&gmail_boxes, "receipts") == null); // only INBOX is case-insensitive
    try testing.expect(!selectable(find(&gmail_boxes, "[Gmail]").?));
    try testing.expect(selectable(find(&gmail_boxes, "Receipts").?));
    try testing.expectEqual('/', delimiterOf(&gmail_boxes, "New/Folder").?);
    try testing.expect(delimiterOf(&.{}, "X") == null);
    try testing.expectEqualStrings(trash_note, destinationNote(find(&gmail_boxes, "[Gmail]/Trash")).?);
    try testing.expectEqualStrings(junk_note, destinationNote(find(&gmail_boxes, "[Gmail]/Spam")).?);
    try testing.expect(destinationNote(find(&gmail_boxes, "Receipts")) == null);
    try testing.expect(destinationNote(null) == null);
}

test "moveStrategy from capabilities" {
    try testing.expectEqual(.move, moveStrategy(.{ .move = true, .uidplus = true }));
    try testing.expectEqual(.move, moveStrategy(.{ .move = true }));
    try testing.expectEqual(.copy_expunge, moveStrategy(.{ .uidplus = true }));
    try testing.expectEqual(.unsupported, moveStrategy(.{}));
}

test "batches of at most 500 UIDs" {
    var uids: [5000]u32 = undefined;
    for (&uids, 1..) |*u, i| u.* = @intCast(i);
    try testing.expectEqual(1, batchCount(1));
    try testing.expectEqual(1, batchCount(500));
    try testing.expectEqual(2, batchCount(501));
    try testing.expectEqual(10, batchCount(5000));
    try testing.expectEqual(500, batch(&uids, 0).len);
    try testing.expectEqual(1, batch(uids[0..501], 1).len);
    try testing.expectEqual(501, batch(uids[0..501], 1)[0]);
    try testing.expectEqual(5000, batch(&uids, 9)[499]);
}

test "selectionProblem: exactly one of uids and criteria" {
    try testing.expect(selectionProblem(true, false) == null);
    try testing.expect(selectionProblem(false, true) == null);
    try testing.expectEqualStrings("pass either uids or criteria, not both", selectionProblem(true, true).?);
    try testing.expectEqualStrings("pass uids (from search) or criteria", selectionProblem(false, false).?);
}

test "uidMap pairs COPYUID ranges and rejects malformed data" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const m = (try uidMap(a, .{ .uidvalidity = 7, .src = &.{ .{ 101, 102 }, .{ 105, 105 } }, .dst = &.{.{ 7, 9 }} })).?;
    try testing.expectEqual(3, m.len);
    try testing.expectEqual(UidPair{ .from = 105, .to = 9 }, m[2]);
    const rev = (try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 3, 1 }}, .dst = &.{.{ 10, 12 }} })).?;
    try testing.expectEqual(UidPair{ .from = 1, .to = 10 }, rev[0]);
    try testing.expect((try uidMap(a, null)) == null);
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 1, 2 }}, .dst = &.{.{ 5, 5 }} })) == null); // lengths differ
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 1, 0 }}, .dst = &.{.{ 5, 0 }} })) == null); // "*"
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{.{ 1, 4294967295 }}, .dst = &.{.{ 1, 4294967295 }} })) == null); // unbounded
    try testing.expect((try uidMap(a, .{ .uidvalidity = 7, .src = &.{}, .dst = &.{} })) == null);
}
```
- [ ] **Step 2: Register the tests**

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("organize.zig");
```
- [ ] **Step 3: Run the tests and confirm they fail**

Run: `zig build test --summary all`
Expected: compilation fails (the code under test does not exist yet).

- [ ] **Step 4: Implement**

Insert at the very top of `src/organize.zig`, above the tests:

```zig
//! Mailbox organization rules (ADR 0021, spec §2-4): folder protection, move
//! strategy, batching, selection limits and COPYUID pairing. No I/O.

const std = @import("std");
const Allocator = std.mem.Allocator;
const imap = @import("imap/session.zig");
const mutf7 = @import("imap/mutf7.zig");

/// Most messages one move_messages/copy_messages call acts on.
pub const max_messages = 5000;
/// UIDs per MOVE/COPY/STORE/EXPUNGE command, keeping command lines short.
pub const batch_size = 500;
/// UIDs listed in a dry-run result.
pub const dry_run_preview = 100;

/// RFC 6154 special-use attributes, plus Gmail's \Important.
pub const special_use = [_][]const u8{ "\\All", "\\Archive", "\\Drafts", "\\Flagged", "\\Junk", "\\Sent", "\\Trash", "\\Important" };

const gmail_roots = [_][]const u8{ "[Gmail]", "[Google Mail]" };

pub const trash_note = "destination is the Trash folder; servers may purge it automatically (Gmail: after 30 days)";
pub const junk_note = "destination is the spam/junk folder; servers may purge it automatically (Gmail: after 30 days)";

/// The special-use attribute among `flags`, if any.
pub fn specialUse(flags: []const []const u8) ?[]const u8 {
    for (flags) |f| for (special_use) |su| if (std.ascii.eqlIgnoreCase(f, su)) return su;
    return null;
}

fn isInbox(wire: []const u8) bool {
    return std.ascii.eqlIgnoreCase(wire, "INBOX");
}

/// The mailbox with wire name `wire` (INBOX matched case-insensitively).
pub fn find(boxes: []const imap.Mailbox, wire: []const u8) ?imap.Mailbox {
    for (boxes) |b| {
        if (std.mem.eql(u8, b.name, wire)) return b;
        if (isInbox(wire) and isInbox(b.name)) return b;
    }
    return null;
}

/// False for \Noselect / \NonExistent mailboxes, which hold no messages.
pub fn selectable(box: imap.Mailbox) bool {
    for (box.flags) |f| {
        if (std.ascii.eqlIgnoreCase(f, "\\Noselect") or std.ascii.eqlIgnoreCase(f, "\\NonExistent")) return false;
    }
    return true;
}

/// Hierarchy delimiter for `wire`: its own, else the account's first.
pub fn delimiterOf(boxes: []const imap.Mailbox, wire: []const u8) ?u8 {
    if (find(boxes, wire)) |b| if (b.delimiter) |d| return d;
    for (boxes) |b| if (b.delimiter) |d| return d;
    return null;
}

/// True if `name` lies strictly below `parent` in the hierarchy.
pub fn isBelow(name: []const u8, parent: []const u8, delimiter: ?u8) bool {
    const d = delimiter orelse return false;
    return name.len > parent.len + 1 and std.mem.startsWith(u8, name, parent) and name[parent.len] == d;
}

fn display(arena: Allocator, wire: []const u8) Allocator.Error![]const u8 {
    return mutf7.decode(arena, wire) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => wire,
    };
}

/// Why the folder `wire` must not be renamed or deleted, or null (spec §3.2).
pub fn protectedReason(arena: Allocator, boxes: []const imap.Mailbox, wire: []const u8) Allocator.Error!?[]const u8 {
    const name = try display(arena, wire);
    if (isInbox(wire)) return try arena.print("\"{s}\" is protected and cannot be renamed or deleted", .{name});
    if (find(boxes, wire)) |b| if (specialUse(b.flags)) |su|
        return try arena.print("\"{s}\" is a special-use folder ({s}) and cannot be renamed or deleted", .{ name, su });
    const d = delimiterOf(boxes, wire);
    for (boxes) |b| {
        if (!isBelow(b.name, wire, d)) continue;
        const su = specialUse(b.flags) orelse continue;
        return try arena.print("\"{s}\" contains the special-use folder \"{s}\" ({s}) and cannot be renamed or deleted", .{ name, try display(arena, b.name), su });
    }
    return null;
}

/// Why `target` (UTF-8; `target_wire` encoded) cannot be created or be a
/// rename target, or null. `source_wire` is the folder being renamed.
pub fn targetReason(arena: Allocator, target: []const u8, target_wire: []const u8, source_wire: ?[]const u8, delimiter: ?u8) Allocator.Error!?[]const u8 {
    for (gmail_roots) |root| {
        if (!std.ascii.startsWithIgnoreCase(target, root)) continue;
        const rest = target[root.len..];
        if (rest.len == 0 or (delimiter != null and rest[0] == delimiter.?))
            return try arena.print("\"{s}\" is inside Gmail's system folders; choose a name outside {s}", .{ target, root });
    }
    if (isInbox(target_wire)) return try arena.print("\"{s}\" is reserved for the inbox", .{target});
    if (source_wire) |src| {
        if (std.mem.eql(u8, src, target_wire)) return try arena.dupe(u8, "new_name is the same as name");
        if (isBelow(target_wire, src, delimiter))
            return try arena.print("cannot move \"{s}\" inside itself", .{try display(arena, src)});
    }
    return null;
}

/// Note for a move/copy into Trash or Junk (spec §2.2).
pub fn destinationNote(box: ?imap.Mailbox) ?[]const u8 {
    const b = box orelse return null;
    for (b.flags) |f| {
        if (std.ascii.eqlIgnoreCase(f, "\\Trash")) return trash_note;
        if (std.ascii.eqlIgnoreCase(f, "\\Junk")) return junk_note;
    }
    return null;
}

pub const MoveStrategy = enum {
    /// UID MOVE.
    move,
    /// UID COPY, STORE +FLAGS (\Deleted), UID EXPUNGE of those UIDs.
    copy_expunge,
    /// Neither MOVE nor UIDPLUS: a plain EXPUNGE could purge unrelated
    /// messages, so refuse.
    unsupported,
};

pub fn moveStrategy(caps: imap.Caps) MoveStrategy {
    if (caps.move) return .move;
    if (caps.uidplus) return .copy_expunge;
    return .unsupported;
}

pub fn batchCount(n: usize) usize {
    return (n + batch_size - 1) / batch_size;
}

/// The `i`-th batch of at most `batch_size` UIDs.
pub fn batch(uids: []const u32, i: usize) []const u32 {
    const start = i * batch_size;
    return uids[start..@min(uids.len, start + batch_size)];
}

/// Problem with the uids/criteria combination, or null.
pub fn selectionProblem(has_uids: bool, has_criteria: bool) ?[]const u8 {
    if (has_uids and has_criteria) return "pass either uids or criteria, not both";
    if (!has_uids and !has_criteria) return "pass uids (from search) or criteria";
    return null;
}

pub const UidPair = struct { from: u32, to: u32 };

/// Expanded UIDs, ascending within each range; null for a "*" end or more
/// than `max` UIDs (a server cannot make us allocate without bound).
fn expand(arena: Allocator, ranges: []const [2]u32, max: usize) Allocator.Error!?[]u32 {
    var total: usize = 0;
    for (ranges) |r| {
        if (r[0] == 0 or r[1] == 0) return null;
        total += @as(usize, @max(r[0], r[1]) - @min(r[0], r[1])) + 1;
        if (total > max) return null;
    }
    const out = try arena.alloc(u32, total);
    var n: usize = 0;
    for (ranges) |r| {
        var u = @min(r[0], r[1]);
        while (true) : (u += 1) {
            out[n] = u;
            n += 1;
            if (u == @max(r[0], r[1])) break;
        }
    }
    return out;
}

/// Source → destination UID pairs from COPYUID, or null when the server
/// sent none or the sets do not line up.
pub fn uidMap(arena: Allocator, cu: ?imap.CopyUid) Allocator.Error!?[]UidPair {
    const c = cu orelse return null;
    const src = (try expand(arena, c.src, max_messages)) orelse return null;
    const dst = (try expand(arena, c.dst, max_messages)) orelse return null;
    if (src.len != dst.len or src.len == 0) return null;
    const out = try arena.alloc(UidPair, src.len);
    for (out, src, dst) |*o, s, d| o.* = .{ .from = s, .to = d };
    return out;
}
```
- [ ] **Step 5: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `173/173 tests passed`.

- [ ] **Step 6: Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is ready and suggest the message: `feat(organize): folder protection, move strategy, batching and COPYUID pairing`

---

### Task 4: Registry: refresh after folder changes, forget moved headers

**Files:**
- Modify: `src/accounts.zig`

**Interfaces:**
- Produces: `Registry.mailboxesChanged(idx, arena) void` (refreshes the list, which drops cached headers of vanished mailboxes; marks stale on failure; never sets a diagnostic); `Registry.forgetMoved(idx, mailbox, uidvalidity, uids) void`.

- [ ] **Step 1: Write the failing tests**

In `src/accounts.zig`, replace everything from the line `const testing = std.testing;` to the end of the file with:

```zig
const testing = std.testing;

const Noop = struct {
    pub fn run(_: *Noop, _: *Session) Error!void {}
};

const no_cache: config.Settings = .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file };
const no_filters_1 = [_][]const *const Filter{&.{}};

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
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
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
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
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
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
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

test "mailboxesChanged marks the list stale when the refresh fails; forgetMoved drops moved rows" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}/cache", .{&tmp.sub_path});
    defer testing.allocator.free(dir);

    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const store = reg.cache(0).?;
    try store.replaceMailboxes(a, &.{.{ .name = "INBOX", .delimiter = '/', .flags = &.{} }});
    try store.putMessages("INBOX", 9, &.{
        .{ .uid = 1, .size = 10, .data = "A: 1\r\n\r\n", .flags = null },
        .{ .uid = 2, .size = 20, .data = "A: 2\r\n\r\n", .flags = null },
    });

    reg.forgetMoved(0, "INBOX", 9, &.{1});
    const left = try store.getMessages(a, "INBOX", 9, &.{ 1, 2 });
    try testing.expectEqual(1, left.len);
    try testing.expectEqual(2, left[0].uid);

    try testing.expect(try store.mailboxesFresh(3600));
    reg.mailboxesChanged(0, a); // 127.0.0.1:1 is unreachable: falls back to stale
    try testing.expect(!try store.mailboxesFresh(3600));
    try testing.expectEqualStrings("", reg.diag());
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
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    try testing.expect(reg.cache(0) != null);
}

test "caching disabled: no store, clearCache reports false" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    try testing.expect(reg.cache(0) == null);
    try testing.expect(!reg.clearCache(0));
}

test "todo: active filters are required and must match the account count" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    try testing.expectError(error.FilterCountMismatch, Registry.init(testing.allocator, testing.io, &accounts, no_cache, &.{}));
}

test "todo: a cache found corrupt during use is deleted (with -wal/-shm) for rebuild" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    defer testing.allocator.free(dir);
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    try testing.expect(reg.cache(0) != null);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "local.sqlite3-wal", .data = "x" });
    testing.log_level = .err;
    defer testing.log_level = .warn;
    reg.cacheFailed(0, error.SqliteCorrupt);
    for ([_][]const u8{ "local.sqlite3", "local.sqlite3-wal", "local.sqlite3-shm" }) |name| {
        try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, name, .{}));
    }
}


fn oauthAccount(token_url: []const u8, refresh_token: [:0]u8) config.Account {
    return .{
        .name = "ms",
        .host = "127.0.0.1",
        .port = 1,
        .login = "me@contoso.com",
        .password = @constCast(&[_:0]u8{}),
        .readonly = false,
        .drafts = null,
        .auth = .{ .oauth2 = .{
            .provider = .custom,
            .client_id = "cid",
            .client_secret = null,
            .refresh_token = refresh_token,
            .tenant = "common",
            .custom = .{ .auth_url = "https://unused", .token_url = token_url, .scope = "imap" },
        } },
    };
}

test "oauth: access token is fetched once and cached until near expiry" {
    const fake = try token.FakeServer.start("HTTP/1.1 200 OK\r\nContent-Length: 44\r\nConnection: close\r\n\r\n{\"access_token\":\"AT-ONE\",\"expires_in\":3600}");
    defer fake.destroy();
    const thread = try std.Thread.spawn(.{}, token.FakeServer.serveOne, .{fake});
    const url = try testing.allocator.print("http://127.0.0.1:{d}/token", .{fake.port()});
    defer testing.allocator.free(url);
    var rt = [_:0]u8{ 'R', 'T' }; // writable: Registry.deinit wipes it
    var accounts = [_]config.Account{oauthAccount(url, &rt)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    reg.allow_insecure_token_loopback = true;

    try testing.expectEqualStrings("AT-ONE", try reg.accessToken(0, false));
    thread.join();
    // Served from memory: the fake server is gone, so a request would fail.
    try testing.expectEqualStrings("AT-ONE", try reg.accessToken(0, false));
}

test "oauth: invalid_grant tells the user to re-run auth, without the token" {
    const fake = try token.FakeServer.start("HTTP/1.1 400 Bad Request\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"error\":\"invalid_grant\"}");
    defer fake.destroy();
    const thread = try std.Thread.spawn(.{}, token.FakeServer.serveOne, .{fake});
    const url = try testing.allocator.print("http://127.0.0.1:{d}/token", .{fake.port()});
    defer testing.allocator.free(url);
    var rt = [_:0]u8{ 'R', 'T' }; // writable: Registry.deinit wipes it
    var accounts = [_]config.Account{oauthAccount(url, &rt)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    reg.allow_insecure_token_loopback = true;

    try testing.expectError(error.LoginFailed, reg.accessToken(0, false));
    thread.join();
    try testing.expect(std.mem.find(u8, reg.diag(), "tp_imap_mcp auth ms") != null);
    try testing.expect(std.mem.find(u8, reg.diag(), "RT") == null);
}
```
- [ ] **Step 2: Run the tests and confirm they fail**

Run: `zig build test --summary all`
Expected: compilation fails (the code under test does not exist yet).

- [ ] **Step 3: Implement**

In `src/accounts.zig`, replace everything **above** the line `const testing = std.testing;` with:

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
const Filter = @import("filter/rules.zig").Filter;
const token = @import("oauth/token.zig");
const provider = @import("oauth/provider.zig");
const text = @import("text.zig");
const unicode = @import("sanitize/unicode.zig");

pub const Session = imap.Session;
pub const Error = imap.Error || error{LoginFailed};

pub const timeout_sec: c_long = 60;

const log = std.log.scoped(.accounts);

pub const Registry = struct {
    gpa: Allocator,
    io: std.Io,
    /// HTTPS client for OAuth token requests, created on first use.
    token_client: ?token.Client = null,
    /// Test seam: let the token client use plain http to 127.0.0.1.
    allow_insecure_token_loopback: bool = false,
    accounts: []config.Account,
    settings: config.Settings,
    slots: []Slot,
    /// Active sensitive-content filters per account (ADR 0017), one entry per
    /// account. Required at init so filtering can never be silently off.
    active_filters: []const []const *const Filter,
    /// Human-readable cause of the most recent failure (no secrets).
    diag_buf: [512]u8 = undefined,
    diag_len: usize = 0,

    const CacheState = union(enum) { unopened, open: Store, disabled };

    const Slot = struct {
        session: ?Session = null,
        drafts: ?[:0]u8 = null, // wire-encoded, owned by gpa
        cache_path: ?[:0]u8 = null, // owned by gpa; set when the cache is opened
        access: ?token.AccessToken = null, // OAuth access token; value owned by gpa, NUL-terminated
        cache: CacheState = .unopened,
    };

    pub fn init(
        gpa: Allocator,
        io: std.Io,
        accounts: []config.Account,
        settings: config.Settings,
        active_filters: []const []const *const Filter,
    ) (Allocator.Error || error{FilterCountMismatch})!Registry {
        if (active_filters.len != accounts.len) return error.FilterCountMismatch;
        const slots = try gpa.alloc(Slot, accounts.len);
        @memset(slots, .{});
        return .{ .gpa = gpa, .io = io, .accounts = accounts, .settings = settings, .slots = slots, .active_filters = active_filters };
    }

    pub fn deinit(self: *Registry) void {
        for (self.slots, self.accounts) |*slot, *account| {
            if (slot.session) |*s| s.close();
            if (slot.drafts) |d| self.gpa.free(d);
            if (slot.cache_path) |cp| self.gpa.free(cp);
            self.forgetAccessToken(slot);
            switch (slot.cache) {
                .open => |*store| store.close(),
                else => {},
            }
            account.wipe();
        }
        self.gpa.free(self.slots);
        if (self.token_client) |*tc| tc.deinit();
        self.* = undefined;
    }

    fn forgetAccessToken(self: *Registry, slot: *Slot) void {
        if (slot.access) |t| {
            std.crypto.secureZero(u8, t.value);
            self.gpa.free(t.value);
        }
        slot.access = null;
    }

    /// The account's OAuth access token, refreshed when absent, near expiry,
    /// or `force`d (after the server rejected it). Kept only in memory.
    pub fn accessToken(self: *Registry, idx: usize, force: bool) Error![:0]const u8 {
        const slot = &self.slots[idx];
        const a = &self.accounts[idx];
        const o = a.auth.oauth2;
        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
        if (!force and !token.needsRefresh(slot.access, now)) return slot.access.?.value[0 .. slot.access.?.value.len - 1 :0];
        self.forgetAccessToken(slot);

        const rt = o.refresh_token orelse {
            self.setDiag("account \"{s}\": no OAuth refresh token; run `op run --env-file imap.env -- tp_imap_mcp auth {s}`", .{ a.name, a.name });
            return error.LoginFailed;
        };
        if (self.token_client == null) {
            self.token_client = token.Client.init(self.gpa, self.io, self.settings.ca_file) catch {
                self.setDiag("account \"{s}\": cannot load the CA bundle {s} for OAuth", .{ a.name, self.settings.ca_file });
                return error.LoginFailed;
            };
        }
        self.token_client.?.allow_insecure_loopback = self.allow_insecure_token_loopback;
        var arena_state: std.heap.ArenaAllocator = .init(self.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const ep = try provider.endpoints(arena, o.provider, o.tenant, o.custom);
        const resp = self.token_client.?.refresh(arena, ep, o.client_id, o.client_secret, rt) catch |err| {
            self.setDiag("account \"{s}\": OAuth token request failed ({t})", .{ a.name, err });
            return error.LoginFailed;
        };
        switch (resp) {
            .ok => |ok| {
                // A rotated refresh token in the response is ignored (ADR 0020).
                const value = try self.gpa.dupeSentinel(u8, ok.access_token, 0);
                slot.access = .{ .value = value[0 .. value.len + 1], .expires_at = now + ok.expires_in };
                return value;
            },
            .failed => |f| {
                if (std.mem.eql(u8, f.code, "invalid_grant")) {
                    self.setDiag("account \"{s}\": the OAuth refresh token was rejected (expired or revoked); run `op run --env-file imap.env -- tp_imap_mcp auth {s}` and store the new token", .{ a.name, a.name });
                } else {
                    self.setDiag("account \"{s}\": OAuth token request failed: {s}{s}{s}", .{ a.name, f.code, if (f.description.len > 0) ": " else "", f.description });
                }
                return error.LoginFailed;
            },
        }
    }

    pub fn find(self: *Registry, name: []const u8) ?usize {
        for (self.accounts, 0..) |a, i| if (std.ascii.eqlIgnoreCase(a.name, name)) return i;
        return null;
    }

    pub fn filtersFor(self: *const Registry, idx: usize) []const *const Filter {
        return self.active_filters[idx];
    }

    pub fn diag(self: *const Registry) []const u8 {
        return self.diag_buf[0..self.diag_len];
    }

    fn setDiag(self: *Registry, comptime fmt: []const u8, args: anytype) void {
        var w: std.Io.Writer = .fixed(&self.diag_buf);
        w.print(fmt, args) catch {
            // Overflow: cut on a code-point boundary and mark the truncation.
            const ellipsis = "...";
            const kept = text.truncateUtf8(w.buffered(), self.diag_buf.len - ellipsis.len);
            @memcpy(self.diag_buf[kept.len..][0..ellipsis.len], ellipsis);
            self.diag_len = kept.len + ellipsis.len;
            return;
        };
        self.diag_len = w.buffered().len;
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
                    const Op = @typeInfo(@TypeOf(op)).pointer.child;
                    if (comptime !retriesAfterConnectionLoss(Op)) {
                        self.setDiag("account \"{s}\": {s}", .{ self.accounts[idx].name, Op.connection_lost_message });
                        return err;
                    }
                    if (attempt == 0) continue;
                    self.setDiag("account \"{s}\": connection lost twice; giving up", .{self.accounts[idx].name});
                    return err;
                },
                error.ServerRejected => {
                    var buf: [400]u8 = undefined;
                    self.setDiag("IMAP server rejected the command: {s}", .{unicode.cleanInto(&buf, s.lastResponse())});
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
        var s = Session.connect(a.host, a.port, timeout_sec, self.settings.ca_file) catch |err| {
            switch (err) {
                error.TlsFailed => self.setDiag("account \"{s}\": TLS handshake with {s}:{d} failed; the certificate is not trusted by {s}", .{ a.name, a.host, a.port, self.settings.ca_file }),
                error.HostnameMismatch => self.setDiag("account \"{s}\": the TLS certificate of {s}:{d} is not valid for host {s}", .{ a.name, a.host, a.port, a.host }),
                else => self.setDiag("account \"{s}\": cannot connect to {s}:{d}", .{ a.name, a.host, a.port }),
            }
            return err;
        };
        self.authenticate(idx, &s) catch |err| {
            s.abandon();
            return err;
        };
        slot.session = s;
        return &slot.session.?;
    }

    /// Password LOGIN or XOAUTH2 (one token refresh-and-retry on rejection).
    fn authenticate(self: *Registry, idx: usize, s: *Session) Error!void {
        const a = &self.accounts[idx];
        var buf: [400]u8 = undefined;
        switch (a.auth) {
            .password => s.login(a.login, a.password) catch |err| {
                self.setDiag("account \"{s}\": login failed: {s}", .{ a.name, unicode.cleanInto(&buf, s.lastResponse()) });
                return if (err == error.ServerRejected) error.LoginFailed else err;
            },
            .oauth2 => {
                const first = try self.accessToken(idx, false);
                s.oauth2Login(a.login, first) catch |err| {
                    if (err != error.ServerRejected) return err;
                    const fresh = try self.accessToken(idx, true);
                    s.oauth2Login(a.login, fresh) catch |err2| {
                        self.setDiag("account \"{s}\": OAuth login failed: {s}", .{ a.name, unicode.cleanInto(&buf, s.lastResponse()) });
                        return if (err2 == error.ServerRejected) error.LoginFailed else err2;
                    };
                };
            },
        }
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
        if (slot.cache_path == null) slot.cache_path = cachePath(self.gpa, dir, self.accounts[idx].name) catch return null;
        const store = openCache(self.gpa, dir, slot.cache_path.?) catch |err| {
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
        // Corruption found during use: delete the files so the next start
        // rebuilds the cache instead of failing on it every time.
        if (err == error.SqliteCorrupt) if (slot.cache_path) |cp| deleteCacheFiles(cp);
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

    /// The cached mailbox list if it is fresh; never contacts the server.
    pub fn freshMailboxes(self: *Registry, idx: usize, arena: Allocator) ?[]imap.Mailbox {
        const store = self.cache(idx) orelse return null;
        const fresh = store.mailboxesFresh(self.settings.mailbox_ttl) catch |e| return self.cacheMiss(idx, e);
        if (!fresh) return null;
        return store.loadMailboxes(arena) catch |e| self.cacheMiss(idx, e);
    }

    /// After CREATE/RENAME/DELETE (ADR 0021): refreshes the mailbox list,
    /// which also drops cached headers of mailboxes that no longer exist. If
    /// the refresh fails the list is marked stale instead; never fails.
    pub fn mailboxesChanged(self: *Registry, idx: usize, arena: Allocator) void {
        defer self.diag_len = 0; // the tool already succeeded
        _ = self.mailboxList(idx, arena, true) catch {
            if (self.cache(idx)) |store| store.markMailboxesStale() catch |e| self.cacheFailed(idx, e);
        };
    }

    /// Drops cached headers of messages moved out of `mailbox`.
    pub fn forgetMoved(self: *Registry, idx: usize, mailbox: []const u8, uidvalidity: u32, uids: []const u32) void {
        const store = self.cache(idx) orelse return;
        store.deleteMessages(mailbox, uidvalidity, uids) catch |e| self.cacheFailed(idx, e);
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

/// Operations are retried once after a dropped connection unless they declare
/// `pub const retry_after_connection_loss = false;` (non-idempotent commands
/// such as APPEND), together with a `connection_lost_message`.
pub fn retriesAfterConnectionLoss(comptime Op: type) bool {
    return !@hasDecl(Op, "retry_after_connection_loss") or Op.retry_after_connection_loss;
}

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
fn cachePath(gpa: Allocator, dir: []const u8, account: []const u8) ![:0]u8 {
    const lower = try std.ascii.allocLowerString(gpa, account);
    defer gpa.free(lower);
    return gpa.printSentinel("{s}/{s}.sqlite3", .{ dir, lower }, 0);
}

/// Removes the database and its WAL companions (best effort).
fn deleteCacheFiles(path: [:0]const u8) void {
    _ = std.c.unlink(path);
    var buf: [std.fs.max_path_bytes + 8]u8 = undefined;
    for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
        const p = std.mem.printSentinel(&buf, "{s}{s}", .{ path, suffix }, 0) catch continue;
        _ = std.c.unlink(p);
    }
}

fn openCache(gpa: Allocator, dir: []const u8, path: [:0]const u8) !Store {
    try makePath(gpa, dir);
    const old_mask = std.c.umask(0o077);
    defer _ = std.c.umask(old_mask);
    return Store.open(path) catch |err| switch (err) {
        error.SqliteCorrupt => {
            log.warn("cache file {s} is corrupt; rebuilding", .{path});
            deleteCacheFiles(path);
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
- [ ] **Step 4: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `174/174 tests passed`.

- [ ] **Step 5: Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is ready and suggest the message: `feat(organize): cache upkeep for folder changes and moves`

---

### Task 5: The five tools

**Files:**
- Modify: `src/tools.zig`, `src/descriptions.zig`, `src/mcp.zig` (tool count in a test)

**Interfaces:**
- Consumes: everything above.
- Produces: tools `create_mailbox`, `rename_mailbox`, `delete_mailbox`, `move_messages`, `copy_messages` (spec §2); ops `CreateOp`, `RenameOp`, `DeleteOp`, `TransferOp`, all non-retryable; `bestEffort`, `existingUids`, `keepPresent`, `displayName`; `Ctx.folderName`, `Ctx.freshList`.

- [ ] **Step 1: Write the failing tests**

In `src/tools.zig`, replace everything from the line `const testing = std.testing;` to the end of the file with:

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
    const none = [_][]const *const filter.Filter{ &.{}, &.{} };
    return Registry.init(testing.allocator, testing.io, accts, .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &none);
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
        "[{\"name\":\"rw\",\"login\":\"rw@example.org\",\"readonly\":false,\"filters\":[]},{\"name\":\"ro\",\"login\":\"ro@example.org\",\"readonly\":true,\"filters\":[]}]",
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

test "alignToUids merges duplicate FETCH responses instead of letting the last win" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    // Real response, then an unsolicited flag update for the same UID.
    const fetched = [_]Fetched{
        .{ .uid = 5, .size = 50, .data = "Subject: x\r\n\r\n", .flags = null },
        .{ .uid = 5, .size = 0, .data = null, .flags = &.{"\\Seen"} },
    };
    const out = try alignToUids(arena_state.allocator(), &.{5}, &fetched);
    try testing.expectEqualStrings("Subject: x\r\n\r\n", out[0].?.data.?);
    try testing.expectEqual(50, out[0].?.size);
    try testing.expectEqualStrings("\\Seen", out[0].?.flags.?[0]);
}

test "list_accounts reports each account's active filters" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    const active = [_][]const *const filter.Filter{ &.{&filter.password_reset}, &.{} };
    reg.active_filters = &active;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const got = (try callJson(&reg, arena_state.allocator(), "list_accounts", "{}")).?.content;
    try testing.expect(std.mem.find(u8, got, "\"name\":\"rw\",\"login\":\"rw@example.org\",\"readonly\":false,\"filters\":[\"password_reset\"]") != null);
    try testing.expect(std.mem.find(u8, got, "\"readonly\":true,\"filters\":[]") != null);
}

test "withheld message: get_header keeps only date/from plus marker; get_header_field withholds the rest" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const raw = "Date: Tue, 7 Oct 2026 10:00:00 +0000\r\nFrom: GitHub <noreply@github.com>\r\nSubject: =?UTF-8?Q?Reset_your_password?=\r\nX-Code: 482913\r\n\r\n";
    const active = [_]*const filter.Filter{&filter.password_reset};
    const withheld = try withheldBy(a, &active, raw);
    try testing.expectEqualStrings("password_reset", withheld.?);
    try testing.expect((try withheldBy(a, &.{}, raw)) == null);

    const hs = try headers.parse(a, raw);
    var aw: std.Io.Writer.Allocating = .init(a);
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeHeaderObject(&jw, try headerGroups(a, hs, withheld, 32 * 1024), withheld);
    try testing.expectEqualStrings(
        "{\"date\":[\"Tue, 7 Oct 2026 10:00:00 +0000\"],\"from\":[\"GitHub <noreply@github.com>\"],\"x-tp-imap-mcp-withheld\":[\"password_reset\"]}",
        aw.written(),
    );

    try testing.expectEqualStrings("[withheld by filter \"password_reset\"]", (try headerFieldValues(a, hs, "Subject", withheld))[0]);
    try testing.expectEqualStrings("[withheld by filter \"password_reset\"]", (try headerFieldValues(a, hs, "x-code", withheld))[0]);
    try testing.expectEqualStrings("GitHub <noreply@github.com>", (try headerFieldValues(a, hs, "FROM", withheld))[0]);
    // Not withheld: the subject comes back decoded (ADR 0019).
    try testing.expectEqualStrings("Reset your password", (try headerFieldValues(a, hs, "subject", null))[0]);
}

test "header values are decoded, cleaned of invisible characters, and capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // "Invoice\u{200B} due" base64-encoded, with a zero-width space hidden inside.
    try testing.expectEqualStrings("Invoice due", try displayValue(a, "=?UTF-8?B?SW52b2ljZeKAiyBkdWU=?="));
    try testing.expectEqualStrings("plain\u{e9}", try displayValue(a, "plain\u{e9}\u{202E}"));

    var long: std.ArrayList(u8) = .empty;
    try long.appendNTimes(a, 'a', 5000);
    const capped = try displayValue(a, long.items);
    try testing.expect(std.mem.endsWith(u8, capped, "[truncated: 2952 bytes omitted]"));

    const hg = try headerGroups(a, try headers.parse(a, "Subject: =?UTF-8?Q?Hi?=\r\nTo: x@y.z\r\n\r\n"), null, 32 * 1024);
    try testing.expectEqual("subject".len + "Hi".len + "to".len + "x@y.z".len, hg.size);
}

test "review: one get_header item is capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var raw: std.ArrayList(u8) = .empty;
    for (0..2000) |i| {
        try raw.print(a, "X-H{d}: ", .{i});
        try raw.appendNTimes(a, 'v', 100);
        try raw.appendSlice(a, "\r\n");
    }
    try raw.appendSlice(a, "\r\n");
    const hg = try headerGroups(a, try headers.parse(a, raw.items), null, 32 * 1024);
    try testing.expect(hg.size <= 32 * 1024 + 4096);
    try testing.expect(hg.omitted > 0);
}

test "review: bodies are fetched only for UIDs whose headers were seen and passed" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const active = [_]*const filter.Filter{&filter.password_reset};
    // UID 42: an unsolicited flags-only FETCH arrives before its real headers.
    const fetched = [_]Fetched{
        .{ .uid = 42, .size = 0, .data = null, .flags = &.{"\\Seen"} },
        .{ .uid = 42, .size = 10, .data = "Subject: Reset your password\r\n\r\n", .flags = null },
        .{ .uid = 7, .size = 10, .data = "Subject: Lunch\r\n\r\n", .flags = null },
        .{ .uid = 9, .size = 0, .data = null, .flags = &.{"\\Seen"} }, // never got headers
    };
    var withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty;
    const allowed = try classifyForBodies(a, &active, &.{ 42, 7, 9 }, &fetched, &withheld);
    try testing.expectEqualSlices(u32, &.{7}, allowed);
    try testing.expectEqualStrings("password_reset", withheld.get(42).?);
}

test "todo: create_message's append is never retried after a dropped connection" {
    try testing.expect(!accounts.retriesAfterConnectionLoss(AppendOp));
    try testing.expect(accounts.retriesAfterConnectionLoss(SearchOp));
}

test "todo: a cleaned mailbox name resolves back to its real wire name" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const boxes = [_]imap.Mailbox{
        .{ .name = "INBOX", .delimiter = '/', .flags = &.{} },
        .{ .name = "Fo&IAs-o", .delimiter = '/', .flags = &.{} }, // "Fo\u{200B}o"
    };
    try testing.expectEqualStrings("Fo&IAs-o", try resolveMailbox(a, &boxes, "Foo", "Foo"));
    try testing.expectEqualStrings("INBOX", try resolveMailbox(a, &boxes, "INBOX", "INBOX"));
    try testing.expectEqualStrings("Other", try resolveMailbox(a, &boxes, "Other", "Other"));
}

test "todo: cached hits for expunged UIDs are pruned" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cached = [_]Fetched{
        .{ .uid = 5, .size = 1, .data = "A: b\r\n\r\n", .flags = null },
        .{ .uid = 6, .size = 1, .data = "A: c\r\n\r\n", .flags = null },
    };
    const r = try pruneCached(a, &cached, &.{6});
    try testing.expectEqual(1, r.kept.len);
    try testing.expectEqual(6, r.kept[0].uid);
    try testing.expectEqualSlices(u32, &.{5}, r.gone);
}

test "todo: message headers cannot spoof x-tp-imap-mcp markers" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const hs = try headers.parse(a, "Subject: hi\r\nX-TP-IMAP-MCP-Withheld: password_reset\r\n\r\n");
    const hg = try headerGroups(a, hs, null, 32 * 1024);
    try testing.expectEqual(1, hg.groups.count());
    try testing.expectEqual(0, (try headerFieldValues(a, hs, "x-tp-imap-mcp-withheld", null)).len);
}

test "todo: withheld entries bypass the response budget" {
    var b: limit.Budget = .init(10);
    try testing.expect(admitItem(&b, 50, null)); // first item always admitted
    try testing.expect(admitItem(&b, 50, "password_reset")); // withheld: kept regardless
    try testing.expect(!admitItem(&b, 50, null));
}

test "todo: list_attachments is offered with account, directory, uids" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    for (parsed.value.array.items) |t| {
        if (!std.mem.eql(u8, t.object.get("name").?.string, "list_attachments")) continue;
        const req = t.object.get("inputSchema").?.object.get("required").?.array.items;
        try testing.expectEqual(3, req.len);
        return;
    }
    return error.TestExpectedTool;
}

test "todo: attachment JSON shape" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const atts = [_]attachments.Attachment{.{ .filename = "a.pdf", .content_type = "application/pdf", .size = 3, .inline_ = false }};
    try testing.expectEqualStrings(
        "[{\"filename\":\"a.pdf\",\"content_type\":\"application/pdf\",\"size\":3,\"inline\":false}]",
        try attachmentsJson(a, &atts),
    );
}

test "organization tools: read-only accounts refuse changes but allow dry runs" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ro = "account \"ro\" is read-only";
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "create_mailbox", "{\"account\":\"ro\",\"name\":\"X\"}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "rename_mailbox", "{\"account\":\"ro\",\"name\":\"X\",\"new_name\":\"Y\"}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "delete_mailbox", "{\"account\":\"ro\",\"name\":\"X\"}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "move_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"uids\":[\"1\"]}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "copy_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"uids\":[\"1\"]}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "move_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"criteria\":\"ALL\",\"dry_run\":false}")).?.tool_error);
    // Criteria default to a dry run, which read-only accounts may do: the
    // call gets as far as the (unreachable) server.
    try testing.expectEqualStrings(
        "account \"ro\": cannot connect to 127.0.0.1:1",
        (try callJson(&reg, a, "move_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"criteria\":\"ALL\"}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "account \"ro\": cannot connect to 127.0.0.1:1",
        (try callJson(&reg, a, "copy_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"uids\":[\"1\"],\"dry_run\":true}")).?.tool_error,
    );
}

test "organization tools: argument errors never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("mailbox name must not be empty", (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"\"}")).?.invalid_params);
    try testing.expectEqualStrings("mailbox name must not contain * or %", (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"All*\"}")).?.invalid_params);
    try testing.expectEqualStrings(
        "mailbox name must be valid UTF-8 without control characters",
        (try callJson(&reg, a, "rename_mailbox", "{\"account\":\"rw\",\"name\":\"X\",\"new_name\":\"Y\\r\\nZ\"}")).?.invalid_params,
    );
    const move = "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"X\"";
    try testing.expectEqualStrings("pass either uids or criteria, not both", (try callJson(&reg, a, "move_messages", move ++ ",\"uids\":[\"1\"],\"criteria\":\"ALL\"}")).?.invalid_params);
    try testing.expectEqualStrings("pass uids (from search) or criteria", (try callJson(&reg, a, "copy_messages", move ++ "}")).?.invalid_params);
    try testing.expectEqualStrings("criteria must not contain CR, LF, or NUL", (try callJson(&reg, a, "move_messages", move ++ ",\"criteria\":\"ALL\\r\\nA1 DELETE INBOX\"}")).?.invalid_params);

    var many: std.ArrayList(u8) = .empty;
    try many.appendSlice(a, move ++ ",\"uids\":[");
    for (1..5002) |i| try many.print(a, "{s}\"{d}\"", .{ if (i > 1) "," else "", i });
    try many.appendSlice(a, "]}");
    try testing.expectEqualStrings("at most 5000 messages per call; got 5001 uids", (try callJson(&reg, a, "move_messages", many.items)).?.invalid_params);
}

test "organization tools: schema requires account, directory, destination" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    for (parsed.value.array.items) |t| {
        if (!std.mem.eql(u8, t.object.get("name").?.string, "move_messages")) continue;
        const schema = t.object.get("inputSchema").?.object;
        const req = schema.get("required").?.array.items;
        try testing.expectEqual(3, req.len);
        try testing.expectEqualStrings("destination", req[2].string);
        try testing.expect(schema.get("properties").?.object.get("dry_run") != null);
        return;
    }
    return error.TestExpectedMoveMessages;
}

test "organization operations are never retried after a dropped connection" {
    try testing.expect(!accounts.retriesAfterConnectionLoss(CreateOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(RenameOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(DeleteOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(TransferOp));
}

test "bestEffort tolerates a server refusal only" {
    try testing.expect(try bestEffort({}));
    try testing.expect(!try bestEffort(error.ServerRejected));
    try testing.expectError(error.ConnectionLost, bestEffort(error.ConnectionLost));
}

test "keepPresent keeps existing UIDs in input order without duplicates" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var present: std.AutoHashMapUnmanaged(u32, void) = .empty;
    for ([_]u32{ 3, 5, 9 }) |u| try present.put(a, u, {});
    try testing.expectEqualSlices(u32, &.{ 9, 3, 5 }, try keepPresent(a, &.{ 9, 4, 3, 9, 5 }, &present));
}
```
- [ ] **Step 2: Edit `src/mcp.zig`**

Replace every occurrence of

```zig
try testing.expectEqual(15, list.value.object
```

with

```zig
try testing.expectEqual(20, list.value.object
```
- [ ] **Step 3: Run the tests and confirm they fail**

Run: `zig build test --summary all`
Expected: compilation fails (the code under test does not exist yet).

- [ ] **Step 4: Write `src/descriptions.zig`**

Replace (or create) the whole file:

```zig
//! Tool descriptions, adapted from vivier/imap-mcp-server docstrings with an
//! `account` argument added. These are what the model reads; edit with care.

pub const account_param = "Account name, as returned by list_accounts().";

pub const list_accounts =
    \\Lists the configured IMAP accounts. Every other tool takes one of these
    \\names as its `account` argument.
    \\
    \\Return:
    \\    [ {"name": "tetra", "login": "me@example.org", "readonly": false,
    \\       "filters": ["password_reset"]}, ... ]
    \\    readonly accounts refuse change_keywords, create_message and the
    \\    folder and move/copy tools (dry runs are allowed).
    \\    filters are the account's active sensitive-content filters. Messages
    \\    they match are withheld: get_text/get_html return
    \\    [withheld by filter "<name>"] and get_header shows only date and from.
    \\    Built-in filters: password_reset (password resets, account recovery)
    \\    and one_time_codes (verification and sign-in codes, 2FA, magic links).
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

const sanitized_note =
    \\
    \\Output is sanitized: plain text only, hidden HTML content and invisible
    \\Unicode removed, links shown as "text (url)". Long bodies end with
    \\"[truncated: N bytes omitted]". If the response grows too large, later
    \\items are replaced by "[omitted: response size limit reached; request
    \\fewer UIDs]" -- ask again for those UIDs in a smaller batch.
;

const withheld_note =
    \\
    \\A message matched by one of the account's sensitive-content filters (see
    \\list_accounts) is withheld: its content is never downloaded and you get
    \\[withheld by filter "<name>"] instead. Tell the user the message exists
    \\but is withheld; do not retry or try to work around it.
;

pub const get_header =
    \\Read message headers for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++
    \\
    \\Return:
    \\    list of {lowercased header name: [values]}. Values are decoded
    \\    (RFC 2047) and sanitized. For a withheld message only date and from
    \\    are returned, plus "x-tp-imap-mcp-withheld": ["<filter>"].
++ sanitized_note ++ withheld_note;

pub const get_header_field =
    \\Read one header field for the given UIDs in directory.
    \\
    \\Args:
    \\    directory: directory to read from
    \\    field: header field name (case-insensitive), e.g. "Message-ID"
++ "\n" ++ uids_note ++
    \\
    \\Return:
    \\    list of [values] (decoded, sanitized); [] when the message lacks the
    \\    field. For a withheld message, fields other than date and from return
    \\    the marker.
++ sanitized_note ++ withheld_note;

pub const get_text =
    \\Read the plain text body for the given UIDs in directory. Concatenates
    \\every text/plain part that is not an attachment; if there is none, the
    \\HTML part converted to plain text. Charset is UTF-8.
    \\Encrypted (PGP/MIME) messages are not decrypted; a marker is returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++ sanitized_note ++ withheld_note;

pub const get_html =
    \\Read the HTML body for the given UIDs in directory, converted to plain
    \\text (no markup is returned). Concatenates every text/html part that
    \\is not an attachment; "" if the message has no HTML part.
    \\Encrypted (PGP/MIME) messages are not decrypted; a marker is returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++ sanitized_note ++ withheld_note;

pub const list_attachments =
    \\List the attachments of the given UIDs: file name, content type, approximate
    \\size in bytes, and whether the part is inline (e.g. an image embedded in
    \\the HTML). Attachment content is never downloaded or returned.
    \\
    \\Args:
    \\    directory: directory to read from
++ "\n" ++ uids_note ++
    \\
    \\Return, e.g. for list_attachments(account, "INBOX", ["12", "13", "999"]):
    \\    [ [{"filename": "invoice.pdf", "content_type": "application/pdf",
    \\        "size": 48213, "inline": false}],
    \\      [],
    \\      null ]
    \\
    \\File names are sanitized (decoded, invisible characters and paths removed).
    \\An attached e-mail without a name is listed as forwarded-message.eml.
++ withheld_note;

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

pub const create_mailbox =
    \\Create a folder (mailbox) and subscribe to it. Missing parent folders
    \\are created by the server. Refused for read-only accounts.
    \\
    \\Args:
    \\    name: folder path using the account's hierarchy delimiter (see
    \\          list_mailboxes DELIMITER), e.g. "Receipts/2026"
    \\
    \\Return:
    \\    {"created": "Receipts/2026", "subscribed": true}
    \\
    \\Notes:
    \\    Folders cannot be created inside Gmail's [Gmail]/ system folders.
    \\    On Gmail a folder is a label.
;

pub const rename_mailbox =
    \\Rename a folder, or move it under another parent by giving a new path.
    \\Subfolders move with it and subscriptions follow. Refused for read-only
    \\accounts.
    \\
    \\Args:
    \\    name: the folder to rename, e.g. "Projects/X"
    \\    new_name: its new path, e.g. "Archive/2025/X"
    \\
    \\Return:
    \\    {"renamed": "Projects/X", "to": "Archive/2025/X", "note": null}
    \\
    \\Notes:
    \\    INBOX and special-use folders (Sent, Drafts, Trash, Junk/Spam,
    \\    Archive, All Mail, ...), and folders containing them, cannot be
    \\    renamed. On Gmail this renames the label.
;

pub const delete_mailbox =
    \\Delete an empty folder. Refused if it still holds messages or
    \\subfolders (move or delete those first), and for read-only accounts.
    \\
    \\Args:
    \\    name: the folder to delete
    \\
    \\Return:
    \\    {"deleted": "Old/Empty", "note": null}
    \\
    \\Notes:
    \\    INBOX and special-use folders cannot be deleted.
;

pub const move_messages =
    \\Move messages from one folder to another. Select them with uids (from
    \\search) or with criteria (IMAP SEARCH syntax, as in search()).
    \\
    \\Args:
    \\    directory: the source folder, e.g. "INBOX"
    \\    destination: the target folder, e.g. "Receipts/2026"
    \\    uids: an array of UID strings, or
    \\    criteria: e.g. "FROM \"billing@example.com\" SINCE 1-Jan-2026"
    \\    create_missing: true to create the destination if it does not exist
    \\    dry_run: with criteria the default is true: nothing is moved and the
    \\        result shows how many messages match (and the first 100 UIDs).
    \\        Show this to the user, then call again with dry_run=false.
    \\        With uids the default is false.
    \\
    \\Return:
    \\    {"moved": 3, "source": "INBOX", "destination": "Receipts/2026",
    \\     "uid_map": [{"from": "101", "to": "7"}, ...], "note": null}
    \\    uid_map gives the messages' new UIDs in the destination (null if the
    \\    server does not report them). A dry run returns
    \\    {"dry_run": true, "matched": 42, "uids": [...], ...}.
    \\
    \\Notes:
    \\    At most 5000 messages per call. Refused for read-only accounts
    \\    (dry runs are allowed). Moving to Trash or Spam/Junk works like a
    \\    deletion: servers may purge those folders (Gmail after 30 days).
    \\    Gmail: moving out of INBOX archives the message and applies the
    \\    destination label; every message also stays in [Gmail]/All Mail,
    \\    and moving out of All Mail only adds a label.
;

pub const copy_messages =
    \\Copy messages to another folder, keeping the originals. Arguments and
    \\selection rules are those of move_messages (uids or criteria; criteria
    \\default to a dry run; at most 5000 messages per call).
    \\
    \\Return:
    \\    {"copied": 3, "source": "INBOX", "destination": "Receipts/2026",
    \\     "uid_map": [{"from": "101", "to": "7"}, ...], "note": null}
    \\
    \\Notes:
    \\    On Gmail, copying adds the destination label; the message stays
    \\    where it was. Refused for read-only accounts (dry runs are allowed).
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
- [ ] **Step 5: Implement**

In `src/tools.zig`, replace everything **above** the line `const testing = std.testing;` with:

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
const filter = @import("filter/rules.zig");
const attachments = @import("attachments.zig");
const unicode = @import("sanitize/unicode.zig");
const limit = @import("sanitize/limit.zig");
const mutf7 = @import("imap/mutf7.zig");
const organize = @import("organize.zig");
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
    /// Set by `account()`; lets `mailbox()` resolve names via the cache.
    idx: ?usize = null,

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
        if (ctx.registry.find(name)) |idx| {
            ctx.idx = idx;
            return idx;
        }
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
        const encoded = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        // list_mailboxes shows names with invisible characters removed; map
        // such a name back to the real one (fresh cache only, no round trip).
        const boxes = if (ctx.idx) |i| ctx.registry.freshMailboxes(i, ctx.arena) else null;
        const wire = if (boxes) |b| try resolveMailbox(ctx.arena, b, utf8, encoded) else encoded;
        return ctx.arena.dupeSentinel(u8, wire, 0);
    }

    /// A folder name to create or rename to (ADR 0021): validated against
    /// the account's hierarchy delimiter; UTF-8 and wire forms.
    fn folderName(ctx: *Ctx, key: []const u8, delimiter: ?u8) Failure!struct { utf8: []const u8, wire: [:0]const u8 } {
        const utf8 = try ctx.string(key);
        try ctx.check(validate.mailboxName(utf8, delimiter));
        const wire = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        return .{ .utf8 = utf8, .wire = try ctx.arena.dupeSentinel(u8, wire, 0) };
    }

    /// The account's mailbox list straight from the server (also refreshes
    /// the cache, so `mailbox()` resolves against it).
    fn freshList(ctx: *Ctx, idx: usize) Failure![]imap.Mailbox {
        return ctx.registry.mailboxList(idx, ctx.arena, true) catch |err| return ctx.imapFailed(err);
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
const p_folder: Param = .{ .name = "name", .kind = .string, .description = "Folder path, e.g. \"Receipts/2026\"" };
const transfer_params = [_]Param{
    p_account,
    .{ .name = "directory", .kind = .string, .description = "Source mailbox, e.g. \"INBOX\"" },
    .{ .name = "destination", .kind = .string, .description = "Destination mailbox, e.g. \"Receipts/2026\"" },
    .{ .name = "uids", .kind = .string_array, .description = "Message UIDs from search(); pass this or criteria", .required = false },
    .{ .name = "criteria", .kind = .string, .description = "IMAP SEARCH criteria selecting the messages; pass this or uids", .required = false },
    .{ .name = "create_missing", .kind = .boolean, .description = "true to create the destination if it does not exist (default false)", .required = false },
    .{ .name = "dry_run", .kind = .boolean, .description = "true to only report what would happen; default true with criteria, false with uids", .required = false },
};

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
    .{ .name = "list_attachments", .description = desc.list_attachments, .params = &.{ p_account, p_directory, p_uids }, .handler = listAttachments },
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
    .{ .name = "create_mailbox", .description = desc.create_mailbox, .params = &.{ p_account, p_folder }, .handler = createMailbox },
    .{ .name = "rename_mailbox", .description = desc.rename_mailbox, .params = &.{
        p_account,
        .{ .name = "name", .kind = .string, .description = "Folder to rename, e.g. \"Projects/X\"" },
        .{ .name = "new_name", .kind = .string, .description = "New path; a different parent moves the folder, e.g. \"Archive/2025/X\"" },
    }, .handler = renameMailbox },
    .{ .name = "delete_mailbox", .description = desc.delete_mailbox, .params = &.{ p_account, p_folder }, .handler = deleteMailbox },
    .{ .name = "move_messages", .description = desc.move_messages, .params = &transfer_params, .handler = moveMessages },
    .{ .name = "copy_messages", .description = desc.copy_messages, .params = &transfer_params, .handler = copyMessages },
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
    const Entry = struct { name: []const u8, login: []const u8, readonly: bool, filters: []const []const u8 };
    const out = try ctx.arena.alloc(Entry, ctx.registry.accounts.len);
    for (ctx.registry.accounts, out, 0..) |a, *e, i| {
        const active = ctx.registry.filtersFor(i);
        const names = try ctx.arena.alloc([]const u8, active.len);
        for (active, names) |f, *n| n.* = f.name;
        e.* = .{ .name = a.name, .login = a.login, .readonly = a.readonly, .filters = names };
    }
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
        const decoded = mutf7.decode(ctx.arena, m.name) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidMutf7 => try text.sanitizeUtf8(ctx.arena, m.name),
        };
        const path = try unicode.clean(ctx.arena, decoded);
        if (!try listmatch.matches(ctx.arena, path, directory, pattern, m.delimiter)) continue;
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
fn fetchHeaders(ctx: *Ctx) Failure!struct { idx: usize, items: []?*const Fetched } {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: CachedHeadersOp = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = uids };
    try ctx.imapRun(idx, &op);
    return .{ .idx = idx, .items = try alignToUids(ctx.arena, uids, op.result) };
}

/// Name of the active filter withholding this message, if any (ADR 0017).
fn withheldBy(arena: Allocator, active: []const *const filter.Filter, raw_header: []const u8) Allocator.Error!?[]const u8 {
    if (active.len == 0) return null;
    return filter.classify(arena, active, try filter.decodeHeaders(arena, raw_header));
}

/// A header value as shown to the model: RFC 2047-decoded, valid UTF-8,
/// invisible characters removed, capped (ADR 0019).
fn displayValue(arena: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    const utf8 = try text.sanitizeUtf8(arena, try imap.decodeHeaderValue(arena, raw));
    return limit.truncate(arena, try unicode.clean(arena, utf8), limit.header_value_max);
}

const HeaderGroups = struct {
    groups: std.array_hash_map.String(std.ArrayList([]const u8)) = .empty,
    size: usize = 0, // bytes of names and values, for the response budget
    omitted: usize = 0, // header lines dropped by the per-item cap
};

/// Display values grouped by name in first-appearance order; for a withheld
/// message only the visible headers.
/// At most `max_bytes` of names and values per message; the rest are counted
/// in `omitted` (one message cannot flood a response).
fn headerGroups(arena: Allocator, hs: []const headers.Header, withheld: ?[]const u8, max_bytes: usize) Allocator.Error!HeaderGroups {
    var out: HeaderGroups = .{};
    for (hs) |h| {
        if (withheld != null and !filter.isVisibleHeader(h.name)) continue;
        if (isOwnMarker(h.name)) continue; // a message must not spoof our markers
        if (out.size >= max_bytes) {
            out.omitted += 1;
            continue;
        }
        const g = try out.groups.getOrPut(arena, h.name);
        if (!g.found_existing) {
            g.value_ptr.* = .empty;
            out.size += limit.jsonLen(h.name);
        }
        const v = try displayValue(arena, h.value);
        try g.value_ptr.append(arena, v);
        out.size += limit.jsonLen(v);
    }
    return out;
}

/// One get_header object, plus the withheld marker header when withheld.
fn writeHeaderObject(jw: *Stringify, hg: HeaderGroups, withheld: ?[]const u8) Failure!void {
    var groups = hg.groups;
    jw.beginObject() catch return error.OutOfMemory;
    var it = groups.iterator();
    while (it.next()) |e| {
        jw.objectField(e.key_ptr.*) catch return error.OutOfMemory;
        jw.write(e.value_ptr.items) catch return error.OutOfMemory;
    }
    if (withheld) |name| {
        jw.objectField("x-tp-imap-mcp-withheld") catch return error.OutOfMemory;
        jw.write(&[_][]const u8{name}) catch return error.OutOfMemory;
    }
    if (hg.omitted > 0) {
        jw.objectField("x-tp-imap-mcp-truncated") catch return error.OutOfMemory;
        var buf: [64]u8 = undefined;
        const note = std.mem.print(&buf, "{d} header lines omitted", .{hg.omitted}) catch unreachable;
        jw.write(&[_][]const u8{note}) catch return error.OutOfMemory;
    }
    jw.endObject() catch return error.OutOfMemory;
}

/// get_header_field values for one message (withheld fields get the marker).
fn headerFieldValues(arena: Allocator, hs: []const headers.Header, field: []const u8, withheld: ?[]const u8) Allocator.Error![]const []const u8 {
    if (withheld) |name| if (!filter.isVisibleHeader(field)) {
        const m = try arena.alloc([]const u8, 1);
        m[0] = try filter.marker(arena, name);
        return m;
    };
    if (isOwnMarker(field)) return &.{};
    var values: std.ArrayList([]const u8) = .empty;
    for (hs) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, field))
            try values.append(arena, try displayValue(arena, h.value));
    }
    return values.items;
}

fn getHeader(ctx: *Ctx) Failure![]const u8 {
    const r = try fetchHeaders(ctx);
    const active = ctx.registry.filtersFor(r.idx);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    jw.beginArray() catch return error.OutOfMemory;
    for (r.items) |maybe| {
        const item = maybe orelse {
            jw.write(null) catch return error.OutOfMemory;
            continue;
        };
        const raw = item.data orelse "";
        const withheld = try withheldBy(ctx.arena, active, raw);
        const hg = try headerGroups(ctx.arena, try headers.parse(ctx.arena, raw), withheld, ctx.registry.settings.max_body_bytes);
        if (admitItem(&budget, hg.size, withheld)) {
            try writeHeaderObject(&jw, hg, withheld);
        } else {
            jw.write(.{ .@"x-tp-imap-mcp-omitted" = .{limit.omitted_reason} }) catch return error.OutOfMemory;
        }
    }
    jw.endArray() catch return error.OutOfMemory;
    return aw.written();
}

fn getHeaderField(ctx: *Ctx) Failure![]const u8 {
    const field = try ctx.string("field");
    try ctx.check(validate.field(field));
    const r = try fetchHeaders(ctx);
    const active = ctx.registry.filtersFor(r.idx);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    const out = try ctx.arena.alloc(?[]const []const u8, r.items.len);
    for (r.items, out) |maybe, *o| {
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        const raw = item.data orelse "";
        const withheld = try withheldBy(ctx.arena, active, raw);
        const values = try headerFieldValues(ctx.arena, try headers.parse(ctx.arena, raw), field, withheld);
        var size: usize = 0;
        for (values) |v| size += limit.jsonLen(v);
        o.* = if (admitItem(&budget, size, withheld)) values else &.{limit.omitted_text};
    }
    return ctx.json(out);
}

fn bodies(ctx: *Ctx, kind: body.Kind) Failure![]const u8 {
    const idx = try ctx.account();
    if (ctx.registry.filtersFor(idx).len > 0) return filteredBodies(ctx, idx, kind);
    const r = try fetchAligned(ctx, .{ .body = true });
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    const out = try ctx.arena.alloc(?[]const u8, r.items.len);
    for (r.items, out) |maybe, *o| {
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        o.* = try renderBudgeted(ctx, item, kind, &budget);
    }
    return ctx.json(out);
}

/// Sanitized body text, or the omission marker once the response budget is
/// spent (sanitization spec §5.2).
fn renderBudgeted(ctx: *Ctx, item: *const Fetched, kind: body.Kind, budget: *limit.Budget) Failure![]const u8 {
    if (budget.exhausted) return limit.omitted_text;
    const rendered = body.render(ctx.arena, item.data orelse "", kind, ctx.registry.settings.max_body_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return ctx.failed("UID {d}: message could not be parsed as MIME", .{item.uid}),
    };
    return if (budget.admit(limit.jsonLen(rendered))) rendered else limit.omitted_text;
}

/// get_text/get_html with active filters: headers first, classify, then fetch
/// bodies only for messages no filter withholds (ADR 0017).
fn filteredBodies(ctx: *Ctx, idx: usize, kind: body.Kind) Failure![]const u8 {
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: FilteredBodiesOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = uids },
        .active = ctx.registry.filtersFor(idx),
    };
    try ctx.imapRun(idx, &op);
    const items = try alignToUids(ctx.arena, uids, op.bodies);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    const out = try ctx.arena.alloc(?[]const u8, uids.len);
    for (uids, items, out) |u, maybe, *o| {
        if (op.withheld.get(u)) |name| {
            o.* = try filter.marker(ctx.arena, name);
            continue;
        }
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        o.* = try renderBudgeted(ctx, item, kind, &budget);
    }
    return ctx.json(out);
}

fn writeAttachments(jw: *Stringify, atts: []const attachments.Attachment) Stringify.Error!void {
    try jw.beginArray();
    for (atts) |att| try jw.write(.{
        .filename = att.filename,
        .content_type = att.content_type,
        .size = att.size,
        .@"inline" = att.inline_,
    });
    try jw.endArray();
}

fn attachmentsJson(arena: Allocator, atts: []const attachments.Attachment) Allocator.Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    writeAttachments(&jw, atts) catch return error.OutOfMemory;
    return aw.written();
}

fn listAttachments(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: AttachmentsOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = uids },
        .active = ctx.registry.filtersFor(idx),
    };
    try ctx.imapRun(idx, &op);

    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    jw.beginArray() catch return error.OutOfMemory;
    for (uids) |u| {
        if (op.withheld.get(u)) |name| {
            jw.write(try filter.marker(ctx.arena, name)) catch return error.OutOfMemory;
            continue;
        }
        var leaves: std.ArrayList(attachments.Part) = .empty;
        for (op.parts) |p| if (p.uid == u) try leaves.append(ctx.arena, .{
            .content_type = p.content_type,
            .disposition = p.disposition,
            .params = p.params,
            .disp_params = p.disp_params,
            .size = p.size,
            .base64 = p.base64,
        });
        if (leaves.items.len == 0) {
            jw.write(null) catch return error.OutOfMemory; // no such message
            continue;
        }
        const atts = try attachments.select(ctx.arena, leaves.items);
        var size: usize = 0;
        for (atts) |att| size += limit.jsonLen(att.filename) + limit.jsonLen(att.content_type) + 64;
        if (admitItem(&budget, size, null)) {
            writeAttachments(&jw, atts) catch return error.OutOfMemory;
        } else {
            jw.write(limit.omitted_text) catch return error.OutOfMemory;
        }
    }
    jw.endArray() catch return error.OutOfMemory;
    return aw.written();
}

fn getText(ctx: *Ctx) Failure![]const u8 {
    return bodies(ctx, .plain);
}

fn getHtml(ctx: *Ctx) Failure![]const u8 {
    return bodies(ctx, .html);
}

fn getSize(ctx: *Ctx) Failure![]const u8 {
    const items = (try fetchHeaders(ctx)).items;
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

/// A wire mailbox name as shown to the model (decoded, cleaned).
fn displayName(arena: Allocator, wire: []const u8) Allocator.Error![]const u8 {
    const decoded = mutf7.decode(arena, wire) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidMutf7 => try text.sanitizeUtf8(arena, wire),
    };
    return unicode.clean(arena, decoded);
}

fn createMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    try ctx.check(validate.mailboxName(try ctx.string("name"), null)); // delimiter rules need the list
    const boxes = try ctx.freshList(idx);
    const d = organize.delimiterOf(boxes, "");
    const name = try ctx.folderName("name", d);
    if (try organize.targetReason(ctx.arena, name.utf8, name.wire, null, d)) |r| return ctx.failed("{s}", .{r});
    if (organize.find(boxes, name.wire) != null) return ctx.failed("mailbox \"{s}\" already exists", .{name.utf8});
    var op: CreateOp = .{ .mailbox = name.wire };
    try ctx.imapRun(idx, &op);
    ctx.registry.mailboxesChanged(idx, ctx.arena);
    return ctx.json(.{ .created = name.utf8, .subscribed = op.subscribed });
}

fn renameMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    try ctx.check(validate.mailboxName(try ctx.string("new_name"), null));
    const boxes = try ctx.freshList(idx);
    const from = try ctx.mailbox("name", null);
    if (organize.find(boxes, from) == null) return ctx.failed("mailbox \"{s}\" does not exist", .{try displayName(ctx.arena, from)});
    if (try organize.protectedReason(ctx.arena, boxes, from)) |r| return ctx.failed("{s}", .{r});
    const d = organize.delimiterOf(boxes, from);
    const to = try ctx.folderName("new_name", d);
    if (try organize.targetReason(ctx.arena, to.utf8, to.wire, from, d)) |r| return ctx.failed("{s}", .{r});
    if (organize.find(boxes, to.wire) != null) return ctx.failed("mailbox \"{s}\" already exists", .{to.utf8});

    var children: std.ArrayList([2][:0]const u8) = .empty;
    for (boxes) |b| {
        if (!organize.isBelow(b.name, from, d)) continue;
        try children.append(ctx.arena, .{
            try ctx.arena.dupeSentinel(u8, b.name, 0),
            try ctx.arena.printSentinel("{s}{s}", .{ to.wire, b.name[from.len..] }, 0),
        });
    }
    var op: RenameOp = .{ .from = from, .to = to.wire, .children = children.items };
    try ctx.imapRun(idx, &op);
    ctx.registry.mailboxesChanged(idx, ctx.arena);
    const note: ?[]const u8 = if (op.subscribe_failures > 0)
        try ctx.arena.print("could not subscribe {d} renamed folder(s); mail clients that show only subscribed folders may hide them", .{op.subscribe_failures})
    else
        null;
    return ctx.json(.{ .renamed = try displayName(ctx.arena, from), .to = to.utf8, .note = note });
}

fn deleteMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    const boxes = try ctx.freshList(idx);
    const name = try ctx.mailbox("name", null);
    const shown = try displayName(ctx.arena, name);
    const box = organize.find(boxes, name) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{shown});
    if (try organize.protectedReason(ctx.arena, boxes, name)) |r| return ctx.failed("{s}", .{r});
    const d = organize.delimiterOf(boxes, name);
    var subfolders: usize = 0;
    for (boxes) |b| {
        if (organize.isBelow(b.name, name, d)) subfolders += 1;
    }
    var op: DeleteOp = .{ .mailbox = name, .selectable = organize.selectable(box), .subfolders = subfolders };
    try ctx.imapRun(idx, &op);
    if (op.refused) return ctx.failed("\"{s}\" is not empty ({d} messages, {d} subfolders); move or delete its contents first", .{ shown, op.messages, subfolders });
    ctx.registry.mailboxesChanged(idx, ctx.arena);
    const note: ?[]const u8 = if (op.unsubscribed) null else "the folder was deleted but could not be unsubscribed";
    return ctx.json(.{ .deleted = shown, .note = note });
}

fn moveMessages(ctx: *Ctx) Failure![]const u8 {
    return transfer(ctx, true);
}

fn copyMessages(ctx: *Ctx) Failure![]const u8 {
    return transfer(ctx, false);
}

const UidPairJson = struct { from: []const u8, to: []const u8 };

/// move_messages / copy_messages (spec §2, §4.2).
fn transfer(ctx: *Ctx, move: bool) Failure![]const u8 {
    const idx = try ctx.account();
    const has_uids = ctx.get("uids") != null;
    const has_criteria = ctx.get("criteria") != null;
    if (organize.selectionProblem(has_uids, has_criteria)) |p| return ctx.invalid("{s}", .{p});
    var given: ?[]const u32 = null;
    var command: [:0]const u8 = "";
    if (has_uids) {
        const u = try ctx.uids();
        if (u.len > organize.max_messages) return ctx.invalid("at most {d} messages per call; got {d} uids", .{ organize.max_messages, u.len });
        given = u;
    } else {
        const criteria = try ctx.string("criteria");
        try ctx.check(validate.criteria(criteria));
        command = try ctx.arena.printSentinel("CHARSET UTF-8 {s}", .{criteria}, 0);
    }
    const dry_run = try ctx.booleanOr("dry_run", has_criteria);
    const create_missing = try ctx.booleanOr("create_missing", false);
    const dest_utf8 = try ctx.string("destination");
    try ctx.check(validate.mailbox(dest_utf8));
    if (!dry_run) try ctx.writable(idx);

    const boxes = try ctx.freshList(idx);
    const source = try ctx.mailbox("directory", null);
    const destination = try ctx.mailbox("destination", null);
    if (std.mem.eql(u8, source, destination)) return ctx.invalid("destination must differ from directory", .{});
    const source_shown = try displayName(ctx.arena, source);
    const src_box = organize.find(boxes, source) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{source_shown});
    if (!organize.selectable(src_box)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{source_shown});
    const dest_box = organize.find(boxes, destination);
    var note: ?[]const u8 = organize.destinationNote(dest_box);
    if (dest_box) |b| {
        if (!organize.selectable(b)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{dest_utf8});
    } else {
        if (!create_missing) return ctx.failed("mailbox \"{s}\" does not exist; create it with create_mailbox (or pass create_missing=true)", .{dest_utf8});
        const d = organize.delimiterOf(boxes, destination);
        try ctx.check(validate.mailboxName(dest_utf8, d));
        if (try organize.targetReason(ctx.arena, dest_utf8, destination, null, d)) |r| return ctx.failed("{s}", .{r});
        if (dry_run) note = "the destination does not exist yet; it will be created";
    }
    const dest_shown = if (dest_box != null) try displayName(ctx.arena, destination) else dest_utf8;

    var op: TransferOp = .{
        .arena = ctx.arena,
        .source = source,
        .destination = destination,
        .move = move,
        .dry_run = dry_run,
        .create_destination = dest_box == null,
        .uids = given,
        .command = command,
    };
    ctx.registry.run(idx, &op) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const d = ctx.registry.diag();
        const why = if (d.len > 0) d else @errorName(err);
        const msg = if (op.copied_not_removed)
            try ctx.arena.print("messages were copied to \"{s}\" but not removed from \"{s}\": {s}", .{ dest_shown, source_shown, why })
        else if (op.done > 0)
            try ctx.arena.print("{d} of {d} messages were {s} before the error: {s}", .{ op.done, op.matched.len, if (move) "moved" else "copied", why })
        else
            try ctx.arena.dupe(u8, why);
        if (op.created) ctx.registry.mailboxesChanged(idx, ctx.arena);
        if (move and op.done > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.matched[0..op.done]);
        return ctx.failed("{s}", .{msg});
    };
    if (op.refused) |r| return ctx.failed("{s}", .{r});
    if (op.matched.len > organize.max_messages and !dry_run)
        return ctx.failed("{d} messages match; at most {d} per call. Narrow the criteria or split the work.", .{ op.matched.len, organize.max_messages });
    if (op.created) ctx.registry.mailboxesChanged(idx, ctx.arena);
    if (move and op.done > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.matched[0..op.done]);

    if (dry_run) {
        const preview = op.matched[0..@min(op.matched.len, organize.dry_run_preview)];
        const strs = try ctx.arena.alloc([]const u8, preview.len);
        for (preview, strs) |u, *o| o.* = try ctx.arena.print("{d}", .{u});
        return ctx.json(.{ .dry_run = true, .matched = op.matched.len, .uids = strs, .source = source_shown, .destination = dest_shown, .note = note });
    }
    var uid_map: ?[]UidPairJson = null;
    if (op.map_complete and op.pairs.items.len > 0) {
        const m = try ctx.arena.alloc(UidPairJson, op.pairs.items.len);
        for (op.pairs.items, m) |pair, *o| o.* = .{ .from = try ctx.arena.print("{d}", .{pair.from}), .to = try ctx.arena.print("{d}", .{pair.to}) };
        uid_map = m;
    }
    if (move) return ctx.json(.{ .moved = op.done, .source = source_shown, .destination = dest_shown, .uid_map = uid_map, .note = note });
    return ctx.json(.{ .copied = op.done, .source = source_shown, .destination = dest_shown, .uid_map = uid_map, .note = note });
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
        try self.afterExamine(s, try s.examine(self.mailbox));
    }

    /// The mailbox is already open; serve from cache, fetch the rest.
    fn afterExamine(self: *CachedHeadersOp, s: *Session, uidvalidity: u32) accounts.Error!void {
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

        // Cached headers outlive expunged messages: confirm the hits still
        // exist (one UID SEARCH) and forget the ones that are gone.
        var gone: []const u32 = &.{};
        if (cached.len > 0) {
            var set: std.ArrayList(u8) = .empty;
            try set.appendSlice(self.arena, "UID ");
            for (cached, 0..) |c, i| try set.print(self.arena, "{s}{d}", .{ if (i > 0) "," else "", c.uid });
            const existing = try s.uidSearch(self.arena, try self.arena.dupeSentinel(u8, set.items, 0));
            const pruned = try pruneCached(self.arena, cached, existing);
            if (pruned.gone.len > 0) if (store) |st|
                st.deleteMessages(self.mailbox, uidvalidity, pruned.gone) catch |e| self.registry.cacheFailed(self.idx, e);
            cached = pruned.kept;
            gone = pruned.gone;
        }

        var missing: std.ArrayList(u32) = .empty;
        for (self.uids) |u| {
            for (cached) |c| {
                if (c.uid == u) break;
            } else for (gone) |g| {
                if (g == u) break; // known expunged: do not refetch
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

const FilteredBodiesOp = struct {
    arena: Allocator,
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    bodies: []Fetched = &.{},
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,

    pub fn run(self: *FilteredBodiesOp, s: *Session) accounts.Error!void {
        // A retry after reconnect starts from scratch.
        self.withheld.clearRetainingCapacity();
        self.bodies = &.{};
        try self.headers.afterExamine(s, try s.examine(self.headers.mailbox));
        const allowed = try classifyForBodies(self.arena, self.active, self.headers.uids, self.headers.result, &self.withheld);
        if (allowed.len > 0)
            self.bodies = try s.uidFetch(self.arena, allowed, .{ .body = true });
    }
};

/// Fail closed: a UID is allowed only if its merged header data was seen and
/// no active filter matches it. Withheld UIDs are recorded in `withheld`.
fn classifyForBodies(
    arena: Allocator,
    active: []const *const filter.Filter,
    uids: []const u32,
    header_results: []const Fetched,
    withheld: *std.AutoHashMapUnmanaged(u32, []const u8),
) Allocator.Error![]const u32 {
    const merged = try alignToUids(arena, uids, header_results);
    var allowed: std.ArrayList(u32) = .empty;
    for (uids, merged) |u, maybe| {
        const item = maybe orelse continue; // no such message
        const data = item.data orelse continue; // headers never arrived: do not fetch
        if (withheld.contains(u)) continue;
        if (try withheldBy(arena, active, data)) |name| {
            try withheld.put(arena, u, name);
        } else {
            for (allowed.items) |x| {
                if (x == u) break;
            } else try allowed.append(arena, u);
        }
    }
    return allowed.items;
}

/// list_attachments: classify by headers first when filters are active (fail
/// closed), then BODYSTRUCTURE for the allowed UIDs only.
const AttachmentsOp = struct {
    arena: Allocator,
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    parts: []imap.BodyPart = &.{},
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,

    pub fn run(self: *AttachmentsOp, s: *Session) accounts.Error!void {
        self.withheld.clearRetainingCapacity();
        self.parts = &.{};
        const uidvalidity = try s.examine(self.headers.mailbox);
        const allowed: []const u32 = if (self.active.len == 0) self.headers.uids else blk: {
            try self.headers.afterExamine(s, uidvalidity);
            break :blk try classifyForBodies(self.arena, self.active, self.headers.uids, self.headers.result, &self.withheld);
        };
        if (allowed.len > 0) self.parts = try s.uidBodyParts(self.arena, allowed);
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

    // APPEND is not idempotent: retrying after a lost connection could save
    // the draft twice.
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while saving the draft; it may or may not have been saved. Check the Drafts folder before retrying.";

    pub fn run(self: *AppendOp, s: *Session) accounts.Error!void {
        try s.append(self.mailbox, self.data);
        self.response = s.lastResponse();
    }
};

/// A SUBSCRIBE-style call whose refusal must not fail the tool (spec §4.4):
/// true on success, false if the server said NO/BAD.
fn bestEffort(result: accounts.Error!void) accounts.Error!bool {
    result catch |err| switch (err) {
        error.ServerRejected => return false,
        else => return err,
    };
    return true;
}

const CreateOp = struct {
    mailbox: [:0]const u8,
    subscribed: bool = false,

    // Not retried: a resent CREATE fails with "already exists" (ADR 0021).
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while creating the mailbox; it may or may not exist now. Check with list_mailboxes (refresh=true) before retrying.";

    pub fn run(self: *CreateOp, s: *Session) accounts.Error!void {
        try s.create(self.mailbox);
        self.subscribed = try bestEffort(s.subscribe(self.mailbox));
    }
};

const RenameOp = struct {
    from: [:0]const u8,
    to: [:0]const u8,
    /// Subfolders (old, new wire names); their subscriptions follow.
    children: []const [2][:0]const u8,
    subscribe_failures: usize = 0,

    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while renaming the mailbox; it may or may not have been renamed. Check with list_mailboxes (refresh=true) before retrying.";

    pub fn run(self: *RenameOp, s: *Session) accounts.Error!void {
        try s.rename(self.from, self.to);
        try self.follow(s, self.from, self.to);
        for (self.children) |c| try self.follow(s, c[0], c[1]);
    }

    fn follow(self: *RenameOp, s: *Session, old: [:0]const u8, new: [:0]const u8) accounts.Error!void {
        _ = try bestEffort(s.unsubscribe(old)); // often not subscribed: ignore
        if (!try bestEffort(s.subscribe(new))) self.subscribe_failures += 1;
    }
};

const DeleteOp = struct {
    mailbox: [:0]const u8,
    selectable: bool,
    subfolders: usize,
    messages: u32 = 0,
    refused: bool = false,
    unsubscribed: bool = false,

    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while deleting the mailbox; it may or may not have been deleted. Check with list_mailboxes (refresh=true) before retrying.";

    pub fn run(self: *DeleteOp, s: *Session) accounts.Error!void {
        if (self.selectable) self.messages = (try s.status(self.mailbox)).messages;
        if (self.messages > 0 or self.subfolders > 0) {
            self.refused = true;
            return;
        }
        try s.delete(self.mailbox);
        self.unsubscribed = try bestEffort(s.unsubscribe(self.mailbox));
    }
};

const unsupported_move = "the server supports neither MOVE nor UIDPLUS, so messages cannot be moved safely; use copy_messages and remove the originals in your mail client";

const TransferOp = struct {
    arena: Allocator,
    source: [:0]const u8,
    destination: [:0]const u8,
    move: bool,
    dry_run: bool,
    create_destination: bool,
    /// Given UIDs, or null to select by `command` (UID SEARCH arguments).
    uids: ?[]const u32,
    command: [:0]const u8,

    matched: []const u32 = &.{},
    uidvalidity: u32 = 0,
    refused: ?[]const u8 = null,
    created: bool = false,
    /// Messages moved/copied so far (a prefix of `matched`).
    done: usize = 0,
    /// The copy+expunge fallback copied a batch but failed to remove it.
    copied_not_removed: bool = false,
    pairs: std.ArrayList(organize.UidPair) = .empty,
    map_complete: bool = true,

    // Not retried: a resent COPY duplicates messages (ADR 0021).
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while moving or copying messages; some may have been moved or copied. Check with search before retrying.";

    pub fn run(self: *TransferOp, s: *Session) accounts.Error!void {
        const acting = !self.dry_run;
        const strategy: organize.MoveStrategy = if (self.move and acting) organize.moveStrategy(try s.capabilities()) else .move;
        if (strategy == .unsupported) {
            self.refused = unsupported_move;
            return;
        }
        self.uidvalidity = if (self.move and acting) try s.select(self.source) else try s.examine(self.source);
        self.matched = if (self.uids) |given| try existingUids(self.arena, s, given) else blk: {
            const found = try s.uidSearch(self.arena, self.command);
            std.mem.sort(u32, found, {}, std.sort.asc(u32));
            break :blk found;
        };
        if (!acting or self.matched.len > organize.max_messages) return;
        if (self.create_destination) {
            try s.create(self.destination);
            self.created = true;
            _ = try bestEffort(s.subscribe(self.destination));
        }
        for (0..organize.batchCount(self.matched.len)) |i| {
            const b = organize.batch(self.matched, i);
            const cu = try s.uidTransfer(self.arena, b, self.destination, self.move and strategy == .move);
            if (self.move and strategy == .copy_expunge) {
                s.uidStoreFlags(self.arena, b, true, &.{"\\Deleted"}) catch |err| {
                    self.copied_not_removed = true;
                    return err;
                };
                s.uidExpunge(b) catch |err| {
                    self.copied_not_removed = true;
                    return err;
                };
            }
            self.done += b.len;
            if (try organize.uidMap(self.arena, cu)) |m| try self.pairs.appendSlice(self.arena, m) else self.map_complete = false;
        }
    }
};

/// The given UIDs that exist in the selected mailbox, in input order without
/// duplicates (so counts and UID maps describe real messages).
fn existingUids(arena: Allocator, s: *Session, given: []const u32) accounts.Error![]const u32 {
    var present: std.AutoHashMapUnmanaged(u32, void) = .empty;
    for (0..organize.batchCount(given.len)) |i| {
        for (try s.uidFetch(arena, organize.batch(given, i), .{ .size = true })) |f| try present.put(arena, f.uid, {});
    }
    return keepPresent(arena, given, &present);
}

fn keepPresent(arena: Allocator, given: []const u32, present: *const std.AutoHashMapUnmanaged(u32, void)) Allocator.Error![]const u32 {
    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    var out: std.ArrayList(u32) = .empty;
    for (given) |u| {
        if (!present.contains(u)) continue;
        if ((try seen.getOrPut(arena, u)).found_existing) continue;
        try out.append(arena, u);
    }
    return out.items;
}

/// Response-budget decision for one item; withheld entries are always kept
/// (sanitization spec §5.2).
fn admitItem(budget: *limit.Budget, size: usize, withheld: ?[]const u8) bool {
    if (withheld != null) return true;
    return budget.admit(size);
}

/// True for header names in this server's own `x-tp-imap-mcp-` namespace.
fn isOwnMarker(name: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(name, "x-tp-imap-mcp-");
}

/// Wire name for a `directory` argument: the encoded input when a mailbox has
/// exactly that name; otherwise a mailbox whose decoded name, after
/// invisible-character cleaning, equals the input (what list_mailboxes
/// showed); otherwise the encoded input unchanged.
fn resolveMailbox(arena: Allocator, boxes: []const imap.Mailbox, utf8: []const u8, encoded: []const u8) Allocator.Error![]const u8 {
    for (boxes) |b| if (std.mem.eql(u8, b.name, encoded)) return encoded;
    for (boxes) |b| {
        const decoded = mutf7.decode(arena, b.name) catch continue;
        if (std.mem.eql(u8, try unicode.clean(arena, decoded), utf8)) return b.name;
    }
    return encoded;
}

/// Splits cached entries into those the server still has and the UIDs gone.
fn pruneCached(arena: Allocator, cached: []const Fetched, existing: []const u32) Allocator.Error!struct { kept: []Fetched, gone: []u32 } {
    var kept: std.ArrayList(Fetched) = .empty;
    var gone: std.ArrayList(u32) = .empty;
    for (cached) |c| {
        if (std.mem.findScalar(u32, existing, c.uid) != null) {
            try kept.append(arena, c);
        } else {
            try gone.append(arena, c.uid);
        }
    }
    return .{ .kept = kept.items, .gone = gone.items };
}

/// One entry per input UID (duplicates repeat), null where the server
/// returned nothing for that UID. Several FETCH responses for one UID (e.g.
/// an unsolicited flag update next to the real one) are merged field by field.
pub fn alignToUids(arena: Allocator, uids: []const u32, fetched: []const Fetched) Allocator.Error![]?*const Fetched {
    var by_uid: std.AutoHashMapUnmanaged(u32, *Fetched) = .empty;
    for (fetched) |f| {
        const slot = try by_uid.getOrPut(arena, f.uid);
        if (!slot.found_existing) {
            slot.value_ptr.* = try arena.create(Fetched);
            slot.value_ptr.*.* = f;
            continue;
        }
        const merged = slot.value_ptr.*;
        if (merged.data == null) merged.data = f.data;
        if (merged.flags == null) merged.flags = f.flags;
        if (merged.size == 0) merged.size = f.size;
    }
    const out = try arena.alloc(?*const Fetched, uids.len);
    for (uids, out) |u, *o| o.* = by_uid.get(u);
    return out;
}
```
- [ ] **Step 6: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `180/180 tests passed`.

- [ ] **Step 7: Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is ready and suggest the message: `feat(organize): create/rename/delete folders, move/copy messages`

---

### Task 6: Live checks and documentation

**Files:**
- Modify: `src/itest.zig`, `README.md`, `docs/adr/0010-write-tools-with-read-only-switch.md`, `docs/adr/README.md`
- Create: `docs/adr/0021-mailbox-organization-tools.md`

**Interfaces:**
- Consumes: the five tools; `Registry.mailboxesChanged`; `Session.uidStoreFlags/uidExpunge/delete` for cleanup.
- Produces: `zig build itest -- <account> --organize` (14 checks on folders named `tp-imap-mcp-itest-<random>`, always cleaned up); ADR 0021; README sections.

- [ ] **Step 1: Write `src/itest.zig`**

Replace (or create) the whole file:

```zig
//! Live integration checks against a real IMAP account (spec §9).
//!
//!   op run --env-file imap.env -- zig build itest -- <account> [--write <scratch-mailbox>] [--organize]
//!
//! Read-only by default. Prints only counts and shapes, never message content.
//! Uses a throwaway cache in .zig-cache/itest-cache, never ~/.cache.
//! `--write` adds then removes the keyword $TpImapMcpTest on the newest
//! message of <scratch-mailbox>; use a folder you do not care about.
//! `--organize` exercises the folder and move/copy tools (ADR 0021) on
//! folders it creates (tp-imap-mcp-itest-<random>) and removes them again.

const std = @import("std");
const config = @import("config.zig");
const tools = @import("tools.zig");
const c = @import("imap/c.zig");
const Registry = @import("accounts.zig").Registry;
const filter = @import("filter/rules.zig");
const unicode = @import("sanitize/unicode.zig");
const organize = @import("organize.zig");
const Session = @import("imap/session.zig").Session;

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
        std.debug.print("usage: itest <account> [--write <scratch-mailbox>] [--organize]\n", .{});
        return 2;
    }
    const account = args[1];
    var write_box: ?[]const u8 = null;
    var organize_checks = false;
    var ai: usize = 2;
    while (ai < args.len) : (ai += 1) {
        if (std.mem.eql(u8, args[ai], "--write") and ai + 1 < args.len) {
            ai += 1;
            write_box = args[ai];
        } else if (std.mem.eql(u8, args[ai], "--organize")) {
            organize_checks = true;
        } else {
            std.debug.print("unknown argument {s}\n", .{args[ai]});
            return 2;
        }
    }

    var diag_buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&diag_buf);
    const accounts = config.load(arena, init.environ_map, &diag) catch |err| {
        std.debug.print("config: {s} ({t})\n", .{ diag.buffered(), err });
        return 2;
    };
    var settings = config.loadSettings(arena, init.environ_map, &diag) catch |err| {
        std.debug.print("config: {s} ({t})\n", .{ diag.buffered(), err });
        return 2;
    };
    settings.cache_dir = ".zig-cache/itest-cache"; // never touch ~/.cache
    settings.mailbox_ttl = 3600;
    const no_filters = try arena.alloc([]const *const filter.Filter, accounts.len);
    @memset(no_filters, &.{});
    var reg: Registry = try .init(init.gpa, init.io, accounts, settings, no_filters);
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

        try sanitizeChecks(h, acct, uids);
        try attachmentChecks(h, acct, uids, "newest");
        // The newest messages may have no attachments: also check large
        // messages (> 400 KB), which usually do.
        const large = try h.call("search", "{{\"account\":{s},\"directory\":\"INBOX\",\"criteria\":\"LARGER 400000\"}}", .{acct});
        if (large) |m| if (m.array.items.len > 0) try attachmentChecks(h, acct, m.array.items, "large");
        try filterChecks(h, &reg, idx, acct, set);
    }

    if (write_box) |box| try writeChecks(h, acct, box);
    if (organize_checks) try organizeChecks(h, &reg, idx, acct, init.io);

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

/// ADR 0017: with a filter matching every message, bodies and non-visible
/// headers must be withheld; with no filters, content comes back.
fn filterChecks(h: Harness, reg: *Registry, idx: usize, acct: []const u8, set: []const u8) !void {
    const everything: filter.Filter = .{ .name = "everything", .rules = &.{.{ .conditions = &.{.{ .field = "date", .matcher = .{ .glob = &.{"*"} } }} }} };
    const one = [_]*const filter.Filter{&everything};
    const per_account = try h.arena.alloc([]const *const filter.Filter, reg.accounts.len);
    @memset(per_account, &.{});
    per_account[idx] = &one;
    const original = reg.active_filters;
    reg.active_filters = per_account;
    defer reg.active_filters = original;

    const marker = "[withheld by filter \"everything\"]";
    for ([_][]const u8{ "get_text", "get_html" }) |tool| {
        const r = try h.call(tool, "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
        const items = if (r) |v| v.array.items else &.{};
        const ok = items.len == 3 and items[0] == .string and std.mem.eql(u8, items[0].string, marker) and
            items[1] == .null and items[2] == .string and std.mem.eql(u8, items[2].string, marker);
        report(ok, "filter: {s} withholds matched messages", .{tool});
    }
    const att = try h.call("list_attachments", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
    const ok_att = att != null and att.?.array.items.len == 3 and att.?.array.items[0] == .string and
        std.mem.eql(u8, att.?.array.items[0].string, marker) and att.?.array.items[1] == .null;
    report(ok_att, "filter: list_attachments withholds matched messages", .{});

    const hdr = try h.call("get_header", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
    const ok_hdr = blk: {
        const obj = (hdr orelse break :blk false).array.items[0].object;
        if (obj.get("x-tp-imap-mcp-withheld") == null) break :blk false;
        for (obj.keys()) |k| if (!std.mem.eql(u8, k, "date") and !std.mem.eql(u8, k, "from") and !std.mem.eql(u8, k, "x-tp-imap-mcp-withheld")) break :blk false;
        break :blk true;
    };
    report(ok_hdr, "filter: get_header shows only date/from plus marker", .{});

    reg.active_filters = original;
    const plain = try h.call("get_text", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
    const ok_plain = plain != null and plain.?.array.items[0] == .string and !std.mem.startsWith(u8, plain.?.array.items[0].string, "[withheld");
    report(ok_plain, "filter: no active filters returns content", .{});
}

/// ADR 0018: bodies of the newest messages contain no invisible characters,
/// and HTML-converted output (get_html) contains no markup. get_text may
/// legitimately contain `<tag` text: senders sometimes put raw HTML inside
/// the text/plain alternative, which is returned verbatim as inert text.
fn sanitizeChecks(h: Harness, acct: []const u8, uids: []const std.json.Value) !void {
    const n = @min(uids.len, 10);
    var list: std.ArrayList(u8) = .empty;
    try list.append(h.arena, '[');
    for (uids[uids.len - n ..], 0..) |u, i| {
        if (i > 0) try list.append(h.arena, ',');
        try list.print(h.arena, "\"{s}\"", .{u.string});
    }
    try list.append(h.arena, ']');
    for ([_][]const u8{ "get_text", "get_html" }) |tool| {
        const r = try h.call(tool, "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, list.items });
        var ok = r != null;
        var checked: usize = 0;
        if (r) |v| for (v.array.items) |item| {
            if (item != .string) continue;
            const body = item.string;
            checked += 1;
            if (std.mem.eql(u8, tool, "get_html") and containsHtmlTag(body)) ok = false;
            if ((try unicode.clean(h.arena, body)).ptr != body.ptr) ok = false;
        };
        report(ok, "sanitize: {s} on {d} messages has no invisible characters{s}", .{ tool, checked, if (std.mem.eql(u8, tool, "get_html")) " or markup" else "" });
    }
}

/// `<tag` followed by whitespace, `>` or `/`, for common HTML element names.
/// (A bare `<letter` is legitimate in plain text, e.g. `John <john@x.org>`.)
fn containsHtmlTag(body: []const u8) bool {
    const tags = [_][]const u8{ "html", "body", "head", "div", "span", "p", "a", "br", "table", "tr", "td", "img", "script", "style", "font", "center", "ul", "li" };
    var i: usize = 0;
    while (std.mem.findScalarPos(u8, body, i, '<')) |at| : (i = at + 1) {
        const rest = body[at + 1 ..];
        for (tags) |t| {
            if (rest.len > t.len and std.ascii.startsWithIgnoreCase(rest, t)) {
                const next = rest[t.len];
                if (next == '>' or next == '/' or std.ascii.isWhitespace(next)) return true;
            }
        }
    }
    return false;
}

/// list_attachments on the newest messages: one entry per UID, each a list
/// of well-formed, sanitized attachment records. Prints counts only.
fn attachmentChecks(h: Harness, acct: []const u8, uids: []const std.json.Value, label: []const u8) !void {
    const n = @min(uids.len, 10);
    var list: std.ArrayList(u8) = .empty;
    try list.append(h.arena, '[');
    for (uids[uids.len - n ..], 0..) |u, i| {
        if (i > 0) try list.append(h.arena, ',');
        try list.print(h.arena, "\"{s}\"", .{u.string});
    }
    try list.appendSlice(h.arena, ",\"4294967295\"]");
    const r = try h.call("list_attachments", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, list.items });
    var ok = r != null and r.?.array.items.len == n + 1 and r.?.array.items[n] == .null;
    var total: usize = 0;
    if (r) |v| for (v.array.items[0..@min(n, v.array.items.len)]) |item| {
        if (item != .array) {
            ok = false;
            continue;
        }
        for (item.array.items) |a| {
            total += 1;
            const o = a.object;
            const name = (o.get("filename") orelse {
                ok = false;
                continue;
            }).string;
            if (name.len == 0 or name.len > 255 or std.mem.findAny(u8, name, "/\\") != null) ok = false;
            if ((try unicode.clean(h.arena, name)).ptr != name.ptr) ok = false;
            if (o.get("content_type") == null or o.get("size") == null or o.get("inline") == null) ok = false;
        }
    };
    report(ok, "list_attachments on {d} {s} messages: {d} attachments, well-formed and sanitized; null for missing uid", .{ n, label, total });
}

const AppendTo = struct {
    mailbox: [:0]const u8,
    data: []const u8,

    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while appending the itest message";

    pub fn run(self: *AppendTo, s: *Session) !void {
        try s.append(self.mailbox, self.data);
    }
};

/// Best-effort removal of the itest folders and their messages, through the
/// session layer (flag \Deleted + UID EXPUNGE, then DELETE). `boxes` lists
/// children before parents.
const Cleanup = struct {
    arena: std.mem.Allocator,
    boxes: []const [:0]const u8,

    pub fn run(self: *Cleanup, s: *Session) !void {
        for (self.boxes) |b| {
            _ = s.select(b) catch continue;
            const uids = s.uidSearch(self.arena, "ALL") catch continue;
            if (uids.len == 0) continue;
            s.uidStoreFlags(self.arena, uids, true, &.{"\\Deleted"}) catch continue;
            s.uidExpunge(uids) catch {};
        }
        _ = s.examine("INBOX") catch {}; // leave the folder before deleting it
        for (self.boxes) |b| {
            s.delete(b) catch {};
            s.unsubscribe(b) catch {};
        }
    }
};

fn intField(v: ?std.json.Value, key: []const u8) ?i64 {
    const o = v orelse return null;
    if (o != .object) return null;
    const f = o.object.get(key) orelse return null;
    return if (f == .integer) f.integer else null;
}

fn messagesIn(h: Harness, acct: []const u8, box: []const u8) !?i64 {
    const r = try h.call("mailboxes_status", "{{\"account\":{s},\"directory\":\"{s}\"}}", .{ acct, box });
    return intField(r, "MESSAGES");
}

/// ADR 0021 tools on folders this check creates; always cleans up.
fn organizeChecks(h: Harness, reg: *Registry, idx: usize, acct: []const u8, io: std.Io) !void {
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    const a = try h.arena.print("tp-imap-mcp-itest-{x}", .{rnd});
    const b = try h.arena.print("{s}-b", .{a});
    const tag = try h.arena.print("tp-imap-mcp organize itest {x}", .{rnd});
    const delim = organize.delimiterOf(try reg.mailboxList(idx, h.arena, false), "") orelse '/';
    const ab = try h.arena.print("{s}{c}{s}", .{ a, delim, b });
    var cleanup: Cleanup = .{ .arena = h.arena, .boxes = &.{
        try h.arena.dupeSentinel(u8, ab, 0),
        try h.arena.dupeSentinel(u8, b, 0),
        try h.arena.dupeSentinel(u8, a, 0),
    } };
    defer {
        reg.run(idx, &cleanup) catch {};
        reg.mailboxesChanged(idx, h.arena);
        const left = h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"tp-imap-mcp-itest-*\",\"refresh\":true}}", .{acct}) catch null;
        var gone = left != null;
        if (left) |l| for (l.array.items) |m| {
            if (std.mem.startsWith(u8, m.object.get("PATH").?.string, a)) gone = false;
        };
        report(gone, "organize: test folders removed", .{});
    }

    const ca = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, a });
    const cb = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, b });
    report(ca != null and cb != null, "organize: create_mailbox x2", .{});
    const listed = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"{s}*\"}}", .{ acct, a });
    report(listed != null and listed.?.array.items.len == 2, "organize: both folders listed (cache refreshed)", .{});
    const dup = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, a });
    report(dup == null, "organize: creating an existing folder is refused", .{});

    const msg = try h.arena.print("From: itest@example.invalid\r\nTo: itest@example.invalid\r\nSubject: {s}\r\nDate: Thu, 08 Oct 2026 12:00:00 +0000\r\nMessage-ID: <{x}@tp-imap-mcp.invalid>\r\n\r\nTest message; safe to delete.\r\n", .{ tag, rnd });
    var append: AppendTo = .{ .mailbox = try h.arena.dupeSentinel(u8, a, 0), .data = msg };
    reg.run(idx, &append) catch {};
    const in_a = try h.call("search", "{{\"account\":{s},\"directory\":\"{s}\",\"criteria\":\"ALL\"}}", .{ acct, a });
    const uid = if (in_a) |v| (if (v.array.items.len == 1) v.array.items[0].string else null) else null;
    report(uid != null, "organize: test message appended", .{});
    if (uid == null) return;

    const copied = try h.call("copy_messages", "{{\"account\":{s},\"directory\":\"{s}\",\"destination\":\"{s}\",\"uids\":[\"{s}\"]}}", .{ acct, a, b, uid.? });
    const has_map = copied != null and copied.?.object.get("uid_map").? == .array;
    report(intField(copied, "copied") == 1 and has_map, "organize: copy_messages by uid, uid_map present", .{});
    report((try messagesIn(h, acct, b)) == 1 and (try messagesIn(h, acct, a)) == 1, "organize: copy keeps the original", .{});

    const crit = try h.arena.print("SUBJECT \\\"{s}\\\"", .{tag});
    const dry = try h.call("move_messages", "{{\"account\":{s},\"directory\":\"{s}\",\"destination\":\"{s}\",\"criteria\":\"{s}\"}}", .{ acct, b, a, crit });
    report(intField(dry, "matched") == 1 and (try messagesIn(h, acct, b)) == 1, "organize: move by criteria is a dry run by default", .{});
    const moved = try h.call("move_messages", "{{\"account\":{s},\"directory\":\"{s}\",\"destination\":\"{s}\",\"criteria\":\"{s}\",\"dry_run\":false}}", .{ acct, b, a, crit });
    report(intField(moved, "moved") == 1, "organize: move_messages dry_run=false moves", .{});
    report((try messagesIn(h, acct, b)) == 0 and (try messagesIn(h, acct, a)) == 2, "organize: source emptied, destination has both", .{});

    const renamed = try h.call("rename_mailbox", "{{\"account\":{s},\"name\":\"{s}\",\"new_name\":\"{s}\"}}", .{ acct, b, ab });
    report(renamed != null, "organize: rename_mailbox moves a folder under another", .{});
    const nonempty = try h.call("delete_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, a });
    report(nonempty == null, "organize: delete_mailbox refuses a non-empty folder", .{});
    const inbox = try h.call("rename_mailbox", "{{\"account\":{s},\"name\":\"INBOX\",\"new_name\":\"{s}-inbox\"}}", .{ acct, a });
    report(inbox == null, "organize: INBOX cannot be renamed", .{});
    const deleted = try h.call("delete_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, ab });
    report(deleted != null, "organize: delete_mailbox removes an empty folder", .{});
}
```
- [ ] **Step 2: Write `docs/adr/0021-mailbox-organization-tools.md`**

Replace (or create) the whole file:

```markdown
# 0021. Add folder and move/copy tools with safe moves, protected folders and dry runs

- Status: Accepted
- Date: 2026-10-08

## Context

The user wants the assistant to organize mail: create, rename/move and delete
folders, and move or copy messages. These are the first tools that remove
messages from a folder or remove folders, so a mistake costs more than with
`change_keywords` or `create_message` (ADR 0010).

- **Moving without MOVE.** RFC 6851 `MOVE` is atomic. Without it, a move is
  `COPY` + `STORE \Deleted` + `EXPUNGE`, but a plain `EXPUNGE` also purges
  every other message already flagged `\Deleted` in that folder. `UID
  EXPUNGE` (UIDPLUS, RFC 4315) limits it to the given UIDs. Options: refuse
  without MOVE; fall back with UID EXPUNGE; fall back with plain EXPUNGE.
- **Special folders.** Renaming or deleting INBOX, Sent, Drafts, Trash, or
  Gmail's `[Gmail]/` tree breaks mail clients and, on Gmail, is refused or
  behaves oddly. Moving messages into Trash or Junk is ordinary organizing,
  but those folders are purged automatically.
- **Bulk selection.** Moving by search criteria is fast, but a loose criterion
  can move thousands of messages the user never saw.
- **Retries.** The registry retries an operation once after a dropped
  connection (ADR 0006); a resent `COPY` duplicates messages and a resent
  `CREATE` reports a confusing error.

## Decision

- Five tools: `create_mailbox`, `rename_mailbox`, `delete_mailbox`,
  `move_messages`, `copy_messages`. All are refused on read-only accounts,
  except dry runs.
- Moves use `UID MOVE` when the server has MOVE; otherwise `UID COPY`,
  `UID STORE +FLAGS (\Deleted)` and `UID EXPUNGE` of exactly those UIDs when
  it has UIDPLUS; otherwise the tool refuses. Plain `EXPUNGE` is never sent.
- INBOX, folders with a special-use attribute (`\All \Archive \Drafts
  \Flagged \Junk \Sent \Trash \Important`) and folders containing one are
  never renamed or deleted; nothing is created or renamed into `[Gmail]/` or
  `[Google Mail]/`. Moving into Trash or Junk is allowed and the result
  carries a note.
- `delete_mailbox` only deletes empty folders without subfolders.
- Messages are selected by `uids` or `criteria`. Criteria default to a dry run
  that reports the match count and the first 100 UIDs; `dry_run=false` acts.
  At most 5000 messages per call; commands go out in batches of 500.
- A missing destination is an error unless `create_missing=true`.
- None of the five operations is retried after a lost connection; the error
  says the outcome is unknown and to check before retrying.
- Results include the COPYUID source→destination UID map when the server
  reports one.

## Consequences

- No silent loss of unrelated `\Deleted` messages; servers with neither MOVE
  nor UIDPLUS cannot move (copy still works).
- The assistant must confirm bulk moves with the user before acting, which
  costs one extra call per criteria-based move.
- Special folders cannot be reorganized through the tools even when the user
  wants to; that stays a mail-client task.
- After a dropped connection the assistant must re-check state instead of
  getting an automatic retry.
- Gmail semantics differ (folders are labels, All Mail keeps everything); the
  tool descriptions state them, but behavior there is verified manually.
```
- [ ] **Step 3: Edit `docs/adr/README.md`**

Replace every occurrence of

```markdown
| [0020](0020-xoauth2-with-refresh-tokens-in-1password.md) | Support XOAUTH2 with refresh tokens kept in 1Password | Accepted |
```

with

```markdown
| [0020](0020-xoauth2-with-refresh-tokens-in-1password.md) | Support XOAUTH2 with refresh tokens kept in 1Password | Accepted |
| [0021](0021-mailbox-organization-tools.md) | Add folder and move/copy tools with safe moves, protected folders and dry runs | Accepted |
```
- [ ] **Step 4: Edit `docs/adr/0010-write-tools-with-read-only-switch.md`**

Replace every occurrence of

```markdown
- `create_message` works across servers without per-server code.
```

with

```markdown
- `create_message` works across servers without per-server code.
- The folder and move/copy tools added later follow the same read-only
  switch; their own safeguards are in [ADR 0021](0021-mailbox-organization-tools.md).
```
- [ ] **Step 5: Edit `README.md`**

Replace every occurrence of

```markdown
| 👀 Read-only accounts | `IMAP_<NAME>_READONLY=1` refuses the two write tools; reads never mark mail as seen. |
```

with

```markdown
| 🗂️ Mail organization | Create, rename/move and delete folders; move or copy messages by UID or by search criteria, with dry runs and protected system folders. |
| 👀 Read-only accounts | `IMAP_<NAME>_READONLY=1` refuses every tool that changes the mailbox; reads never mark mail as seen. |
```
- [ ] **Step 6: Edit `README.md`**

Replace every occurrence of

````markdown
```bash
op run --env-file imap.env -- zig build itest -- work
# … 29 PASS lines …
# 0 failure(s)
```
````

with

````markdown
```bash
op run --env-file imap.env -- zig build itest -- work
# … 29 PASS lines …
# 0 failure(s)
```

`--organize` also checks the folder and move/copy tools. It creates two folders named `tp-imap-mcp-itest-<random>`, appends one test message, moves, copies and renames, and removes everything again (it never touches other folders):

```bash
op run --env-file imap.env -- zig build itest -- work --organize
```
````
- [ ] **Step 7: Edit `README.md`**

Replace every occurrence of

```markdown
- "Draft a reply to that message." *(creates a draft; it never sends mail)*
```

with

```markdown
- "Draft a reply to that message." *(creates a draft; it never sends mail)*
- "File every receipt from this year into Receipts/2026." *(not on read-only accounts)*
```
- [ ] **Step 8: Edit `README.md`**

Replace every occurrence of

```markdown
| `create_message` | Append a raw RFC 822 message to the Drafts folder |
```

with

```markdown
| `create_message` | Append a raw RFC 822 message to the Drafts folder |
| `create_mailbox` | Create a folder (and subscribe to it) |
| `rename_mailbox` | Rename a folder or move it under another parent |
| `delete_mailbox` | Delete an empty folder |
| `move_messages` / `copy_messages` | Move or copy messages by `uids` or by search `criteria`; criteria default to a dry run |
```
- [ ] **Step 9: Edit `README.md`**

Replace every occurrence of

```markdown
## 🔒 Security model
```

with

```markdown
### Organizing mail

The folder and move/copy tools ([ADR 0021](docs/adr/0021-mailbox-organization-tools.md)) follow a few rules:

- **Bulk moves are previewed.** With `criteria`, `move_messages` and `copy_messages` only report the match count and the first 100 UIDs, unless `dry_run=false` is passed. With `uids` they act immediately. At most 5000 messages per call.
- **Safe moves.** `MOVE` is used when the server supports it, otherwise `COPY` + `\Deleted` + `UID EXPUNGE` of exactly those messages. A server with neither MOVE nor UIDPLUS cannot move messages (copy still works).
- **Protected folders.** INBOX, special-use folders (Sent, Drafts, Trash, Junk/Spam, Archive, All Mail, …) and folders containing them are never renamed or deleted. Nothing is created inside Gmail's `[Gmail]/` tree. Messages *can* be moved to Trash or Spam; the result notes that those folders are purged automatically.
- **Only empty folders are deleted.** Move the messages and subfolders out first.
- **Missing destinations** are an error unless `create_missing=true`.
- **Gmail:** folders are labels. Moving out of INBOX archives the message and applies the label; copying adds a label; every message stays in `[Gmail]/All Mail`.

A typical exchange: *"Move all newsletters from news@example.com in INBOX to Newsletters"* → the assistant runs a dry run (`matched: 42`), shows you the count, then repeats the call with `dry_run=false`.

## 🔒 Security model
```
- [ ] **Step 10: Edit `README.md`**

Replace every occurrence of

```markdown
- **Read-only accounts:** write tools refuse before contacting the server.
```

with

```markdown
- **Read-only accounts:** write tools refuse before contacting the server (dry runs of `move_messages` / `copy_messages` are allowed).
- **Organizing:** see [Organizing mail](#organizing-mail): previews for bulk moves, no plain `EXPUNGE`, protected system folders, and no automatic retry of a folder or move/copy command after a dropped connection.
```
- [ ] **Step 11: Edit `README.md`**

Replace every occurrence of

```markdown
- [x] Built-in `one_time_codes` filter (2FA codes, sign-in links, verification emails), on by default
```

with

```markdown
- [x] Built-in `one_time_codes` filter (2FA codes, sign-in links, verification emails), on by default
- [x] Mail organization: folders and move/copy — [spec](docs/superpowers/specs/2026-10-08-mailbox-organization-design.md) · [ADR 0021](docs/adr/0021-mailbox-organization-tools.md)
```
- [ ] **Step 12: Edit `README.md`**

Replace every occurrence of

```markdown
├── tools.zig           tool handlers (descriptions.zig: model-facing texts)
```

with

```markdown
├── tools.zig           tool handlers (descriptions.zig: model-facing texts)
├── organize.zig        folder protection, move strategy, batching (ADR 0021)
```
- [ ] **Step 13: Edit `README.md`**

Replace every occurrence of

```markdown
| An email shows `[withheld by filter
```

with

```markdown
| `… is a special-use folder (\Sent) and cannot be renamed or deleted` | Working as intended (ADR 0021); reorganize system folders in your mail client. |
| `the server supports neither MOVE nor UIDPLUS…` | The server cannot move messages safely; use `copy_messages` and delete the originals in your mail client. |
| `connection lost while moving or copying messages…` | The outcome is unknown; search both folders before retrying. |
| An email shows `[withheld by filter
```
- [ ] **Step 14: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `180/180 tests passed`.

- [ ] **Step 15: Checkpoint: hand off for commit**

Do not run git (the user performs all git operations). Tell the user the task is ready and suggest the message: `feat(organize): live checks (--organize), ADR 0021 and README`

---

## After the last task

- Live checks (the user runs this; it needs 1Password):
  `! op run --env-file imap.env -- zig build itest -- <account> --organize`. Expected: 43 PASS lines and `0 failure(s)`.
- Manual Gmail check once XOAUTH2 works: create a label, move a message out of INBOX (archive + label), copy (adds a label), and confirm that renaming `[Gmail]/Sent Mail` is refused.
- Mark the spec `Status: Implemented`.
