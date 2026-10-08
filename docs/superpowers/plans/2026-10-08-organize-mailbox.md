# Organize My Mailbox — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One action, "organize my mailbox" (default INBOX): the conversation's model classifies the newest messages as move / delete (to Trash) / flag / keep, following the user's `organize.md` or a built-in default; the server shows the plan as a dry run and carries it out only with `execute=true` and the dry run's `plan_hash`.

**Architecture:** Two phases, because an MCP server cannot run the model (Claude Code does not support MCP sampling). `organize_mailbox` (read-only) returns instructions, destination folders, Trash, and sanitized candidates (headers plus a snippet from a partial `BODY.PEEK[]<0.16384>` fetch), skipping messages already marked `$TpOrganized`. `apply_organization` validates the model's actions (UIDVALIDITY, destinations, withheld-means-keep), returns the grouped plan and its hash, and on execute runs flag → moves → delete-to-Trash through the existing batched move path, then marks kept/flagged messages `$TpOrganized`. Pure rules live in `src/triage.zig`; an MCP prompt `organize_my_mailbox` drives the workflow.

**Tech Stack:** Zig 0.17.0, libetpan 1.10.1, SQLite header cache (unchanged schema).

**Spec:** `docs/superpowers/specs/2026-10-08-organize-mailbox-design.md` (extends `docs/superpowers/specs/2026-10-08-mailbox-organization-design.md`). Decision: ADR 0022 (written in Task 5).

**Provenance:** Every code block below was compiled and tested before this plan was written: 205/205 unit tests, and 49/49 live checks against the user's Dovecot server with `--organize` (43 existing + 6 triage checks: gather lists the 3 test messages with instructions; dry run returns a hash and changes nothing; a wrong hash is refused; execute moves one, flags one, keeps one; `\Flagged` and `$TpOrganized` are set; reviewed messages are skipped on the next run). The plan was replayed task by task on a fresh copy of the repository: each task's tests fail before and pass after, and the end state is byte-identical to the verified sources. Copy code exactly; if something does not match the stated expectation, stop and report. Where a code block lost the blank line before `const testing = std.testing;`, keep exactly one blank line there.

## Global Constraints

- Zig 0.17.0; no `@cImport`; C only through `src/imap/c.zig` externs mirroring `src/c/tpi.h`; C compiled `-std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror`.
- No new dependencies.
- No permanent deletion: "delete" is a move to the `\Trash` folder; Trash, Junk and `\All` are never move destinations; `\All` is never a source (spec §3).
- `organize_mailbox` and dry runs are allowed on read-only accounts; `execute=true` is refused there (spec §2.2).
- `execute=true` requires `plan_hash` equal to the hash of this call's actions (first 8 bytes of SHA-256, lowercase hex, actions sorted by UID) (spec §2.2).
- Withheld messages accept only `keep`, regardless of the instructions file (spec §5.1).
- `limit` 1–200, default 50; 1–500 actions; instructions file at most 16 KiB, looked up as `organize.<account>.md`, then `organize.md`, then built-in (spec §2.1).
- `apply_organization` is not retried after a lost connection (spec §2.2).
- Commit after each task (git is allowed in this repository).

## Review Focus

1. **The folder changes between gather and execute** (messages moved away in another client, new mail arriving). UIDVALIDITY is checked and missing UIDs are listed under `missing` and skipped; reviewer should confirm `ApplyOp` computes groups and counts from present UIDs only, and the hash still covers the requested actions.
2. **A partial failure mid-plan** (flag succeeds, the second move destination fails). `applyFailureMessage` must name completed, partial and not-attempted steps, and `Registry.forgetMoved` must drop exactly the moved UIDs — check the `catch` path in `applyOrganization`.
3. **A server that refuses the `$TpOrganized` keyword** (no `\*` in PERMANENTFLAGS): the plan still succeeds with a note. Only the success path runs live (Dovecot accepts keywords); check the `ServerRejected` branch sets `keyword_refused` and does not fail the call.
4. **A hostile instructions file or message snippet** (prompt injection telling the model to delete everything): the server-side guarantees are the dry run, the plan hash, Trash-not-expunge and withheld-means-keep. Confirm none of these depend on instructions text, and that snippets pass through `body.render` (sanitized) and are cut at a UTF-8 boundary.
5. **Delete-to-Trash path** is unit-tested only (the live check never touches the real Trash). Check that `delete` uses `triage.trashFolder` (LIST `\Trash` flag, not a name) and is refused when the account has none or when the source is Trash.

---

### Task 1: Partial body fetch in the C shim

**Files:**
- Modify: `src/c/tpi.h`, `src/c/session.c`, `src/imap/c.zig`, `src/imap/session.zig`

**Interfaces:**
- Produces: C `TPI_FETCH_PARTIAL = 16`, `TPI_PARTIAL_BYTES = 16384` (with `TPI_FETCH_BODY`, `tpi_fetch` sends `BODY.PEEK[]<0.16384>`); Zig `c.FETCH_PARTIAL`, `c.PARTIAL_BYTES`; `imap.What.partial: bool = false`; `imap.What.partial_bytes` (= 16384).

- [ ] **Step 1: Write the failing tests**

In `src/imap/session.zig`, replace everything from the line `const testing = std.testing;` to the end of the file with:

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

test "checkHostName accepts the certificate's SAN and rejects other hosts" {
    const der = @embedFile("../testdata/mail.example.org.der");
    try checkHostName(der, "mail.example.org");
    try testing.expectError(error.HostnameMismatch, checkHostName(der, "evil.example.net"));
    try testing.expectError(error.HostnameMismatch, checkHostName(der, "example.org"));
    try testing.expectError(error.HostnameMismatch, checkHostName(der, "127.0.0.1"));
}

test "decodeHeaderValue decodes RFC 2047 B and Q words, leaves plain text alone" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("Password reset", try decodeHeaderValue(a, "=?UTF-8?B?UGFzc3dvcmQgcmVzZXQ=?="));
    try testing.expectEqualStrings("Password reset", try decodeHeaderValue(a, "=?UTF-8?Q?Password_reset?="));
    try testing.expectEqualStrings("R\u{e9}initialiser", try decodeHeaderValue(a, "=?ISO-8859-1?Q?R=E9initialiser?="));
    try testing.expectEqualStrings("Reset your password", try decodeHeaderValue(a, "=?UTF-8?Q?Reset_?= =?UTF-8?Q?your_password?="));
    try testing.expectEqualStrings("Plain subject", try decodeHeaderValue(a, "Plain subject"));
}

test "todo: a decode that comes out empty falls back to the raw value" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const raw = "=?UTF-8?B?AFJlc2V0IHlvdXIgcGFzc3dvcmQ=?=";
    try testing.expectEqualStrings(raw, try decodeHeaderValue(arena_state.allocator(), raw));
}

test "What.bits sets FETCH_PARTIAL for a partial body fetch" {
    try testing.expectEqual(c.FETCH_BODY | c.FETCH_PARTIAL, (What{ .body = true, .partial = true }).bits());
    try testing.expectEqual(c.FETCH_BODY, (What{ .body = true }).bits());
    try testing.expectEqual(16384, What.partial_bytes);
}
```
- [ ] **Step 2: Run the tests and confirm they fail**

Run: `zig build test --summary all`
Expected: compilation fails (the code under test does not exist yet).

- [ ] **Step 3: Write `src/c/tpi.h`**

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
  TPI_FETCH_PARTIAL = 16, /* with TPI_FETCH_BODY: only the first TPI_PARTIAL_BYTES */
};

enum { TPI_PARTIAL_BYTES = 16384 }; /* BODY.PEEK[]<0.16384> */

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
- [ ] **Step 4: Write `src/c/session.c`**

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
    struct mailimap_fetch_att *att =
        (what & TPI_FETCH_BODY) && (what & TPI_FETCH_PARTIAL)
            ? mailimap_fetch_att_new_body_peek_section_partial(sec, 0, TPI_PARTIAL_BYTES)
            : mailimap_fetch_att_new_body_peek_section(sec);
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
- [ ] **Step 5: Write `src/imap/c.zig`**

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
pub const FETCH_PARTIAL: c_int = 16;
pub const PARTIAL_BYTES = 16384;

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
- [ ] **Step 6: Implement**

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
    /// With `body`: only the first `partial_bytes` (BODY.PEEK[]<0.N>).
    partial: bool = false,

    pub const partial_bytes = c.PARTIAL_BYTES;

    fn bits(w: What) c_int {
        var b: c_int = 0;
        if (w.header) b |= c.FETCH_HEADER;
        if (w.body) b |= c.FETCH_BODY;
        if (w.size) b |= c.FETCH_SIZE;
        if (w.flags) b |= c.FETCH_FLAGS;
        if (w.partial) b |= c.FETCH_PARTIAL;
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
- [ ] **Step 7: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `189/189 tests passed`.

- [ ] **Step 8: Commit**

```bash
git add src/c/session.c src/c/tpi.h src/imap/c.zig src/imap/session.zig
git commit -m "feat(triage): partial body fetch (first 16 KiB) for snippets"
```

---

### Task 2: Triage rules and the built-in organizing instructions

**Files:**
- Create: `src/triage.zig`, `src/organize_prompt.md`
- Modify: `src/main.zig` (test block)

**Interfaces:**
- Consumes: `imap.Mailbox`, `imap.What.partial_bytes` (Task 1); `organize.find`, `organize.selectable`, `organize.specialUse`; `validate.uids`; `text.truncateUtf8`.
- Produces: constants `max_actions = 500`, `max_limit = 200`, `default_limit = 50`, `partial_bytes`, `snippet_bytes = 500`, `instructions_max = 16 * 1024`, `reviewed_keyword = "$TpOrganized"`, `default_instructions` (`@embedFile("organize_prompt.md")`);
  `Instructions{ text, source }`; `LoadResult = union(enum){ ok: Instructions, problem: []const u8 }`; `loadInstructions(arena, io, config_dir: ?[]const u8, account) !LoadResult`;
  `Kind = enum{ move, delete, flag, keep }`; `Action{ uid: u32, kind: Kind, destination: ?[]const u8 }`; `ParseResult = union(enum){ ok: []Action, problem: []const u8 }`; `parseActions(arena, ?std.json.Value) !ParseResult`;
  `planHash(arena, account, directory, uidvalidity: u32, actions) ![16]u8`; `Group{ kind, destination: ?[]const u8, uids: []u32 }`; `group(arena, actions) ![]Group`;
  `trashFolder(boxes) ?imap.Mailbox`; `folderChoices(arena, boxes, source) ![]imap.Mailbox`; `destinationProblem(arena, boxes, source, dest, shown) !?[]const u8`; `snippet(arena, text) ![]const u8`.

- [ ] **Step 1: Write `src/organize_prompt.md`**

Replace (or create) the whole file:

```markdown
# How to organize this mailbox

You are proposing a plan; the user reviews it before anything changes. Be
conservative: a message left in place costs nothing, a message filed or deleted
by mistake can be missed. When unsure, choose **keep**.

## Never touch (always **keep**)

- Messages shown as `withheld`. They were hidden by a sensitive-content filter
  (password resets, one-time codes, sign-in links). Do not guess what they are.
- Anything about credentials or account access, even if it was not withheld:
  password or PIN changes, verification or confirmation codes, magic or sign-in
  links, two-factor setup, recovery codes, API keys or tokens, new-device or
  new-login alerts, "confirm it's you" requests.
- Drafts, and messages the user sent themselves.
- Anything that looks like it is in the middle of a conversation the user is
  part of, unless it clearly belongs in a folder for that topic.

## Flag (needs attention)

Flag a message, and keep it where it is, when it:
- asks the user, personally, to do or answer something;
- mentions a deadline, appointment or expiry in the next two weeks;
- is an invoice, bill, payment request, failed payment, or money owed;
- comes from a person (not a mailing list or a no-reply address) and is not
  plainly social chatter;
- is a security or fraud notice about one of the user's accounts that is not
  about credentials (those are **keep**, see above).

## Move to a folder

Move a message only to a folder from the `folders` list, and only when the
sender or subject clearly matches that folder's purpose (for example receipts
and order confirmations to a receipts folder, newsletters to a newsletters
folder, notifications from a service to that service's folder). Never invent a
folder name. If several messages would fit a folder that does not exist, keep
them and tell the user which new folder you would suggest.

Do not move a message you also flag.

## Delete (move to Trash)

Delete only when it is plainly worthless:
- obvious spam or bulk mail the user never signed up for;
- promotions and sales whose offer has expired;
- automated notifications that are superseded (e.g. a shipping update after a
  later "delivered" message for the same order).
Never delete messages from people, receipts, invoices, anything legal, medical,
financial or tax related, or anything you are not sure about.

## Output

Give exactly one action per message: `keep`, `flag`, `move` (with
`destination`), or `delete`. When presenting the dry run, summarize per group
and mention anything you deliberately left alone and why.
```
- [ ] **Step 2: Write the failing tests**

Create `src/triage.zig` containing only its tests:

```zig
const testing = std.testing;

fn parseJson(arena: Allocator, s: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, arena, s, .{});
}

test "loadInstructions: per-account file, then organize.md, then the built-in default" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const dir = try a.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});

    const none = try loadInstructions(a, testing.io, null, "work");
    try testing.expectEqualStrings("built-in", none.ok.source);
    try testing.expect(std.mem.startsWith(u8, none.ok.text, "# How to organize this mailbox"));
    try testing.expectEqualStrings("built-in", (try loadInstructions(a, testing.io, dir, "work")).ok.source);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.md", .data = "shared rules" });
    try testing.expectEqualStrings("shared rules", (try loadInstructions(a, testing.io, dir, "work")).ok.text);

    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.work.md", .data = "work rules" });
    const per = try loadInstructions(a, testing.io, dir, "Work");
    try testing.expectEqualStrings("work rules", per.ok.text);
    try testing.expect(std.mem.endsWith(u8, per.ok.source, "organize.work.md"));
    try testing.expectEqualStrings("shared rules", (try loadInstructions(a, testing.io, dir, "home")).ok.text);
}

test "loadInstructions rejects a file over 16 KiB, naming it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const dir = try a.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    const big: [instructions_max + 1]u8 = @splat('x');
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.md", .data = &big });
    const r = try loadInstructions(a, testing.io, dir, "work");
    try testing.expect(std.mem.endsWith(u8, r.problem, "organize.md is larger than 16384 bytes"));
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "organize.md", .data = big[0..instructions_max] });
    try testing.expectEqual(instructions_max, (try loadInstructions(a, testing.io, dir, "work")).ok.text.len);
}

test "the built-in instructions keep credential mail and withheld messages" {
    try testing.expect(std.mem.find(u8, default_instructions, "withheld") != null);
    try testing.expect(std.mem.find(u8, default_instructions, "password") != null);
    try testing.expect(default_instructions.len <= instructions_max);
}

test "parseActions accepts the four actions and rejects malformed input" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ok = (try parseActions(a, try parseJson(a,
        \\[{"uid":"7","action":"move","destination":"Receipts"},{"uid":"8","action":"delete"},
        \\ {"uid":"9","action":"flag"},{"uid":"10","action":"keep","destination":null}]
    ))).ok;
    try testing.expectEqual(4, ok.len);
    try testing.expectEqualStrings("Receipts", ok[0].destination.?);
    try testing.expectEqual(Kind.keep, ok[3].kind);

    const cases = [_]struct { json: []const u8, problem: []const u8 }{
        .{ .json = "{}", .problem = "argument \"actions\" must be an array" },
        .{ .json = "[]", .problem = "actions must not be empty" },
        .{ .json = "[1]", .problem = "actions[0] must be an object" },
        .{ .json = "[{\"action\":\"keep\"}]", .problem = "actions[0] has no \"uid\"" },
        .{ .json = "[{\"uid\":7,\"action\":\"keep\"}]", .problem = "actions[0].uid must be a string" },
        .{ .json = "[{\"uid\":\"0\",\"action\":\"keep\"}]", .problem = "actions[0].uid must be a decimal string between 1 and 4294967295" },
        .{ .json = "[{\"uid\":\"1:*\",\"action\":\"keep\"}]", .problem = "actions[0].uid must be a decimal string between 1 and 4294967295" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"keep\"},{\"uid\":\"7\",\"action\":\"flag\"}]", .problem = "uid 7 appears more than once" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"archive\"}]", .problem = "actions[0].action must be \"move\", \"delete\", \"flag\" or \"keep\"" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"move\"}]", .problem = "actions[0]: \"move\" needs a \"destination\"" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"move\",\"destination\":\"\"}]", .problem = "actions[0].destination must be a non-empty string" },
        .{ .json = "[{\"uid\":\"7\",\"action\":\"delete\",\"destination\":\"Trash\"}]", .problem = "actions[0]: only \"move\" takes a \"destination\"" },
    };
    for (cases) |c| try testing.expectEqualStrings(c.problem, (try parseActions(a, try parseJson(a, c.json))).problem);
    try testing.expectEqualStrings("missing required argument \"actions\"", (try parseActions(a, null)).problem);

    var many: std.ArrayList(u8) = .empty;
    try many.append(a, '[');
    for (1..max_actions + 2) |i| try many.print(a, "{s}{{\"uid\":\"{d}\",\"action\":\"keep\"}}", .{ if (i > 1) "," else "", i });
    try many.append(a, ']');
    try testing.expectEqualStrings("at most 500 actions per call; got 501", (try parseActions(a, try parseJson(a, many.items))).problem);
}

test "planHash ignores action order and changes with any action" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const one = [_]Action{ .{ .uid = 7, .kind = .move, .destination = "Receipts" }, .{ .uid = 8, .kind = .delete } };
    const swapped = [_]Action{ one[1], one[0] };
    const h = try planHash(a, "work", "INBOX", 42, &one);
    try testing.expectEqual(16, h.len);
    for (h) |c| try testing.expect(std.ascii.isDigit(c) or (c >= 'a' and c <= 'f'));
    try testing.expectEqualStrings(&h, &(try planHash(a, "work", "INBOX", 42, &swapped)));
    const other_dest = [_]Action{ .{ .uid = 7, .kind = .move, .destination = "Receipt" }, one[1] };
    const other_kind = [_]Action{ one[0], .{ .uid = 8, .kind = .keep } };
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "work", "INBOX", 42, &other_dest))));
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "work", "INBOX", 42, &other_kind))));
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "work", "INBOX", 43, &one))));
    try testing.expect(!std.mem.eql(u8, &h, &(try planHash(a, "home", "INBOX", 42, &one))));
}

test "group orders moves by destination, then delete, flag, keep" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const acts = [_]Action{
        .{ .uid = 1, .kind = .keep },
        .{ .uid = 2, .kind = .move, .destination = "B" },
        .{ .uid = 3, .kind = .flag },
        .{ .uid = 4, .kind = .move, .destination = "A" },
        .{ .uid = 5, .kind = .move, .destination = "B" },
    };
    const g = try group(a, &acts);
    try testing.expectEqual(4, g.len);
    try testing.expectEqualStrings("B", g[0].destination.?);
    try testing.expectEqualSlices(u32, &.{ 2, 5 }, g[0].uids);
    try testing.expectEqualStrings("A", g[1].destination.?);
    try testing.expectEqual(Kind.flag, g[2].kind);
    try testing.expectEqual(Kind.keep, g[3].kind);
}

fn mbox(name: []const u8, flags: []const []const u8) imap.Mailbox {
    return .{ .name = name, .delimiter = '/', .flags = flags };
}

const test_boxes = [_]imap.Mailbox{
    mbox("INBOX", &.{}),
    mbox("Receipts", &.{}),
    mbox("[Gmail]", &.{"\\Noselect"}),
    mbox("[Gmail]/All Mail", &.{"\\All"}),
    mbox("[Gmail]/Trash", &.{"\\Trash"}),
    mbox("[Gmail]/Spam", &.{"\\Junk"}),
    mbox("[Gmail]/Sent Mail", &.{"\\Sent"}),
};

test "folderChoices and trashFolder" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const choices = try folderChoices(arena_state.allocator(), &test_boxes, "inbox");
    try testing.expectEqual(2, choices.len);
    try testing.expectEqualStrings("Receipts", choices[0].name);
    try testing.expectEqualStrings("[Gmail]/Sent Mail", choices[1].name);
    try testing.expectEqualStrings("[Gmail]/Trash", trashFolder(&test_boxes).?.name);
    try testing.expect(trashFolder(test_boxes[0..2]) == null);
}

test "destinationProblem enforces spec §2.2" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expect((try destinationProblem(a, &test_boxes, "INBOX", "Receipts", "Receipts")) == null);
    try testing.expectEqualStrings("destination \"Nope\" does not exist", (try destinationProblem(a, &test_boxes, "INBOX", "Nope", "Nope")).?);
    try testing.expectEqualStrings("\"[Gmail]\" cannot hold messages (\\Noselect)", (try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]", "[Gmail]")).?);
    try testing.expectEqualStrings("destination \"Inbox\" is the folder being organized", (try destinationProblem(a, &test_boxes, "INBOX", "Inbox", "Inbox")).?);
    try testing.expectEqualStrings("\"[Gmail]/Trash\" is the Trash folder; use action \"delete\"", (try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]/Trash", "[Gmail]/Trash")).?);
    try testing.expect((try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]/Spam", "[Gmail]/Spam")) != null);
    try testing.expect((try destinationProblem(a, &test_boxes, "INBOX", "[Gmail]/All Mail", "[Gmail]/All Mail")) != null);
}

test "snippet collapses whitespace and cuts at a UTF-8 boundary" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("Hello there, see you", try snippet(a, "  Hello\n\nthere,\t see   you\n"));
    var long: std.ArrayList(u8) = .empty;
    for (0..400) |_| try long.appendSlice(a, "é");
    const s = try snippet(a, long.items);
    try testing.expect(s.len <= snippet_bytes);
    try testing.expect(std.unicode.utf8ValidateSlice(s));
}
```
- [ ] **Step 3: Register the tests**

Add to the `test { ... }` block in `src/main.zig`:

```zig
    _ = @import("triage.zig");
```
- [ ] **Step 4: Run the tests and confirm they fail**

Run: `zig build test --summary all`
Expected: compilation fails (the code under test does not exist yet).

- [ ] **Step 5: Implement**

Insert at the very top of `src/triage.zig`, above the tests:

```zig
//! organize_mailbox / apply_organization rules (ADR 0022, spec §2-§5):
//! organizing instructions, action parsing and validation, grouping, plan
//! hash, snippets. No IMAP I/O.

const std = @import("std");
const Allocator = std.mem.Allocator;
const imap = @import("imap/session.zig");
const organize = @import("organize.zig");
const text = @import("text.zig");

/// Most actions one apply_organization call accepts.
pub const max_actions = 500;
/// Most messages one organize_mailbox call returns.
pub const max_limit = 200;
pub const default_limit = 50;
/// Bytes of each message fetched for its snippet (BODY.PEEK[]<0.N>).
pub const partial_bytes = imap.What.partial_bytes;
/// Characters of sanitized text in a snippet.
pub const snippet_bytes = 500;
/// Largest organize.md accepted.
pub const instructions_max = 16 * 1024;
/// Keyword marking messages a plan kept or flagged (spec §2.2).
pub const reviewed_keyword = "$TpOrganized";
/// Built-in organizing instructions (spec §5).
pub const default_instructions = @embedFile("organize_prompt.md");

pub const Instructions = struct {
    text: []const u8,
    /// The file it came from, or "built-in".
    source: []const u8,
};

pub const LoadResult = union(enum) {
    ok: Instructions,
    /// Human-readable reason (the file is too large or unreadable).
    problem: []const u8,
};

/// `<config_dir>/organize.<account>.md`, else `<config_dir>/organize.md`,
/// else the built-in default. The account name is lowercased.
pub fn loadInstructions(arena: Allocator, io: std.Io, config_dir: ?[]const u8, account: []const u8) Allocator.Error!LoadResult {
    const dir = config_dir orelse return .{ .ok = .{ .text = default_instructions, .source = "built-in" } };
    const per_account = try arena.print("organize.{s}.md", .{try std.ascii.allocLowerString(arena, account)});
    for ([_][]const u8{ per_account, "organize.md" }) |name| {
        const path = try std.fs.path.join(arena, &.{ dir, name });
        const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(instructions_max + 1)) catch |err| switch (err) {
            error.FileNotFound => continue,
            error.OutOfMemory => return error.OutOfMemory,
            error.StreamTooLong => return .{ .problem = try arena.print("{s} is larger than {d} bytes", .{ path, instructions_max }) },
            else => return .{ .problem = try arena.print("{s}: cannot read ({t})", .{ path, err }) },
        };
        if (bytes.len > instructions_max) return .{ .problem = try arena.print("{s} is larger than {d} bytes", .{ path, instructions_max }) };
        return .{ .ok = .{ .text = try text.sanitizeUtf8(arena, bytes), .source = path } };
    }
    return .{ .ok = .{ .text = default_instructions, .source = "built-in" } };
}

pub const Kind = enum { move, delete, flag, keep };

pub const Action = struct {
    uid: u32,
    kind: Kind,
    /// UTF-8 folder name; set for `move` only.
    destination: ?[]const u8 = null,
};

pub const ParseResult = union(enum) {
    ok: []Action,
    problem: []const u8,
};

/// Parses the `actions` argument (spec §2.2): 1..max_actions objects
/// `{uid, action, destination?}`, each UID at most once.
pub fn parseActions(arena: Allocator, value: ?std.json.Value) Allocator.Error!ParseResult {
    const v = value orelse return .{ .problem = "missing required argument \"actions\"" };
    if (v != .array) return .{ .problem = "argument \"actions\" must be an array" };
    const items = v.array.items;
    if (items.len == 0) return .{ .problem = "actions must not be empty" };
    if (items.len > max_actions) return .{ .problem = try arena.print("at most {d} actions per call; got {d}", .{ max_actions, items.len }) };
    const out = try arena.alloc(Action, items.len);
    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    for (items, out, 0..) |item, *o, i| {
        if (item != .object) return .{ .problem = try arena.print("actions[{d}] must be an object", .{i}) };
        const obj = item.object;
        const uid_v = obj.get("uid") orelse return .{ .problem = try arena.print("actions[{d}] has no \"uid\"", .{i}) };
        if (uid_v != .string) return .{ .problem = try arena.print("actions[{d}].uid must be a string", .{i}) };
        const uid = parseUid(uid_v.string) orelse return .{ .problem = try arena.print("actions[{d}].uid must be a decimal string between 1 and 4294967295", .{i}) };
        if ((try seen.getOrPut(arena, uid)).found_existing) return .{ .problem = try arena.print("uid {d} appears more than once", .{uid}) };
        const kind_v = obj.get("action") orelse return .{ .problem = try arena.print("actions[{d}] has no \"action\"", .{i}) };
        const kind = if (kind_v == .string) std.meta.stringToEnum(Kind, kind_v.string) else null;
        const k = kind orelse return .{ .problem = try arena.print("actions[{d}].action must be \"move\", \"delete\", \"flag\" or \"keep\"", .{i}) };
        const dest_v = obj.get("destination");
        if (k == .move) {
            const d = dest_v orelse return .{ .problem = try arena.print("actions[{d}]: \"move\" needs a \"destination\"", .{i}) };
            if (d != .string or d.string.len == 0) return .{ .problem = try arena.print("actions[{d}].destination must be a non-empty string", .{i}) };
            o.* = .{ .uid = uid, .kind = k, .destination = d.string };
        } else {
            if (dest_v != null and dest_v.? != .null) return .{ .problem = try arena.print("actions[{d}]: only \"move\" takes a \"destination\"", .{i}) };
            o.* = .{ .uid = uid, .kind = k };
        }
    }
    return .{ .ok = out };
}

fn parseUid(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    const u = std.fmt.parseInt(u32, s, 10) catch return null;
    return if (u == 0) null else u;
}

/// 16 lowercase hex characters: SHA-256 over account, directory,
/// UIDVALIDITY and the actions sorted by UID (independent of input order).
pub fn planHash(arena: Allocator, account: []const u8, directory: []const u8, uidvalidity: u32, actions: []const Action) Allocator.Error![16]u8 {
    const sorted = try arena.dupe(Action, actions);
    std.mem.sort(Action, sorted, {}, struct {
        fn lt(_: void, a: Action, b: Action) bool {
            return a.uid < b.uid;
        }
    }.lt);
    var h: std.crypto.hash.sha2.Sha256 = .init(.{});
    var num: [16]u8 = undefined;
    h.update(account);
    h.update(&.{0});
    h.update(directory);
    h.update(&.{0});
    h.update(std.mem.print(&num, "{d}", .{uidvalidity}) catch unreachable);
    for (sorted) |a| {
        h.update(&.{0});
        h.update(std.mem.print(&num, "{d}", .{a.uid}) catch unreachable);
        h.update(&.{0});
        h.update(@tagName(a.kind));
        h.update(&.{0});
        h.update(a.destination orelse "");
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return std.fmt.bytesToHex(digest[0..8].*, .lower);
}

pub const Group = struct {
    kind: Kind,
    /// Move destination as given (UTF-8); null for other kinds.
    destination: ?[]const u8 = null,
    uids: []const u32,
};

/// Actions grouped for display and execution: moves (by destination, in
/// first-appearance order), then delete, flag, keep. Empty groups omitted.
pub fn group(arena: Allocator, actions: []const Action) Allocator.Error![]Group {
    var out: std.ArrayList(Group) = .empty;
    var dests: std.ArrayList([]const u8) = .empty;
    for (actions) |a| {
        if (a.kind != .move) continue;
        for (dests.items) |d| {
            if (std.mem.eql(u8, d, a.destination.?)) break;
        } else try dests.append(arena, a.destination.?);
    }
    for (dests.items) |d| {
        var uids: std.ArrayList(u32) = .empty;
        for (actions) |a| if (a.kind == .move and std.mem.eql(u8, a.destination.?, d)) try uids.append(arena, a.uid);
        try out.append(arena, .{ .kind = .move, .destination = d, .uids = uids.items });
    }
    for ([_]Kind{ .delete, .flag, .keep }) |k| {
        var uids: std.ArrayList(u32) = .empty;
        for (actions) |a| if (a.kind == k) try uids.append(arena, a.uid);
        if (uids.items.len > 0) try out.append(arena, .{ .kind = k, .uids = uids.items });
    }
    return out.items;
}

/// The account's Trash folder (`\Trash` attribute), if any.
pub fn trashFolder(boxes: []const imap.Mailbox) ?imap.Mailbox {
    for (boxes) |b| for (b.flags) |f| {
        if (std.ascii.eqlIgnoreCase(f, "\\Trash")) return b;
    };
    return null;
}

fn hasFlag(box: imap.Mailbox, flag: []const u8) bool {
    for (box.flags) |f| if (std.ascii.eqlIgnoreCase(f, flag)) return true;
    return false;
}

/// Folders offered as move destinations from `source` (spec §2.1): selectable,
/// not the source, not \All, \Trash or \Junk.
pub fn folderChoices(arena: Allocator, boxes: []const imap.Mailbox, source: []const u8) Allocator.Error![]imap.Mailbox {
    var out: std.ArrayList(imap.Mailbox) = .empty;
    for (boxes) |b| {
        if (!organize.selectable(b)) continue;
        if (organize.sameMailbox(boxes, b.name, source)) continue;
        if (hasFlag(b, "\\All") or hasFlag(b, "\\Trash") or hasFlag(b, "\\Junk")) continue;
        try out.append(arena, b);
    }
    return out.items;
}

/// Why `dest` (wire name; `shown` for messages) cannot receive a `move` from
/// `source`, or null (spec §2.2).
pub fn destinationProblem(arena: Allocator, boxes: []const imap.Mailbox, source: []const u8, dest: []const u8, shown: []const u8) Allocator.Error!?[]const u8 {
    const box = organize.find(boxes, dest) orelse return try arena.print("destination \"{s}\" does not exist", .{shown});
    if (!organize.selectable(box)) return try arena.print("\"{s}\" cannot hold messages (\\Noselect)", .{shown});
    if (organize.sameMailbox(boxes, source, dest)) return try arena.print("destination \"{s}\" is the folder being organized", .{shown});
    if (hasFlag(box, "\\Trash")) return try arena.print("\"{s}\" is the Trash folder; use action \"delete\"", .{shown});
    if (hasFlag(box, "\\Junk")) return try arena.print("\"{s}\" is the spam/junk folder and is not a move destination", .{shown});
    if (hasFlag(box, "\\All")) return try arena.print("\"{s}\" holds all mail (\\All) and is not a move destination", .{shown});
    return null;
}

/// Sanitized message text cut for a snippet: whitespace runs collapsed, at
/// most `snippet_bytes`, cut at a UTF-8 boundary.
pub fn snippet(arena: Allocator, body_text: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var space = false;
    for (body_text) |c| {
        if (std.ascii.isWhitespace(c)) {
            space = out.items.len > 0;
            continue;
        }
        if (space) try out.append(arena, ' ');
        space = false;
        try out.append(arena, c);
        if (out.items.len > snippet_bytes + 4) break;
    }
    return text.truncateUtf8(out.items, snippet_bytes);
}
```
- [ ] **Step 6: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `198/198 tests passed`.

- [ ] **Step 7: Commit**

```bash
git add src/main.zig src/organize_prompt.md src/triage.zig
git commit -m "feat(triage): instructions lookup, action parsing, plan hash and grouping"
```

---

### Task 3: The organize_mailbox and apply_organization tools

**Files:**
- Modify: `src/tools.zig`, `src/descriptions.zig`, `src/mcp.zig` (tool count in a test)

**Interfaces:**
- Consumes: `triage.*` (Task 2); `imap.What{ .body = true, .partial = true }` (Task 1); the existing `TransferOp` batching, `CachedHeadersOp`-style header fetch, filters, `body.render`, `limit.Budget`, `Registry.forgetMoved`.
- Produces: tools `organize_mailbox` and `apply_organization` (spec §2.1, §2.2); `ParamKind.integer` and `.actions`; `Ctx.integer`, `Ctx.integerOr`, `Ctx.wireName`; `Batches` (extracted from `TransferOp`, which now holds `progress: Batches`); `GatherOp`, `ApplyOp` (non-retryable); `executionOrder`, `applyFailureMessage`.

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

test "review: a failed fallback move says which messages were moved, copied, untouched" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings(
        "500 of 1200 messages were moved; the next 500 were copied to \"Dest\" but not removed from \"Src\" (they may be flagged \\Deleted); the remaining 200 were not touched: STORE failed",
        try partialMoveMessage(a, 500, 1200, 500, "Dest", "Src", "STORE failed"),
    );
    try testing.expectEqualStrings(
        "0 of 3 messages were moved; the next 3 were copied to \"Dest\" but not removed from \"Src\" (they may be flagged \\Deleted): EXPUNGE failed",
        try partialMoveMessage(a, 0, 3, 3, "Dest", "Src", "EXPUNGE failed"),
    );
}

test "review: a name matching several folders after cleaning is ambiguous" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const boxes = [_]imap.Mailbox{
        .{ .name = "INBOX", .delimiter = '/', .flags = &.{} },
        .{ .name = "Fo&IAs-o", .delimiter = '/', .flags = &.{} }, // "Fo\u{200B}o"
        .{ .name = "Fo&IA0-o", .delimiter = '/', .flags = &.{} }, // "Fo\u{200D}o"
        .{ .name = "Ba&IAs-r", .delimiter = '/', .flags = &.{} }, // "Ba\u{200B}r"
    };
    try testing.expect(try ambiguousMailbox(a, &boxes, "Foo", "Foo"));
    try testing.expect(!try ambiguousMailbox(a, &boxes, "Bar", "Bar"));
    try testing.expect(!try ambiguousMailbox(a, &boxes, "Other", "Other"));
    // An exact wire match wins; nothing to disambiguate.
    try testing.expect(!try ambiguousMailbox(a, &boxes, "Fo\u{200B}o", "Fo&IAs-o"));
}

test "review: new folder names with invisible characters never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const msg = "mailbox name must not contain invisible or control characters";
    try testing.expectEqualStrings(msg, (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"INBOX\\u200b\"}")).?.invalid_params);
    try testing.expectEqualStrings(msg, (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"C1\\u0085\"}")).?.invalid_params);
    try testing.expectEqualStrings(msg, (try callJson(&reg, a, "rename_mailbox", "{\"account\":\"rw\",\"name\":\"X\",\"new_name\":\"Y\\u202e\"}")).?.invalid_params);
}

test "organize tools: argument errors never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("argument \"limit\" must be between 1 and 200", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"limit\":0}")).?.invalid_params);
    try testing.expectEqualStrings("argument \"limit\" must be between 1 and 200", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"limit\":201}")).?.invalid_params);
    try testing.expectEqualStrings("argument \"limit\" must be an integer", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"limit\":\"5\"}")).?.invalid_params);
    try testing.expectEqualStrings("criteria must not contain CR, LF, or NUL", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"criteria\":\"ALL\\r\\nA1 DELETE INBOX\"}")).?.invalid_params);

    const apply = "{\"account\":\"rw\",\"directory\":\"INBOX\",\"uidvalidity\":7";
    try testing.expectEqualStrings("missing required argument \"uidvalidity\"", (try callJson(&reg, a, "apply_organization", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"actions\":[]}")).?.invalid_params);
    try testing.expectEqualStrings("actions must not be empty", (try callJson(&reg, a, "apply_organization", apply ++ ",\"actions\":[]}")).?.invalid_params);
    try testing.expectEqualStrings(
        "execute=true needs the plan_hash from a dry run (execute=false)",
        (try callJson(&reg, a, "apply_organization", apply ++ ",\"actions\":[{\"uid\":\"1\",\"action\":\"keep\"}],\"execute\":true}")).?.invalid_params,
    );
}

test "organize tools: read-only accounts gather and dry-run but never execute" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const unreachable_ro = "account \"ro\": cannot connect to 127.0.0.1:1";
    try testing.expectEqualStrings(unreachable_ro, (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"ro\"}")).?.tool_error);
    const apply = "{\"account\":\"ro\",\"directory\":\"INBOX\",\"uidvalidity\":7,\"actions\":[{\"uid\":\"1\",\"action\":\"flag\"}]";
    try testing.expectEqualStrings(unreachable_ro, (try callJson(&reg, a, "apply_organization", apply ++ "}")).?.tool_error);
    try testing.expectEqualStrings("account \"ro\" is read-only", (try callJson(&reg, a, "apply_organization", apply ++ ",\"execute\":true,\"plan_hash\":\"0123456789abcdef\"}")).?.tool_error);
}

test "apply_organization runs flag, then moves, then delete, then keep" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const groups = [_]triage.Group{
        .{ .kind = .move, .destination = "A", .uids = &.{1} },
        .{ .kind = .move, .destination = "B", .uids = &.{2} },
        .{ .kind = .delete, .uids = &.{3} },
        .{ .kind = .flag, .uids = &.{4} },
        .{ .kind = .keep, .uids = &.{5} },
    };
    try testing.expectEqualSlices(usize, &.{ 3, 0, 1, 2, 4 }, try executionOrder(a, &groups));
}

test "applyFailureMessage says what was done, where it stopped, and what was not attempted" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const groups = [_]triage.Group{
        .{ .kind = .move, .destination = "Receipts", .uids = &.{ 1, 2, 3 } },
        .{ .kind = .delete, .uids = &.{4} },
        .{ .kind = .flag, .uids = &.{5} },
    };
    var op: ApplyOp = .{
        .arena = a,
        .headers = undefined,
        .active = &.{},
        .expected_uidvalidity = 7,
        .execute = true,
        .groups = &groups,
        .dests = &.{ "Receipts", "Trash", "" },
        .steps = try executionOrder(a, &groups),
    };
    for ([_]u32{ 1, 2, 3, 4, 5 }) |u| try op.present.put(a, u, {});
    op.completed = 1; // flag done; stopped in the move
    op.current = .{ .done = 1, .pending = 0 };
    const dests_shown = [_][]const u8{ "Receipts", "Trash", "" };
    try testing.expectEqualStrings(
        "the plan stopped at move 3 to \"Receipts\": 1 of 3 were moved before the error: boom. Completed: flag 1. Not attempted: delete 1 (to \"Trash\").",
        try applyFailureMessage(a, &op, &dests_shown, "INBOX", "boom"),
    );
    op.current = .{ .done = 0, .pending = 2 };
    try testing.expect(std.mem.find(u8, try applyFailureMessage(a, &op, &dests_shown, "INBOX", "boom"), "were copied to \"Receipts\" but not removed from \"INBOX\"") != null);
    op.completed = 3;
    try testing.expectEqualStrings(
        "the plan stopped at marking reviewed messages: boom. Completed: flag 1; move 3 to \"Receipts\"; delete 1 (to \"Trash\"). Not attempted: nothing.",
        try applyFailureMessage(a, &op, &dests_shown, "INBOX", "boom"),
    );
}

test "apply_organization is never retried (gathering may be); its schema lists the actions" {
    try testing.expect(accounts.retriesAfterConnectionLoss(GatherOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(ApplyOp));
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    try testing.expect(std.mem.find(u8, aw.written(), "\"enum\":[\"move\",\"delete\",\"flag\",\"keep\"]") != null);
    try testing.expect(std.mem.find(u8, aw.written(), "\"limit\":{\"type\":\"integer\"") != null);
}
```
- [ ] **Step 2: Edit `src/mcp.zig`**

Replace every occurrence of

```zig
try testing.expectEqual(20, list.value.object
```

with

```zig
try testing.expectEqual(22, list.value.object
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
    \\    readonly accounts refuse change_keywords, create_message, the
    \\    folder and move/copy tools, and executing apply_organization (dry
    \\    runs are allowed).
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
    \\    INBOX, special-use folders (Sent, Drafts, Trash, Junk/Spam,
    \\    Archive, All Mail, ...), the drafts folder create_message uses, and
    \\    folders containing them, cannot be renamed. On Gmail this renames
    \\    the label.
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
    \\    INBOX, special-use folders and the drafts folder create_message
    \\    uses cannot be deleted.
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
    \\    destination label; every message also stays in [Gmail]/All Mail.
    \\    Moving out of All Mail (\All) is refused; use copy_messages to add
    \\    a label.
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

pub const organize_mailbox =
    \\Start organizing a folder (default INBOX): returns the organizing
    \\instructions (the user's organize.md, or the built-in default), the
    \\folders messages may be moved to, the Trash folder, and the newest
    \\messages with sanitized headers and a short text snippet. Read-only.
    \\
    \\Args:
    \\    directory: the folder to organize (default "INBOX")
    \\    limit: how many of the newest messages, 1-200 (default 50)
    \\    criteria: optional IMAP SEARCH criteria, e.g. "UNSEEN"
    \\    include_reviewed: true to include messages an earlier plan kept or
    \\        flagged (they carry the keyword $TpOrganized and are skipped
    \\        otherwise)
    \\
    \\Return:
    \\    {"account", "directory", "uidvalidity", "instructions",
    \\     "instructions_source", "folders": [...], "trash": "Trash" | null,
    \\     "messages": [{"uid", "date", "from", "to", "subject", "size",
    \\       "flags", "snippet"} | {"uid", "date", "from", "withheld"}],
    \\     "omitted": N, "next": "..."}
    \\
    \\Next: classify every message following "instructions", then call
    \\apply_organization with execute=false, show the user the grouped plan,
    \\and execute only after the user confirms. Messages with "withheld" are
    \\hidden by a sensitive-content filter and must be "keep".
;

pub const apply_organization =
    \\Check, preview, or carry out an organizing plan for messages returned by
    \\organize_mailbox.
    \\
    \\Args:
    \\    directory, uidvalidity: as returned by organize_mailbox
    \\    actions: one per message, e.g.
    \\        [{"uid": "4711", "action": "move", "destination": "Receipts"},
    \\         {"uid": "4712", "action": "delete"},   (moved to Trash)
    \\         {"uid": "4713", "action": "flag"},     (sets \Flagged)
    \\         {"uid": "4714", "action": "keep"}]
    \\    execute: false (default) returns the plan grouped by action with a
    \\        plan_hash and changes nothing; true carries it out
    \\    plan_hash: required with execute=true; must come from a dry run of
    \\        exactly these actions
    \\
    \\Return:
    \\    dry run: {"dry_run": true, "plan_hash": "...", "groups": [{"action",
    \\      "destination", "count", "messages": [{"uid", "from", "subject"}]}],
    \\      "missing": [uids that no longer exist]}
    \\    executed: {"executed": true, "flagged", "moved": [{"destination",
    \\      "count"}], "deleted", "kept", "missing", "note"}
    \\
    \\Notes:
    \\    Always show the dry run to the user and execute only after they
    \\    confirm. Nothing is ever permanently deleted. Withheld messages
    \\    accept only "keep". Executing is refused for read-only accounts.
    \\    Kept and flagged messages get the keyword $TpOrganized so the next
    \\    organize_mailbox skips them.
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
const triage = @import("triage.zig");
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

    fn integer(ctx: *Ctx, key: []const u8, min: i64, max: i64) Failure!i64 {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .integer) return ctx.invalid("argument \"{s}\" must be an integer", .{key});
        if (v.integer < min or v.integer > max) return ctx.invalid("argument \"{s}\" must be between {d} and {d}", .{ key, min, max });
        return v.integer;
    }

    fn integerOr(ctx: *Ctx, key: []const u8, default: i64, min: i64, max: i64) Failure!i64 {
        if (ctx.get(key) == null) return default;
        return ctx.integer(key, min, max);
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

    /// Refuses a `key` argument that resolveMailbox would have to guess:
    /// several folders match it once invisible characters are removed.
    fn unambiguous(ctx: *Ctx, boxes: []const imap.Mailbox, key: []const u8) Failure!void {
        const utf8 = try ctx.string(key);
        const encoded = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        if (try ambiguousMailbox(ctx.arena, boxes, utf8, encoded))
            return ctx.failed("mailbox name \"{s}\" is ambiguous; several folders have this name once invisible characters are removed. Rename them in a mail client first.", .{utf8});
    }

    /// Wire name of the folder create_message appends to (protected).
    fn drafts(ctx: *Ctx, idx: usize) Failure![]const u8 {
        return ctx.registry.drafts(idx, ctx.arena) catch |err| return ctx.imapFailed(err);
    }

    /// The account's mailbox list straight from the server (also refreshes
    /// the cache, so `mailbox()` resolves against it).
    fn freshList(ctx: *Ctx, idx: usize) Failure![]imap.Mailbox {
        return ctx.registry.mailboxList(idx, ctx.arena, true) catch |err| return ctx.imapFailed(err);
    }

    /// Wire name of a folder named in a plan action (UTF-8), resolved like
    /// `mailbox()` against `boxes`.
    fn wireName(ctx: *Ctx, boxes: []const imap.Mailbox, utf8: []const u8) Failure![:0]const u8 {
        try ctx.check(validate.mailbox(utf8));
        const encoded = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("destination \"{s}\" is not valid UTF-8", .{utf8}),
        };
        return ctx.arena.dupeSentinel(u8, try resolveMailbox(ctx.arena, boxes, utf8, encoded), 0);
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

const ParamKind = enum {
    string,
    string_array,
    boolean,
    integer,
    /// apply_organization's `actions`: [{uid, action, destination?}].
    actions,
};

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
    .{ .name = "organize_mailbox", .description = desc.organize_mailbox, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "Folder to organize", .default = "INBOX" },
        .{ .name = "limit", .kind = .integer, .description = "Newest messages to return, 1-200 (default 50)", .required = false },
        .{ .name = "criteria", .kind = .string, .description = "Optional IMAP SEARCH criteria narrowing the candidates, e.g. \"UNSEEN\" or \"SINCE 1-Oct-2026\"", .required = false },
        .{ .name = "include_reviewed", .kind = .boolean, .description = "true to include messages an earlier plan kept or flagged ($TpOrganized)", .required = false },
    }, .handler = organizeMailbox },
    .{ .name = "apply_organization", .description = desc.apply_organization, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "The folder passed to organize_mailbox" },
        .{ .name = "uidvalidity", .kind = .integer, .description = "uidvalidity returned by organize_mailbox" },
        .{ .name = "actions", .kind = .actions, .description = "One action per message: move (with destination), delete (to Trash), flag, or keep" },
        .{ .name = "execute", .kind = .boolean, .description = "true to perform the plan; default false (dry run)", .required = false },
        .{ .name = "plan_hash", .kind = .string, .description = "plan_hash from the dry run; required with execute=true", .required = false },
    }, .handler = applyOrganization },
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
                .integer => {
                    try jw.objectField("type");
                    try jw.write("integer");
                },
                .actions => {
                    try jw.objectField("type");
                    try jw.write("array");
                    try jw.objectField("items");
                    try jw.write(.{
                        .type = "object",
                        .properties = .{
                            .uid = .{ .type = "string" },
                            .action = .{ .type = "string", .@"enum" = [_][]const u8{ "move", "delete", "flag", "keep" } },
                            .destination = .{ .type = "string" },
                        },
                        .required = [_][]const u8{ "uid", "action" },
                    });
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
    try ctx.unambiguous(boxes, "name");
    if (organize.find(boxes, from) == null) return ctx.failed("mailbox \"{s}\" does not exist", .{try displayName(ctx.arena, from)});
    if (try organize.protectedReason(ctx.arena, boxes, from, try ctx.drafts(idx))) |r| return ctx.failed("{s}", .{r});
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
    try ctx.unambiguous(boxes, "name");
    const shown = try displayName(ctx.arena, name);
    const box = organize.find(boxes, name) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{shown});
    if (try organize.protectedReason(ctx.arena, boxes, name, try ctx.drafts(idx))) |r| return ctx.failed("{s}", .{r});
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
    // INBOX matches in any case: "INBOX" and "inbox" are one folder.
    if (organize.sameMailbox(boxes, source, destination)) return ctx.invalid("destination must differ from directory", .{});
    const source_shown = try displayName(ctx.arena, source);
    const src_box = organize.find(boxes, source) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{source_shown});
    if (!organize.selectable(src_box)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{source_shown});
    if (move) if (try organize.moveSourceReason(ctx.arena, src_box)) |r| return ctx.failed("{s}", .{r});
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
        const msg = if (op.progress.pending > 0)
            try partialMoveMessage(ctx.arena, op.progress.done, op.matched.len, op.progress.pending, dest_shown, source_shown, why)
        else if (op.progress.done > 0)
            try ctx.arena.print("{d} of {d} messages were {s} before the error: {s}", .{ op.progress.done, op.matched.len, if (move) "moved" else "copied", why })
        else
            try ctx.arena.dupe(u8, why);
        if (op.created) ctx.registry.mailboxesChanged(idx, ctx.arena);
        if (move and op.progress.done > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.matched[0..op.progress.done]);
        return ctx.failed("{s}", .{msg});
    };
    if (op.refused) |r| return ctx.failed("{s}", .{r});
    if (op.matched.len > organize.max_messages and !dry_run)
        return ctx.failed("{d} messages match; at most {d} per call. Narrow the criteria or split the work.", .{ op.matched.len, organize.max_messages });
    if (op.created) ctx.registry.mailboxesChanged(idx, ctx.arena);
    if (move and op.progress.done > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.matched[0..op.progress.done]);

    if (dry_run) {
        const preview = op.matched[0..@min(op.matched.len, organize.dry_run_preview)];
        const strs = try ctx.arena.alloc([]const u8, preview.len);
        for (preview, strs) |u, *o| o.* = try ctx.arena.print("{d}", .{u});
        return ctx.json(.{ .dry_run = true, .matched = op.matched.len, .uids = strs, .source = source_shown, .destination = dest_shown, .note = note });
    }
    var uid_map: ?[]UidPairJson = null;
    if (op.progress.map_complete and op.progress.pairs.items.len > 0) {
        const m = try ctx.arena.alloc(UidPairJson, op.progress.pairs.items.len);
        for (op.progress.pairs.items, m) |pair, *o| o.* = .{ .from = try ctx.arena.print("{d}", .{pair.from}), .to = try ctx.arena.print("{d}", .{pair.to}) };
        uid_map = m;
    }
    if (move) return ctx.json(.{ .moved = op.progress.done, .source = source_shown, .destination = dest_shown, .uid_map = uid_map, .note = note });
    return ctx.json(.{ .copied = op.progress.done, .source = source_shown, .destination = dest_shown, .uid_map = uid_map, .note = note });
}

/// First value of header `name`, decoded and sanitized; "" when absent.
fn firstField(arena: Allocator, hs: []const headers.Header, name: []const u8) Allocator.Error![]const u8 {
    for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return displayValue(arena, h.value);
    return "";
}

const OrganizeItem = struct {
    uid: []const u8,
    date: []const u8,
    from: []const u8,
    to: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    size: ?u32 = null,
    flags: ?[]const []const u8 = null,
    snippet: ?[]const u8 = null,
    withheld: ?[]const u8 = null,
};

const organize_next = "Classify every message using `instructions`: one action each (move with a destination from `folders`, delete, flag, or keep). Then call apply_organization with execute=false, show the user the grouped plan, and call it again with execute=true and the plan_hash only after the user confirms.";

/// organize_mailbox (spec §2.1): instructions, folders and the newest
/// candidate messages for the model to classify. Read-only.
fn organizeMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const limit_n: usize = @intCast(try ctx.integerOr("limit", triage.default_limit, 1, triage.max_limit));
    const include_reviewed = try ctx.booleanOr("include_reviewed", false);
    var command: []const u8 = if (include_reviewed) "ALL" else "NOT KEYWORD " ++ triage.reviewed_keyword;
    if (ctx.get("criteria") != null) {
        const criteria = try ctx.string("criteria");
        try ctx.check(validate.criteria(criteria));
        command = try ctx.arena.print("{s} ({s})", .{ command, criteria });
    }
    const instructions = switch (try triage.loadInstructions(ctx.arena, ctx.registry.io, ctx.registry.settings.config_dir, ctx.registry.accounts[idx].name)) {
        .ok => |i| i,
        .problem => |p| return ctx.failed("{s}", .{p}),
    };

    const boxes = try ctx.freshList(idx);
    const mailbox = try ctx.mailbox("directory", "INBOX");
    const shown = try displayName(ctx.arena, mailbox);
    const box = organize.find(boxes, mailbox) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{shown});
    if (!organize.selectable(box)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{shown});

    var op: GatherOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = &.{} },
        .active = ctx.registry.filtersFor(idx),
        .command = try ctx.arena.printSentinel("CHARSET UTF-8 {s}", .{command}, 0),
        .limit = limit_n,
    };
    try ctx.imapRun(idx, &op);

    const choices = try triage.folderChoices(ctx.arena, boxes, mailbox);
    const folders = try ctx.arena.alloc([]const u8, choices.len);
    var fixed: usize = limit.jsonLen(instructions.text) + 512;
    for (choices, folders) |c, *f| {
        f.* = try displayName(ctx.arena, c.name);
        fixed += limit.jsonLen(f.*) + 4;
    }
    const trash: ?[]const u8 = if (triage.trashFolder(boxes)) |t| try displayName(ctx.arena, t.name) else null;

    const header_items = try alignToUids(ctx.arena, op.uids, op.headers.result);
    const flag_items = try alignToUids(ctx.arena, op.uids, op.flags);
    const body_items = try alignToUids(ctx.arena, op.uids, op.bodies);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes -| fixed);
    var messages: std.ArrayList(OrganizeItem) = .empty;
    var omitted: usize = 0;
    for (op.uids, header_items, flag_items, body_items) |u, h, f, b| {
        const raw = (h orelse continue).data orelse continue; // vanished meanwhile
        const hs = try headers.parse(ctx.arena, raw);
        var item: OrganizeItem = .{
            .uid = try ctx.arena.print("{d}", .{u}),
            .date = try firstField(ctx.arena, hs, "date"),
            .from = try firstField(ctx.arena, hs, "from"),
        };
        if (op.withheld.get(u)) |name| {
            item.withheld = name;
        } else {
            item.to = try firstField(ctx.arena, hs, "to");
            item.subject = try firstField(ctx.arena, hs, "subject");
            item.size = h.?.size;
            item.flags = if (f) |x| x.flags else null;
            const rendered = if (b) |x| body.render(ctx.arena, x.data orelse "", .plain, triage.partial_bytes) catch "" else "";
            item.snippet = try triage.snippet(ctx.arena, rendered);
        }
        const size = limit.jsonLen(item.date) + limit.jsonLen(item.from) + limit.jsonLen(item.to orelse "") +
            limit.jsonLen(item.subject orelse "") + limit.jsonLen(item.snippet orelse "") + 160;
        if (!admitItem(&budget, size, item.withheld)) {
            omitted += 1;
            continue;
        }
        try messages.append(ctx.arena, item);
    }
    return Stringify.valueAlloc(ctx.arena, .{
        .account = ctx.registry.accounts[idx].name,
        .directory = shown,
        .uidvalidity = op.uidvalidity,
        .instructions = instructions.text,
        .instructions_source = instructions.source,
        .folders = folders,
        .trash = trash,
        .messages = messages.items,
        .omitted = omitted,
        .next = organize_next,
    }, .{ .emit_null_optional_fields = false });
}

const PlanMessage = struct { uid: []const u8, from: []const u8, subject: []const u8 };

/// apply_organization (spec §2.2): validates the model's plan, shows it as a
/// dry run, or executes it when `execute` and the dry run's plan_hash match.
fn applyOrganization(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const uidvalidity: u32 = @intCast(try ctx.integer("uidvalidity", 1, std.math.maxInt(u32)));
    const actions = switch (try triage.parseActions(ctx.arena, ctx.get("actions"))) {
        .ok => |a| a,
        .problem => |p| return ctx.invalid("{s}", .{p}),
    };
    const execute = try ctx.booleanOr("execute", false);
    if (execute and ctx.get("plan_hash") == null)
        return ctx.invalid("execute=true needs the plan_hash from a dry run (execute=false)", .{});
    const given_hash = if (execute) try ctx.string("plan_hash") else "";
    if (execute) try ctx.writable(idx);

    const boxes = try ctx.freshList(idx);
    const source = try ctx.mailbox("directory", null);
    const source_shown = try displayName(ctx.arena, source);
    const src_box = organize.find(boxes, source) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{source_shown});
    if (!organize.selectable(src_box)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{source_shown});

    const groups = try triage.group(ctx.arena, actions);
    const dests = try ctx.arena.alloc([:0]const u8, groups.len);
    const dests_shown = try ctx.arena.alloc([]const u8, groups.len);
    var moves_out = false;
    for (groups, dests, dests_shown) |g, *d, *ds| {
        d.* = "";
        ds.* = "";
        switch (g.kind) {
            .move => {
                d.* = try ctx.wireName(boxes, g.destination.?);
                if (try triage.destinationProblem(ctx.arena, boxes, source, d.*, g.destination.?)) |p| return ctx.failed("{s}", .{p});
                ds.* = try displayName(ctx.arena, d.*);
                moves_out = true;
            },
            .delete => {
                const t = triage.trashFolder(boxes) orelse
                    return ctx.failed("this account has no Trash folder (\\Trash), so \"delete\" is not available", .{});
                if (organize.sameMailbox(boxes, source, t.name)) return ctx.failed("\"{s}\" is the Trash folder; \"delete\" is not available here", .{source_shown});
                d.* = try ctx.arena.dupeSentinel(u8, t.name, 0);
                ds.* = try displayName(ctx.arena, t.name);
                moves_out = true;
            },
            .flag, .keep => {},
        }
    }
    if (moves_out) if (try organize.moveSourceReason(ctx.arena, src_box)) |r| return ctx.failed("{s}", .{r});

    const hash = try triage.planHash(ctx.arena, ctx.registry.accounts[idx].name, source, uidvalidity, actions);
    if (execute and !std.mem.eql(u8, given_hash, &hash))
        return ctx.failed("plan_hash does not match these actions; run a dry run (execute=false) and show it to the user again", .{});

    const uids = try ctx.arena.alloc(u32, actions.len);
    for (actions, uids) |a, *u| u.* = a.uid;
    var op: ApplyOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = source, .uids = uids },
        .active = ctx.registry.filtersFor(idx),
        .expected_uidvalidity = uidvalidity,
        .execute = execute,
        .groups = groups,
        .dests = dests,
        .steps = try executionOrder(ctx.arena, groups),
    };
    ctx.registry.run(idx, &op) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const d = ctx.registry.diag();
        const why = if (d.len > 0) d else @errorName(err);
        const msg = try applyFailureMessage(ctx.arena, &op, dests_shown, source_shown, why);
        if (op.moved.items.len > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.moved.items);
        return ctx.failed("{s}", .{msg});
    };
    if (op.refused) |r| return ctx.failed("{s}", .{r});
    if (op.moved.items.len > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.moved.items);

    var missing: std.ArrayList([]const u8) = .empty;
    for (uids) |u| if (!op.present.contains(u)) try missing.append(ctx.arena, try ctx.arena.print("{d}", .{u}));

    if (!execute) {
        const Out = struct { action: []const u8, destination: ?[]const u8 = null, count: usize, messages: ?[]PlanMessage = null };
        const header_items = try alignToUids(ctx.arena, uids, op.headers.result);
        const out = try ctx.arena.alloc(Out, groups.len);
        for (groups, dests_shown, out) |g, ds, *o| {
            var count: usize = 0;
            var listed: std.ArrayList(PlanMessage) = .empty;
            for (g.uids) |u| {
                if (!op.present.contains(u)) continue;
                count += 1;
                if (g.kind == .keep) continue;
                const i = std.mem.findScalar(u32, uids, u).?;
                const hs = try headers.parse(ctx.arena, header_items[i].?.data orelse "");
                try listed.append(ctx.arena, .{
                    .uid = try ctx.arena.print("{d}", .{u}),
                    .from = try firstField(ctx.arena, hs, "from"),
                    .subject = try firstField(ctx.arena, hs, "subject"),
                });
            }
            o.* = .{
                .action = @tagName(g.kind),
                .destination = if (ds.len > 0) ds else null,
                .count = count,
                .messages = if (g.kind == .keep) null else listed.items,
            };
        }
        return Stringify.valueAlloc(ctx.arena, .{ .dry_run = true, .plan_hash = &hash, .groups = out, .missing = missing.items }, .{ .emit_null_optional_fields = false });
    }

    const Moved = struct { destination: []const u8, count: usize };
    var moved: std.ArrayList(Moved) = .empty;
    var deleted: usize = 0;
    var flagged: usize = 0;
    var kept: usize = 0;
    for (groups, dests_shown, op.counts) |g, ds, n| switch (g.kind) {
        .move => try moved.append(ctx.arena, .{ .destination = ds, .count = n }),
        .delete => deleted = n,
        .flag => flagged = n,
        .keep => kept = n,
    };
    const note: ?[]const u8 = if (op.keyword_refused)
        "the server refused the $TpOrganized keyword; kept and flagged messages will be offered again by organize_mailbox"
    else
        null;
    return Stringify.valueAlloc(ctx.arena, .{
        .executed = true,
        .flagged = flagged,
        .moved = moved.items,
        .deleted = deleted,
        .kept = kept,
        .missing = missing.items,
        .note = note,
    }, .{ .emit_null_optional_fields = false });
}

/// What an interrupted plan did and did not do (spec §2.2).
fn applyFailureMessage(arena: Allocator, op: *const ApplyOp, dests_shown: []const []const u8, source_shown: []const u8, why: []const u8) Allocator.Error![]const u8 {
    var done: std.ArrayList(u8) = .empty;
    var not_done: std.ArrayList(u8) = .empty;
    var at: []const u8 = "";
    for (op.steps, 0..) |gi, step| {
        const label = try stepLabel(arena, op.groups, gi, dests_shown, op.presentCount(op.groups[gi].uids));
        if (step < op.completed) {
            try done.print(arena, "{s}{s}", .{ if (done.items.len > 0) "; " else "", label });
        } else if (step == op.completed) {
            const g = op.groups[gi];
            const total = op.presentCount(g.uids);
            at = if ((g.kind == .move or g.kind == .delete) and op.current.pending > 0)
                try partialMoveMessage(arena, op.current.done, total, op.current.pending, dests_shown[gi], source_shown, why)
            else if (op.current.done > 0)
                try arena.print("{s}: {d} of {d} were moved before the error: {s}", .{ label, op.current.done, total, why })
            else
                try arena.print("{s}: {s}", .{ label, why });
        } else {
            try not_done.print(arena, "{s}{s}", .{ if (not_done.items.len > 0) "; " else "", label });
        }
    }
    if (op.completed >= op.steps.len) at = try arena.print("marking reviewed messages: {s}", .{why});
    return arena.print("the plan stopped at {s}. Completed: {s}. Not attempted: {s}.", .{
        at,
        if (done.items.len > 0) done.items else "nothing",
        if (not_done.items.len > 0) not_done.items else "nothing",
    });
}

fn stepLabel(arena: Allocator, groups: []const triage.Group, gi: usize, dests_shown: []const []const u8, n: usize) Allocator.Error![]const u8 {
    return switch (groups[gi].kind) {
        .move => arena.print("move {d} to \"{s}\"", .{ n, dests_shown[gi] }),
        .delete => arena.print("delete {d} (to \"{s}\")", .{ n, dests_shown[gi] }),
        .flag => arena.print("flag {d}", .{n}),
        .keep => arena.print("keep {d}", .{n}),
    };
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
        _ = try s.examine("INBOX"); // leave the folder if a move selected it
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
        // Leave the folder if a move selected it: no STATUS or DELETE of the
        // selected mailbox (RFC 3501 6.3.10; some servers refuse).
        _ = try s.examine("INBOX");
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
    /// Messages moved/copied so far: a prefix of `matched`.
    progress: Batches = .{},

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
        try self.progress.run(self.arena, s, self.matched, self.destination, self.move, strategy);
    }
};

/// Batched UID MOVE (or COPY + \Deleted + UID EXPUNGE under the fallback
/// strategy), or UID COPY when `move` is false, of `uids` from the selected
/// mailbox to `dest` (ADR 0021, spec §4.2). Records how far it got.
const Batches = struct {
    /// Messages moved/copied so far: a prefix of the UIDs passed to `run`.
    done: usize = 0,
    /// Size of the batch the copy+expunge fallback copied but failed to
    /// remove (0 otherwise).
    pending: usize = 0,
    pairs: std.ArrayList(organize.UidPair) = .empty,
    map_complete: bool = true,

    fn run(self: *Batches, arena: Allocator, s: *Session, uids: []const u32, dest: [:0]const u8, move: bool, strategy: organize.MoveStrategy) accounts.Error!void {
        for (0..organize.batchCount(uids.len)) |i| {
            const b = organize.batch(uids, i);
            const cu = try s.uidTransfer(arena, b, dest, move and strategy == .move);
            if (move and strategy == .copy_expunge) {
                s.uidStoreFlags(arena, b, true, &.{"\\Deleted"}) catch |err| {
                    self.pending = b.len;
                    return err;
                };
                s.uidExpunge(b) catch |err| {
                    self.pending = b.len;
                    return err;
                };
            }
            self.done += b.len;
            if (try organize.uidMap(arena, cu)) |m| try self.pairs.appendSlice(arena, m) else self.map_complete = false;
        }
    }
};

/// organize_mailbox's IMAP work: the newest candidates, their headers (cached
/// where possible), flags, and the first bytes of the allowed bodies.
const GatherOp = struct {
    arena: Allocator,
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    /// UID SEARCH arguments.
    command: [:0]const u8,
    limit: usize,

    uidvalidity: u32 = 0,
    /// Newest first, at most `limit`.
    uids: []const u32 = &.{},
    flags: []Fetched = &.{},
    bodies: []Fetched = &.{},
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,

    pub fn run(self: *GatherOp, s: *Session) accounts.Error!void {
        // A retry after reconnect starts from scratch.
        self.withheld.clearRetainingCapacity();
        self.uids = &.{};
        self.flags = &.{};
        self.bodies = &.{};
        self.uidvalidity = try s.examine(self.headers.mailbox);
        const found = try s.uidSearch(self.arena, self.command);
        std.mem.sort(u32, found, {}, std.sort.desc(u32));
        self.uids = found[0..@min(found.len, self.limit)];
        if (self.uids.len == 0) return;
        self.headers.uids = self.uids;
        try self.headers.afterExamine(s, self.uidvalidity);
        self.flags = try s.uidFetch(self.arena, self.uids, .{ .flags = true });
        const allowed = try classifyForBodies(self.arena, self.active, self.uids, self.headers.result, &self.withheld);
        if (allowed.len > 0) self.bodies = try s.uidFetch(self.arena, allowed, .{ .body = true, .partial = true });
    }
};

/// apply_organization's IMAP work (spec §2.2): checks UIDVALIDITY, which UIDs
/// exist and which are withheld; when executing, flags, moves, deletes (to
/// Trash) and marks the reviewed messages, in that order.
const ApplyOp = struct {
    arena: Allocator,
    /// `uids`: every UID in the plan.
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    expected_uidvalidity: u32,
    execute: bool,
    groups: []const triage.Group,
    /// Per group: destination wire name (move), the Trash folder (delete), "".
    dests: []const [:0]const u8,
    /// Group indices in execution order (from `executionOrder`).
    steps: []const usize,

    uidvalidity: u32 = 0,
    refused: ?[]const u8 = null,
    present: std.AutoHashMapUnmanaged(u32, void) = .empty,
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    /// Execution steps finished (an index into `order(groups)`).
    completed: usize = 0,
    /// Progress inside the step being executed.
    current: Batches = .{},
    /// Messages moved out of the folder (moves and deletes), for the cache.
    moved: std.ArrayList(u32) = .empty,
    /// Messages acted on per group (present ones).
    counts: []usize = &.{},
    keyword_refused: bool = false,

    // Not retried: a resent MOVE or STORE after a partial run is ambiguous.
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while applying the plan; part of it may have been done. Run organize_mailbox again to see the current state.";

    pub fn run(self: *ApplyOp, s: *Session) accounts.Error!void {
        self.uidvalidity = if (self.execute) try s.select(self.headers.mailbox) else try s.examine(self.headers.mailbox);
        if (self.uidvalidity != self.expected_uidvalidity) {
            self.refused = "the folder changed since organize_mailbox (UIDVALIDITY differs); run organize_mailbox again";
            return;
        }
        try self.headers.afterExamine(s, self.uidvalidity);
        for (self.headers.result) |f| if (f.data != null) try self.present.put(self.arena, f.uid, {});
        _ = try classifyForBodies(self.arena, self.active, self.headers.uids, self.headers.result, &self.withheld);
        for (self.groups) |g| {
            if (g.kind == .keep) continue;
            for (g.uids) |u| if (self.withheld.get(u)) |name| {
                self.refused = try self.arena.print("message {d} is withheld by filter \"{s}\"; only \"keep\" is allowed", .{ u, name });
                return;
            };
        }
        self.counts = try self.arena.alloc(usize, self.groups.len);
        for (self.groups, self.counts) |g, *n| n.* = self.presentCount(g.uids);
        if (!self.execute) return;

        var strategy: organize.MoveStrategy = .move;
        for (self.groups) |g| if (g.kind == .move or g.kind == .delete) {
            strategy = organize.moveStrategy(try s.capabilities());
            break;
        };
        if (strategy == .unsupported) {
            self.refused = unsupported_move;
            return;
        }
        for (self.steps) |gi| {
            const g = self.groups[gi];
            const ids = try self.presentUids(g.uids);
            self.current = .{};
            switch (g.kind) {
                .flag => for (0..organize.batchCount(ids.len)) |i| {
                    try s.uidStoreFlags(self.arena, organize.batch(ids, i), true, &.{"\\Flagged"});
                },
                .move, .delete => {
                    try self.current.run(self.arena, s, ids, self.dests[gi], true, strategy);
                    try self.moved.appendSlice(self.arena, ids);
                },
                .keep => {},
            }
            self.completed += 1;
        }
        var reviewed: std.ArrayList(u32) = .empty;
        for (self.groups) |g| if (g.kind == .flag or g.kind == .keep) try reviewed.appendSlice(self.arena, try self.presentUids(g.uids));
        for (0..organize.batchCount(reviewed.items.len)) |i| {
            s.uidStoreFlags(self.arena, organize.batch(reviewed.items, i), true, &.{triage.reviewed_keyword}) catch |err| switch (err) {
                error.ServerRejected => {
                    self.keyword_refused = true;
                    break;
                },
                else => return err,
            };
        }
    }

    fn presentCount(self: *const ApplyOp, uids: []const u32) usize {
        var n: usize = 0;
        for (uids) |u| {
            if (self.present.contains(u)) n += 1;
        }
        return n;
    }

    fn presentUids(self: *const ApplyOp, uids: []const u32) Allocator.Error![]const u32 {
        var out: std.ArrayList(u32) = .empty;
        for (uids) |u| if (self.present.contains(u)) try out.append(self.arena, u);
        return out.items;
    }
};

/// Group indices in execution order (spec §2.2): flag first, then the moves,
/// then delete, keep last.
fn executionOrder(arena: Allocator, groups: []const triage.Group) Allocator.Error![]const usize {
    var out: std.ArrayList(usize) = .empty;
    for ([_]triage.Kind{ .flag, .move, .delete, .keep }) |k| {
        for (groups, 0..) |g, i| if (g.kind == k) try out.append(arena, i);
    }
    return out.items;
}

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

/// True when no mailbox is named `encoded` exactly but several match `utf8`
/// after invisible-character cleaning (resolveMailbox would pick the first).
fn ambiguousMailbox(arena: Allocator, boxes: []const imap.Mailbox, utf8: []const u8, encoded: []const u8) Allocator.Error!bool {
    for (boxes) |b| if (std.mem.eql(u8, b.name, encoded)) return false;
    var n: usize = 0;
    for (boxes) |b| {
        const decoded = mutf7.decode(arena, b.name) catch continue;
        if (std.mem.eql(u8, try unicode.clean(arena, decoded), utf8)) n += 1;
    }
    return n > 1;
}

/// Error text when the copy+expunge fallback fails at batch k: batches
/// before it were moved, batch k (`pending`) copied but not removed, later
/// ones not touched.
fn partialMoveMessage(arena: Allocator, done: usize, total: usize, pending: usize, destination: []const u8, source: []const u8, why: []const u8) Allocator.Error![]const u8 {
    const rest = total -| (done + pending);
    const untouched = if (rest > 0) try arena.print("; the remaining {d} were not touched", .{rest}) else "";
    return arena.print("{d} of {d} messages were moved; the next {d} were copied to \"{s}\" but not removed from \"{s}\" (they may be flagged \\Deleted){s}: {s}", .{ done, total, pending, destination, source, untouched, why });
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
Expected: `203/203 tests passed`.

- [ ] **Step 7: Commit**

```bash
git add src/descriptions.zig src/mcp.zig src/tools.zig
git commit -m "feat(triage): organize_mailbox gathers, apply_organization dry-runs or executes a plan"
```

---

### Task 4: The organize_my_mailbox prompt

**Files:**
- Modify: `src/prompts.zig`

**Interfaces:**
- Produces: `Prompt.arguments: []const Argument` (`Argument{ name, description, required }`), written by `prompts/list`; prompt `organize_my_mailbox` with optional `account` and `directory`.

- [ ] **Step 1: Write the failing tests**

In `src/prompts.zig`, replace everything from the line `const testing = std.testing;` to the end of the file with:

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

test "organize_my_mailbox: optional account and directory" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const plain = try render(a, "organize_my_mailbox", null);
    try testing.expect(std.mem.startsWith(u8, plain, "Organize the folder \"INBOX\" of the account I name"));
    try testing.expect(std.mem.find(u8, plain, "execute=false") != null);
    try testing.expect(std.mem.find(u8, plain, "plan_hash") != null);
    var args: std.json.ObjectMap = .empty;
    try args.put(a, "account", .{ .string = "work" });
    try args.put(a, "directory", .{ .string = "Archive" });
    try testing.expect(std.mem.startsWith(u8, try render(a, "organize_my_mailbox", args), "Organize the folder \"Archive\" of account \"work\"."));
}

test "prompts/list marks organize_my_mailbox arguments optional" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    try testing.expect(std.mem.find(u8, aw.written(), "{\"name\":\"cover_letter\",\"required\":true}") != null);
    try testing.expect(std.mem.find(u8, aw.written(), "\"name\":\"account\",\"description\":\"Account name (default: ask, or the only account)\",\"required\":false") != null);
}
```
- [ ] **Step 2: Run the tests and confirm they fail**

Run: `zig build test --summary all`
Expected: compilation fails (the code under test does not exist yet).

- [ ] **Step 3: Implement**

In `src/prompts.zig`, replace everything **above** the line `const testing = std.testing;` with:

```zig
//! MCP prompts: two carried over verbatim from vivier/imap-mcp-server (spec
//! §6.1), plus organize_my_mailbox (organize-mailbox spec §2.3).

const std = @import("std");
const Stringify = std.json.Stringify;

const Argument = struct {
    name: []const u8,
    description: []const u8 = "",
    required: bool = true,
};

const Prompt = struct {
    name: []const u8,
    description: []const u8,
    arguments: []const Argument = &.{},
};

pub const prompts = [_]Prompt{
    .{
        .name = "list_patches_of_a_series",
        .description = "Generates a user message to list all patches in a series given a cover letter.\nFor a cover letter [PATCH 0/X], this will find patches [PATCH 1/X] to [PATCH X/X]",
        .arguments = &.{.{ .name = "cover_letter" }},
    },
    .{
        .name = "review_a_patch_series",
        .description = "Generates a user message with instructions on how to properly review a patch series",
    },
    .{
        .name = "organize_my_mailbox",
        .description = "Organize a mailbox: classify the newest messages (move, delete to Trash, flag, keep), show the plan as a dry run, and carry it out only after confirmation.",
        .arguments = &.{
            .{ .name = "account", .description = "Account name (default: ask, or the only account)", .required = false },
            .{ .name = "directory", .description = "Folder to organize (default INBOX)", .required = false },
        },
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
        for (p.arguments) |a| {
            try jw.beginObject();
            try jw.objectField("name");
            try jw.write(a.name);
            if (a.description.len > 0) {
                try jw.objectField("description");
                try jw.write(a.description);
            }
            try jw.objectField("required");
            try jw.write(a.required);
            try jw.endObject();
        }
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
    if (std.mem.eql(u8, name, "organize_my_mailbox")) {
        const account = optionalString(args, "account");
        const directory = optionalString(args, "directory") orelse "INBOX";
        const who = if (account) |a|
            try arena.print("account \"{s}\"", .{a})
        else
            "the account I name (call list_accounts and ask me if it is not obvious)";
        return arena.print(organize_text, .{ directory, who });
    }
    if (std.mem.eql(u8, name, "review_a_patch_series")) {
        return "When replying to reviews or patch series: reply to each message individually, include the full original message inline, and place your comment directly beneath the specific line you are annotating. Format your answer on 80 columns";
    }
    return error.UnknownPrompt;
}

fn optionalString(args: ?std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = (args orelse return null).get(key) orelse return null;
    if (v != .string or v.string.len == 0) return null;
    return v.string;
}

const organize_text =
    \\Organize the folder "{s}" of {s}.
    \\
    \\1. Call organize_mailbox for it. Read the returned "instructions" and follow them.
    \\2. Classify every returned message: move (to a folder from "folders"), delete (moves to Trash), flag (needs my attention), or keep. Messages marked "withheld" must be keep.
    \\3. Call apply_organization with execute=false and show me the plan: for each group, the count and the senders and subjects; mention anything you left alone on purpose and any new folders you would suggest.
    \\4. Only after I confirm, call apply_organization again with the same actions, execute=true and the plan_hash from step 3. If I change the plan, run step 3 again first.
    \\5. If more messages remain, offer to continue with the next batch.
;
```
- [ ] **Step 4: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `205/205 tests passed`.

- [ ] **Step 5: Commit**

```bash
git add src/prompts.zig
git commit -m "feat(triage): organize_my_mailbox prompt"
```

---

### Task 5: Live checks and documentation

**Files:**
- Modify: `src/itest.zig`, `README.md`, `docs/adr/README.md`
- Create: `docs/adr/0022-organize-mailbox-two-phase-plan.md`

**Interfaces:**
- Consumes: the two tools and the prompt; the existing `--organize` throwaway folders in `itest.zig`.
- Produces: 6 `triage:` live checks at the end of `--organize` (49 checks in total); ADR 0022; README rows, the "Organize my mailbox" section, layout and roadmap lines.

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
    // Folders this run created, newest (deepest) first; only these are
    // cleaned up, so a pre-existing folder of the same name is never touched.
    var made: std.ArrayList([:0]const u8) = .empty;
    defer {
        var cleanup: Cleanup = .{ .arena = h.arena, .boxes = made.items };
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
    if (ca != null) try made.insert(h.arena, 0, try h.arena.dupeSentinel(u8, a, 0));
    const cb = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, b });
    if (cb != null) try made.insert(h.arena, 0, try h.arena.dupeSentinel(u8, b, 0));
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
    if (renamed != null) for (made.items) |*m| {
        if (std.mem.eql(u8, m.*, b)) m.* = try h.arena.dupeSentinel(u8, ab, 0);
    };
    const nonempty = try h.call("delete_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, a });
    report(nonempty == null, "organize: delete_mailbox refuses a non-empty folder", .{});
    const inbox = try h.call("rename_mailbox", "{{\"account\":{s},\"name\":\"INBOX\",\"new_name\":\"{s}-inbox\"}}", .{ acct, a });
    report(inbox == null, "organize: INBOX cannot be renamed", .{});
    const deleted = try h.call("delete_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, ab });
    report(deleted != null, "organize: delete_mailbox removes an empty folder", .{});

    try triageChecks(h, reg, idx, acct, a, &made, rnd);
}

fn stringField(v: ?std.json.Value, key: []const u8) ?[]const u8 {
    const o = v orelse return null;
    if (o != .object) return null;
    const f = o.object.get(key) orelse return null;
    return if (f == .string) f.string else null;
}

fn hasFlags(v: ?std.json.Value, uid: []const u8, wanted: []const []const u8) bool {
    const o = v orelse return false;
    if (o != .array or o.array.items.len != 1) return false;
    const flags = o.array.items[0].object.get(uid) orelse return false;
    if (flags != .array) return false;
    for (wanted) |w| {
        for (flags.array.items) |f| {
            if (std.mem.eql(u8, f.string, w)) break;
        } else return false;
    }
    return true;
}

/// ADR 0022 on folder `a`, which holds two test messages: gather, dry run,
/// refused wrong hash, execute (move, flag, keep), and the $TpOrganized skip.
/// Creates `<a>-d` as the move destination (cleaned up with the others).
fn triageChecks(h: Harness, reg: *Registry, idx: usize, acct: []const u8, a: []const u8, made: *std.ArrayList([:0]const u8), rnd: [4]u8) !void {
    const d = try h.arena.print("{s}-d", .{a});
    const cd = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, d });
    if (cd != null) try made.insert(h.arena, 0, try h.arena.dupeSentinel(u8, d, 0));
    const msg = try h.arena.print("From: itest@example.invalid\r\nTo: itest@example.invalid\r\nSubject: tp-imap-mcp triage itest {x}\r\nDate: Thu, 08 Oct 2026 12:00:00 +0000\r\nMessage-ID: <t{x}@tp-imap-mcp.invalid>\r\n\r\nThird test message; safe to delete.\r\n", .{ rnd, rnd });
    var append: AppendTo = .{ .mailbox = try h.arena.dupeSentinel(u8, a, 0), .data = msg };
    reg.run(idx, &append) catch {};

    const gathered = try h.call("organize_mailbox", "{{\"account\":{s},\"directory\":\"{s}\",\"limit\":10}}", .{ acct, a });
    const msgs = if (gathered) |g| g.object.get("messages").?.array.items else &.{};
    report(msgs.len == 3 and stringField(gathered, "instructions") != null, "triage: organize_mailbox lists the 3 test messages with instructions", .{});
    if (msgs.len != 3) return;
    const uv = gathered.?.object.get("uidvalidity").?.integer;
    const first = msgs[0].object.get("uid").?.string;
    const second = msgs[1].object.get("uid").?.string;
    const third = msgs[2].object.get("uid").?.string;
    const actions = try h.arena.print("[{{\"uid\":\"{s}\",\"action\":\"move\",\"destination\":\"{s}\"}},{{\"uid\":\"{s}\",\"action\":\"flag\"}},{{\"uid\":\"{s}\",\"action\":\"keep\"}}]", .{ first, d, second, third });
    const base = "{{\"account\":{s},\"directory\":\"{s}\",\"uidvalidity\":{d},\"actions\":{s}";

    const dry = try h.call("apply_organization", base ++ "}}", .{ acct, a, uv, actions });
    const hash = stringField(dry, "plan_hash");
    report(hash != null and (try messagesIn(h, acct, a)) == 3 and (try messagesIn(h, acct, d)) == 0, "triage: dry run returns a plan_hash and changes nothing", .{});
    if (hash == null) return;
    const wrong = try h.call("apply_organization", base ++ ",\"execute\":true,\"plan_hash\":\"0000000000000000\"}}", .{ acct, a, uv, actions });
    report(wrong == null, "triage: execute with a wrong plan_hash is refused", .{});
    const done = try h.call("apply_organization", base ++ ",\"execute\":true,\"plan_hash\":\"{s}\"}}", .{ acct, a, uv, actions, hash.? });
    report(intField(done, "flagged") == 1 and intField(done, "kept") == 1 and (try messagesIn(h, acct, a)) == 2 and (try messagesIn(h, acct, d)) == 1, "triage: execute moves one, flags one, keeps one", .{});
    const kw = try h.call("get_keywords", "{{\"account\":{s},\"directory\":\"{s}\",\"uids\":[\"{s}\"]}}", .{ acct, a, second });
    report(hasFlags(kw, second, &.{ "\\Flagged", "$TpOrganized" }), "triage: flagged message carries \\Flagged and $TpOrganized", .{});
    const again = try h.call("organize_mailbox", "{{\"account\":{s},\"directory\":\"{s}\",\"limit\":10}}", .{ acct, a });
    report(again != null and again.?.object.get("messages").?.array.items.len == 0, "triage: reviewed messages are skipped next time", .{});
}
```
- [ ] **Step 2: Write `docs/adr/0022-organize-mailbox-two-phase-plan.md`**

Replace (or create) the whole file:

```markdown
# 0022. Organize a mailbox as a model-classified, server-validated two-phase plan

- Status: Accepted
- Date: 2026-10-08

## Context

The user wants one action that triages a folder: for each recent message,
move it to a folder, delete it, flag it as needing attention, or keep it,
following their own organizing instructions or a built-in default, shown as a
dry run and carried out only when they confirm.

- **Who classifies.** An MCP server cannot run the model itself. MCP
  "sampling" (the server asking the client's model) is not supported by
  Claude Code, the target client. Options: classify in the conversation's
  model with server-side gathering and validation; a prompt-only workflow on
  the existing tools; sampling.
- **Safety.** A plan can touch hundreds of messages. The model may err, and
  message content can carry prompt injection. Sensitive mail (password
  resets, codes) is withheld from the model (ADR 0017), so it cannot be
  classified reliably.
- **Re-runs.** Working through a backlog means running repeatedly on the
  newest messages; messages kept last time would come back every run.

## Decision

- Two tools and one MCP prompt. `organize_mailbox` (read-only) returns the
  organizing instructions (`<config_dir>/organize.<account>.md`, else
  `organize.md`, else built-in), the folders, the Trash folder, and the
  newest candidate messages with sanitized headers and a short snippet.
  `apply_organization` validates the model's actions and returns a grouped
  dry run with a `plan_hash`; with `execute=true` and that hash it carries
  the plan out. The prompt `organize_my_mailbox` tells the model the
  workflow: gather, classify, dry run, confirm, execute.
- "Delete" moves to the `\Trash` folder; nothing is expunged by the user's
  plan. "Needs attention" sets `\Flagged`.
- Withheld messages accept only "keep", enforced by the server.
- Execution requires the dry run's `plan_hash` (SHA-256 over account, folder,
  UIDVALIDITY and the sorted actions), so what runs is exactly what was
  shown; the UIDVALIDITY must still match.
- Kept and flagged messages get the keyword `$TpOrganized`; the next
  `organize_mailbox` skips them unless `include_reviewed=true`.
- Moves reuse ADR 0021's machinery (MOVE, else COPY + UID EXPUNGE, else
  refuse; protected folders; no retry after a lost connection).

## Consequences

- Works with today's MCP clients; the model's judgment is bounded by server
  validation and a hash-checked confirmation step.
- Classification costs model tokens per message (headers plus a 500-character
  snippet; at most 200 messages per call).
- `$TpOrganized` is visible in clients that show keywords; servers that refuse
  custom keywords re-offer kept messages (the result says so).
- The plan cannot create folders; the model suggests them and the user creates
  them with `create_mailbox`.
```
- [ ] **Step 3: Edit `docs/adr/README.md`**

Replace every occurrence of

```markdown
| [0021](0021-mailbox-organization-tools.md) | Add folder and move/copy tools with safe moves, protected folders and dry runs | Accepted |
```

with

```markdown
| [0021](0021-mailbox-organization-tools.md) | Add folder and move/copy tools with safe moves, protected folders and dry runs | Accepted |
| [0022](0022-organize-mailbox-two-phase-plan.md) | Organize a mailbox as a model-classified, server-validated two-phase plan | Accepted |
```
- [ ] **Step 4: Edit `README.md`**

Replace every occurrence of

```markdown
| `move_messages` / `copy_messages` | Move or copy messages by `uids` or by search `criteria`; criteria default to a dry run |
```

with

```markdown
| `move_messages` / `copy_messages` | Move or copy messages by `uids` or by search `criteria`; criteria default to a dry run |
| `organize_mailbox` | Gather the organizing instructions, folders and newest messages for the model to classify |
| `apply_organization` | Preview (dry run) or carry out the model's per-message plan: move, delete (to Trash), flag, keep |
```
- [ ] **Step 5: Edit `README.md`**

Replace every occurrence of

```markdown
A typical exchange: *"Move all newsletters from news@example.com in INBOX to Newsletters"* → the assistant runs a dry run (`matched: 42`), shows you the count, then repeats the call with `dry_run=false`.
```

with

````markdown
A typical exchange: *"Move all newsletters from news@example.com in INBOX to Newsletters"* → the assistant runs a dry run (`matched: 42`), shows you the count, then repeats the call with `dry_run=false`.

### Organize my mailbox

Ask *"organize my inbox"*, or in Claude Code run `/mcp__tp-imap-mcp__organize_my_mailbox` ([ADR 0022](docs/adr/0022-organize-mailbox-two-phase-plan.md)):

1. `organize_mailbox` returns your organizing instructions, your folders and the newest 50 messages (sanitized headers plus a short snippet; messages hidden by a filter show only date and sender).
2. The assistant classifies each message: **move** to a folder, **delete** (moved to Trash, never erased), **flag** (needs your attention), or **keep**.
3. `apply_organization` shows the plan grouped by action, as a dry run. Nothing changes.
4. Only after you confirm does it run again with `execute=true` and the dry run's `plan_hash`. A changed plan needs a new dry run.

Kept and flagged messages get the keyword `$TpOrganized`, so the next run continues with messages it has not seen. Withheld messages (password resets, codes) are always kept; the server refuses anything else for them.

Write your own instructions in `~/.config/tp-imap-mcp/organize.md`, or `organize.<account>.md` for one account (Markdown, at most 16 KiB, read on every run). Without one, the built-in [default](src/organize_prompt.md) is used. A short example:

```markdown
# How to organize my mail
- Receipts and order confirmations go to "Receipts/2026".
- Newsletters I read: move to "Newsletters". Other marketing: delete.
- Anything from my accountant or my bank: flag.
- Never touch password, login or verification emails: keep.
- When unsure: keep.
```
````
- [ ] **Step 6: Edit `README.md`**

Replace every occurrence of

```markdown
- **Command injection:** search criteria cannot contain CR/LF/NUL; UIDs, keywords, and header names are validated.
- **Read-only accounts:** write tools refuse before contacting the server (dry runs of `move_messages` / `copy_messages` are allowed).
```

with

```markdown
- **Command injection:** search criteria cannot contain CR/LF/NUL; UIDs, keywords, and header names are validated.
- **Read-only accounts:** write tools refuse before contacting the server (dry runs of `move_messages` / `copy_messages` / `apply_organization` are allowed).
```
- [ ] **Step 7: Edit `README.md`**

Replace every occurrence of

```markdown
├── organize.zig        folder protection, move strategy, batching (ADR 0021)
```

with

```markdown
├── organize.zig        folder protection, move strategy, batching (ADR 0021)
├── triage.zig          organize_mailbox / apply_organization rules (ADR 0022)
├── organize_prompt.md  built-in organizing instructions
```
- [ ] **Step 8: Edit `README.md`**

Replace every occurrence of

```markdown
- [x] Mail organization: folders and move/copy — [spec](docs/superpowers/specs/2026-10-08-mailbox-organization-design.md) · [ADR 0021](docs/adr/0021-mailbox-organization-tools.md)
```

with

```markdown
- [x] Mail organization: folders and move/copy — [spec](docs/superpowers/specs/2026-10-08-mailbox-organization-design.md) · [ADR 0021](docs/adr/0021-mailbox-organization-tools.md)
- [x] Organize my mailbox: model-classified plan with dry run and confirmation — [spec](docs/superpowers/specs/2026-10-08-organize-mailbox-design.md) · [ADR 0022](docs/adr/0022-organize-mailbox-two-phase-plan.md)
```
- [ ] **Step 9: Run the tests and confirm they pass**

Run: `zig build test --summary all`
Expected: `205/205 tests passed`.

- [ ] **Step 10: Commit**

```bash
git add README.md docs/adr/0022-organize-mailbox-two-phase-plan.md docs/adr/README.md src/itest.zig
git commit -m "feat(triage): live checks, ADR 0022 and README"
```

---

## After the last task

- Live checks (the user runs this; it needs 1Password):
  `! op run --env-file imap.env -- zig build itest -- <account> --organize`. Expected: 49 PASS lines and `0 failure(s)`.
- Manual: in Claude Code run `/mcp__tp-imap-mcp__organize_my_mailbox` against a real inbox, read the dry run, then confirm execution.
- Mark the spec `Status: Implemented`.
