# Mailbox organization tools — Design

Date: 2026-10-08
Status: Approved (design); spec under review
Extends: `docs/superpowers/specs/2026-10-07-tp-imap-mcp-design.md`
Decision record: `docs/adr/0021-mailbox-organization-tools.md` (new; linked from ADR 0010)

## 1. Goal

Let the assistant organize mail: create, rename/move and delete folders, and
move or copy messages between folders, on any IMAP server and on Gmail (where
folders are labels).

### Non-goals

- Deleting messages (beyond the internal expunge of a non-MOVE move, §4.2).
- Moving between accounts.
- Server-side rules/filters (Sieve) or Gmail filters.
- Automatic retries of these operations after a lost connection (§5).

## 2. Tools

All take `account`. All are refused on read-only accounts
(`account "X" is read-only`), except a call with `dry_run=true`.

| Tool | Parameters | Effect |
|---|---|---|
| `create_mailbox` | `name` | `CREATE name`, then `SUBSCRIBE name`. The server creates missing parents (RFC 3501 §6.3.3). |
| `rename_mailbox` | `name`, `new_name` | `RENAME`. A different parent moves the folder (e.g. `Projects/X` → `Archive/2025/X`). Subscriptions follow (§4.4). |
| `delete_mailbox` | `name` | Only when the folder holds 0 messages and has no subfolders; otherwise an error naming what it holds. Then `UNSUBSCRIBE`. |
| `move_messages` | `directory`, `destination`, exactly one of `uids` / `criteria`; optional `create_missing` (default false), `dry_run` | Moves the selected messages (§4.2). Refused when `directory` has the `\All` flag (`[Gmail]/All Mail`), dry runs included: `moving out of "[Gmail]/All Mail" (\All) is not supported; use copy_messages to add a label`. |
| `copy_messages` | same as `move_messages` | `UID COPY` of the selected messages. On Gmail this adds a label. |

### 2.1 Selecting messages (move/copy)

- Exactly one of `uids` (string array, from `search()`) or `criteria` (IMAP
  SEARCH criteria, validated by `validate.criteria`); both or neither is an
  error.
- `dry_run` defaults to **true when `criteria` is given** and **false when
  `uids` are given**. A dry run changes nothing and returns
  `{"dry_run":true,"matched":N,"uids":[first 100 UIDs],"destination":…}`;
  for `uids` it reports which of them exist.
- At most **5000** messages per call (after the criteria search). More is an
  error that reports the count and asks for narrower criteria or several calls.
- `destination` equal to `directory` is an error.
- `create_missing=true`: if `destination` does not exist, create and subscribe
  it first (same protection and validation as `create_mailbox`). Without it, a
  missing destination is the error
  `mailbox "D" does not exist; create it with create_mailbox (or pass create_missing=true)`.
  Existence is checked against a fresh mailbox list (cache bypassed).
- Messages withheld by sensitive-content filters may be moved and copied; no
  message content is returned.

### 2.2 Results

```json
{"moved":3,"source":"INBOX","destination":"Receipts/2026",
 "uid_map":[{"from":"101","to":"7"},{"from":"102","to":"8"},{"from":"105","to":"9"}],
 "uid_map_omitted":null,"note":null}
```

- `copy_messages` reports `"copied"` instead of `"moved"`.
- `uid_map` is present when the server reports COPYUID (UIDPLUS; Gmail and
  Dovecot do), else `null`. It lists at most the first 100 pairs;
  `uid_map_omitted` counts the rest (`null` when none were left out), so a
  5000-message move stays small (a 4,746-message move returned 134 KB before).
- `note` is set when the destination has the `\Trash` or `\Junk` special-use
  flag: `"destination is the Trash folder; servers may purge it automatically
  (Gmail: after 30 days)"` (resp. Junk/spam).
- Folder tools return `{"created":"X","subscribed":true}`,
  `{"renamed":"A","to":"B"}`, `{"deleted":"X"}`. A SUBSCRIBE/UNSUBSCRIBE
  failure does not fail the tool; it sets `"subscribed":false` (or a `note`).

## 3. Validation and protection

### 3.1 Folder names (`validate.mailboxName`, pure)

Given the account's hierarchy delimiter (from the mailbox list):

- not empty; at most 512 bytes (UTF-8, before modified UTF-7 encoding);
- valid UTF-8; no CR, LF, NUL or other control characters;
- no invisible, bidi or C1 control characters (anything `unicode.clean`
  would remove), so `INBOX\u{200B}` cannot pose as INBOX;
- no `*` or `%` (LIST wildcards);
- no leading or trailing delimiter, no two consecutive delimiters.

Names are encoded with `mutf7.encode` before being sent and decoded on output,
as the existing tools do.

### 3.2 Protected folders (`organize.protection`, pure)

Inputs: the name, the account's mailbox list (names, flags, delimiter), the
drafts folder's wire name.

- **Never renamed or deleted:** `INBOX` (case-insensitive), any folder whose
  LIST flags include a special-use attribute (`\All \Archive \Drafts \Flagged
  \Junk \Sent \Trash \Important`), the configured drafts folder
  (`IMAP_<NAME>_DRAFTS`, the folder `create_message` writes to; default:
  the `\Drafts`-flagged folder, else `Drafts`), and any folder that has such a folder beneath it. Special-use
  protection relies on the server's LIST flags; a system folder the server
  does not flag is not protected.
- **Never created or renamed into:** the Gmail system trees `[Gmail]/…` and
  `[Google Mail]/…`; and a rename's target must not be the folder itself or
  inside it (`A` → `A/B`).
- **Allowed:** moving or copying messages into any existing selectable folder,
  including `\Trash` and `\Junk` (with the §2.2 note). `\Noselect` folders are
  refused as `directory` or `destination`.

Refusals name the rule, e.g.
`"[Gmail]/Sent Mail" is a special-use folder (\Sent) and cannot be renamed`.

## 4. Behavior

### 4.1 Session layer

New C shim functions (`src/c/session.c`, `tpi.h`) with Zig wrappers on
`Session`:

| Zig | libetpan |
|---|---|
| `create(name)`, `rename(old, new)`, `delete(name)` | `mailimap_create`, `_rename`, `_delete` |
| `subscribe(name)`, `unsubscribe(name)` | `mailimap_subscribe`, `_unsubscribe` |
| `hasCapability(name) bool` | `mailimap_has_extension` (capabilities cached by libetpan after login; fetched once if absent) |
| `uidMove(arena, uids, dest) ?UidMap` | `mailimap_uidplus_uid_move` when UIDPLUS, else `mailimap_uid_move` |
| `uidCopy(arena, uids, dest) ?UidMap` | `mailimap_uidplus_uid_copy` when UIDPLUS, else `mailimap_uid_copy` |
| `uidExpunge(uids)` | `mailimap_uid_expunge` |

`UidMap` pairs source and destination UIDs from the COPYUID sets (expanded
ranges); a malformed or mismatched-length response yields `null`, never an
error.

### 4.2 Move strategy (`organize.moveStrategy`, pure: capabilities → strategy)

1. Server has `MOVE`: `UID MOVE`.
2. Otherwise, server has `UIDPLUS`: `UID COPY`; then `UID STORE +FLAGS.SILENT
   (\Deleted)`; then `UID EXPUNGE` of exactly those UIDs.
   - COPY fails → nothing changed; normal error.
   - STORE or EXPUNGE fails → error
     `<done> of <M> messages were moved; the next <pending> were copied to "D" but not removed from "S" (they may be flagged \Deleted); the remaining <rest> were not touched: <server response>`
     (the "remaining" clause is omitted when nothing is left).
3. Neither: refuse —
   `server supports neither MOVE nor UIDPLUS; use copy_messages and remove the originals in your mail client`.
   (A plain `EXPUNGE` would also purge unrelated messages already flagged
   `\Deleted`.)

The source folder is `SELECT`ed (read-write) for move; `EXAMINE` suffices for
copy. UIDs are sent in batches of 500; the result aggregates the batches. If a
later batch fails, the error says how many were already moved/copied.

### 4.3 Delete

`delete_mailbox` lists `name<delim>%` (children) and, unless the folder is
`\Noselect`, gets `STATUS (MESSAGES)`. Non-empty →
`"X" is not empty (12 messages, 2 subfolders); move or delete its contents first`.

### 4.4 Subscriptions

- create: `SUBSCRIBE name`.
- rename: `UNSUBSCRIBE old` and `SUBSCRIBE new`; then, for each subfolder of
  the new name in a fresh LIST, `SUBSCRIBE` it and `UNSUBSCRIBE` its old name.
  Best effort: failures only set a `note`.
- delete: `UNSUBSCRIBE name` (best effort).

### 4.5 Gmail semantics (stated in the tool descriptions)

- Moving out of INBOX archives the message and applies the destination label.
- Copying adds a label; the message stays where it was.
- Every message also remains in `[Gmail]/All Mail`. Moving out of a `\All`
  folder is refused (unverified; it may send the messages to Trash);
  `copy_messages` from it is allowed and adds a label.
- Renaming a folder renames the label; deleting a folder removes the label
  (refused unless empty, §4.3).

## 5. Registry, retries, cache

- Each tool runs as one registry operation (`Registry.run`). All five are
  **non-retryable** after `ConnectionLost` (like `AppendOp`): resending
  COPY/CREATE could duplicate messages or report a confusing error. The
  message says: `connection lost during <tool>; the operation may or may not
  have completed — check with list_mailboxes/search before retrying`.
- Cache:
  - create/rename/delete (and `create_missing`): `markMailboxesStale`. The next
    list refreshes, and the existing `pruneCached` drops cached headers of
    folders that no longer exist (a renamed folder's old name and children).
  - move: `deleteMessages(source, uidvalidity, moved uids)`.
  - copy: no cache change.
- `ServerRejected` already marks the mailbox list stale (unchanged).

## 6. Code layout

- `src/organize.zig` (new): `protection`, `moveStrategy`, selection checks
  (uids/criteria exclusivity, cap), dry-run and result JSON shaping; pure and
  unit-tested.
- `src/validate.zig`: `mailboxName(name, delimiter)`.
- `src/imap/session.zig`, `src/imap/c.zig`, `src/c/tpi.h`, `src/c/session.c`:
  §4.1.
- `src/tools.zig`: five tool entries and handlers; operations in
  `src/accounts.zig` style (`CreateOp`, `RenameOp`, `DeleteOp`, `MoveOp`,
  `CopyOp`) marked non-retryable.
- `src/descriptions.zig`: descriptions, including §4.5 and the dry-run default.
- `src/itest.zig`: live checks (§7).

## 7. Testing

Unit (no server):
- name validation (each rule, multi-byte names, delimiter variants);
- protection (INBOX, each special-use flag, ancestor of a special-use folder,
  Gmail trees, rename into self);
- move strategy from capability sets;
- selection: both/neither of uids/criteria, cap, destination == source,
  dry-run defaults;
- batching (1, 500, 501, 5000 UIDs);
- COPYUID → `uid_map` expansion and malformed input → `null`;
- read-only refusal for every tool, and dry run allowed on read-only;
- cache: move deletes source rows; folder ops mark the list stale (in-memory
  store).

Live (`zig build itest -- <account>`, user's Dovecot), touching only folders it
creates, named `tp-imap-mcp-itest-<random>`:
1. `create_mailbox` A and B; both appear in `list_mailboxes`.
2. Append a test message to A (session layer).
3. `copy_messages` A → B by uid; `uid_map` present; B has 1 message.
4. `move_messages` B → A by criteria: dry run reports 1 match and moves
   nothing; `dry_run=false` moves it.
5. `rename_mailbox` B → A/B.
6. `delete_mailbox` A is refused (not empty); `rename_mailbox INBOX` is refused.
7. Cleanup via the session layer: flag the test messages `\Deleted`,
   `UID EXPUNGE` them, delete A/B then A. Cleanup runs even after a failed check.

Manual, once XOAUTH2 works: the same sequence against Gmail, plus moving out of
INBOX (archive + label).

## 8. Documentation

- README: tools table, "Organizing mail" example, security model (protection,
  dry run, no retry).
- ADR 0021; ADR 0010 links to it.
- `docs/TODO.md`: open items from review.
