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
- INBOX, folders the server marks as special-use (`\All \Archive \Drafts
  \Flagged \Junk \Sent \Trash \Important`), the configured drafts folder
  `create_message` uses, and folders containing one are never renamed or
  deleted; nothing is created or renamed into `[Gmail]/` or
  `[Google Mail]/`. Moving into Trash or Junk is allowed and the result
  carries a note.
- `delete_mailbox` only deletes empty folders without subfolders.
- `move_messages` refuses a source flagged `\All` (Gmail's All Mail): moving
  out of it is unverified and may send the messages to Trash.
  `copy_messages` from it is allowed.
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
