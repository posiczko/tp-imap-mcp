# 0023. Keep a local audit log of every tool call

- Status: Accepted
- Date: 2026-10-08

## Context

During a live reorganization of ~700 folders, 26 folders disappeared from the
server. The server could not say whether it had removed them: nothing it did
was recorded anywhere except the MCP client's transcript, which belongs to the
client, can be summarized away, and does not exist for other clients. The
user wants a record of everything the server does on their behalf.

Options considered:

- **Log only changes** (create/rename/delete/move/copy/flags). Answers "did
  the MCP do this?" but not "what did it read, and when?". Rejected: the user
  asked for everything.
- **Log every IMAP command.** Too low-level to read, and FETCH responses carry
  message content. Rejected.
- **Log every tool call, with content kept out.** One line per call at the
  single dispatch point (`mcp.handle` → `tools.call`). Chosen.
- **Log through the client or stderr.** stderr is shared with startup and
  library warnings and is often discarded by MCP clients. Rejected.

## Decision

- Every `tools/call` appends one JSON line to
  `$XDG_STATE_HOME/tp-imap-mcp/audit.log` (`~/.local/state/…`; ADR 0014),
  created with mode `0600` in a `0700` directory. Unknown tools are logged
  too; other requests (initialize, ping, list) are not.
- A line holds: UTC timestamp, tool, account, arguments, outcome
  (`ok` / `invalid_params` / `tool_error` with its message), duration in ms,
  and the result:
  - for tools that change the mailbox or cache (`change_keywords`,
    `create_message`, `create_mailbox`, `rename_mailbox`, `delete_mailbox`,
    `move_messages`, `copy_messages`, `apply_organization`, `clear_cache`)
    the result itself;
  - for reads only its size in bytes and, for an array, its length. Message
    bodies, headers, snippets and attachment names never reach the log, so
    the log cannot leak mail content and filtered messages stay withheld.
- Arguments are logged in full (search criteria and folder names included:
  the file is local and owner-only), except `create_message`'s raw message,
  which is logged as its size. Arrays over 10 items become
  `{"count", "first"}`; strings over 512 bytes are cut.
- Credentials are never tool arguments or results, so they cannot be logged.
- The log rotates at 10 MB; `audit.log.1` and `audit.log.2` are kept.
- Writing is best effort: a log problem never fails a tool call; the first
  failure is reported once on stderr.
- On by default. `TP_IMAP_MCP_AUDIT=0` disables it;
  `TP_IMAP_MCP_AUDIT_FILE` (absolute path) moves it. The startup line on
  stderr shows the path.

## Consequences

- "Did the MCP do this?" is answered by `grep` over one file, with arguments
  and results for every change.
- The log holds search criteria and folder names, i.e. some personal data at
  rest (like the header cache, ADR 0013); it is owner-only and bounded at
  ~30 MB.
- A crash between the IMAP command and the append loses that line; the log is
  a record of completed calls, not a write-ahead journal.
- The format is JSON Lines; changing field names later would break the user's
  own scripts, so additions should be new fields.
