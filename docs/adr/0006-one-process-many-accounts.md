# 0006. Serve multiple accounts from one process

- Status: Accepted
- Date: 2026-10-07

## Context

The reference server handles one account per process. The user needs to query
several IMAP servers. Options: (A) one process with an `account` argument on
every tool; (B) one process per account, each registered as a separate MCP
server with the reference's exact tool signatures.

## Decision

Option A. Every tool takes a required `account` argument (case-insensitive
match against configured names), and a new `list_accounts` tool lists them.
Each account has one lazily opened IMAP connection, checked with `NOOP`
before each call; a dropped connection is re-established and the call retried
once.

## Consequences

- One MCP registration; the model sees one tool set instead of duplicates.
- Tool signatures differ from the reference by the extra `account` argument.
- A login failure affects only that account; the others keep working.
- Calls are handled serially; one slow server delays the next request.
