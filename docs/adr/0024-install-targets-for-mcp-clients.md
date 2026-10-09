# 0024. Register the server with MCP clients through `zig build install-<client>` steps

- Status: Accepted
- Date: 2026-10-09

## Context

Registering the server with an MCP client is a manual step today (README,
"Register with your MCP client"): the user copies a command or a JSON block,
fills in their own paths, and picks the right wrapper. Mistakes show up as
"works in Claude Code, fails in Claude Desktop", almost always because a GUI
app does not inherit the shell's `PATH` or `$HOME`, so a relative `op` or a
`~/.local/bin` path silently fails.

Unlike a server that only needs its binary, this one must load `imap.env`
before it starts (ADR 0007, ADR 0020), in one of two ways:

- **env file:** `/bin/sh -c 'set -a; . <imap.env>; exec <binary>'`
- **1Password:** `<op> run --env-file <imap.env> -- <binary>`, which resolves
  `op://` references at start-up and needs `op` to unlock without a terminal
  (1Password desktop-app integration, or a service-account token).

The sibling project `tp-things3-mcp` already solved registration with
`zig build install-claude-code | install-claude-desktop | install-chatgpt`
(and `uninstall-*`). Its build-time helper `tools/mcp_config.zig` (about 360
lines, standard library only) merges one server entry from a
`config/mcp.json` template into Claude Desktop's JSON or into
`$CODEX_HOME/config.toml` (ChatGPT desktop app and Codex CLI), keeps every
other server and setting, and saves the previous file as `<file>.bak`. Claude
Code is registered through its own CLI (`claude mcp add-json --scope user`).

Options considered:

- **Keep the README instructions only.** No code, but the error-prone part
  (absolute paths, choosing the wrapper) stays with the user. Rejected.
- **A shell script installer.** Easy to write, but editing JSON and TOML
  safely from shell needs `jq` and a TOML tool (new dependencies), and it would
  differ from the sibling project. Rejected.
- **Let the server read `imap.env` itself** (e.g. a default path or
  `--env-file`), so no wrapper is needed. That would remove the wrapper in env-file mode
  only (`op run` is still needed for `op://` references) and
  would change the credential model of ADR 0007. Deferred; this ADR does
  not depend on it.
- **`zig build` install steps reusing the things3 helper, extended for the
  wrapper.** Same commands and behaviour as the sibling project, no new
  dependencies, testable with `zig build test`. Chosen.

## Decision

Add these build steps:

| Step | Effect |
|------|--------|
| `install-local` / `uninstall-local` | Copy the server to `$HOME/.local/bin/tp_imap_mcp` / remove it. |
| `install-claude-code` / `uninstall-claude-code` | `claude mcp add-json --scope user imap …` (removing any previous `imap` entry first) / `claude mcp remove --scope user imap`. |
| `install-claude-desktop` / `uninstall-claude-desktop` | Add/remove `mcpServers.imap` in `~/Library/Application Support/Claude/claude_desktop_config.json`. |
| `install-chatgpt` / `uninstall-chatgpt` | Add/remove `[mcp_servers.imap]` in `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`). |

Every `install-<client>` step depends on `install-local`, so clients always run
`$HOME/.local/bin/tp_imap_mcp`.

Build options choose the wrapper and the paths:

- `-Dsecrets=op|envfile`. Default: `op` when the env file contains an `op://`
  reference, otherwise `envfile`.
- `-Denv-file=<path>`. Default: `$HOME/.config/tp-imap-mcp/imap.env`. The step
  fails if the file does not exist.
- `-Dop=<path>`. Default: `op` found on `PATH` at build time, written as an
  absolute path. The step fails with a clear message in `op` mode if `op`
  cannot be found.

Every path written into a client configuration is absolute.

Copy `tools/mcp_config.zig` from `tp-things3-mcp` rather than sharing it, and
generalize its single placeholder into several (`@BINARY@`, `@ENV_FILE@`,
`@OP@`), with one template per mode: `config/mcp.envfile.json` and
`config/mcp.op.json`. Its tests run under `zig build test`.

Documentation: README step 5 becomes the install steps, followed by a table
per client: which file is written, which wrapper runs, and how secrets resolve
there. The Gmail XOAUTH2 runbook (`docs/runbooks/gmail-xoauth2.md`) stays
client-independent, because the refresh token is obtained once in a terminal
with `tp_imap_mcp auth <account>`. It gains a short closing section: where the
token goes (`imap.env` or a 1Password field), and that every client must be
restarted or reconnected after re-running `auth`, because the token is read
only when the server starts.

## Consequences

- Registration becomes one command per client, with the same names as
  `tp-things3-mcp`, and the GUI-path failure mode disappears.
- Re-running an install step is safe: it replaces only the `imap` entry and
  keeps a `.bak` of the previous file.
- The helper is duplicated between two repositories. Accepted: it is small and
  has no dependencies. If a third server needs it, extract a shared package.
- Before documenting them as supported, these must be checked on a real
  machine:
  - that the ChatGPT desktop app reads `~/.codex/config.toml` (taken from
    `tp-things3-mcp`, not verified here);
  - that `op run` can reach the 1Password desktop app from Claude Desktop and
    from Codex, including inside Codex's sandbox.
- Linux: Claude Desktop is macOS/Windows only; `install-claude-desktop` stays
  macOS-only, the other steps work wherever the clients do.
