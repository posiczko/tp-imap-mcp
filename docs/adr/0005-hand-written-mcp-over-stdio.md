# 0005. Implement MCP by hand over stdio

- Status: Accepted
- Date: 2026-10-07

## Context

The server needs only a small part of MCP: `initialize`, notifications,
`ping`, `tools/list`, `tools/call`, `prompts/list`, `prompts/get`. No mature
MCP library tracks Zig 0.17, and adopting one would add a dependency. The
reference server supports stdio and HTTP; the intended clients launch servers
as subprocesses.

## Decision

Implement newline-delimited JSON-RPC 2.0 over stdin/stdout on `std.json`
(`src/mcp.zig`), stdio transport only. All logging goes to stderr. Supported
protocol versions: 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05; an unknown
requested version is answered with the newest.

## Consequences

- A few hundred lines of code, no dependency, fully unit-tested.
- HTTP transport and newer MCP features (resources, sampling, structured
  output) are not available; adding them later is a new decision.
- Tool-level failures are results with `isError: true`; only protocol faults
  are JSON-RPC errors.
