# 0003. Link libetpan from Homebrew via pkg-config

- Status: Accepted
- Date: 2026-10-07

## Context

libetpan can either be linked from the system (Homebrew) or vendored and
compiled by `build.zig`. Vendoring gives a self-contained, reproducible binary
but requires porting libetpan's autotools/CMake configuration (`config.h`
generation, iconv vs ICU selection) to the Zig build system, and OpenSSL would
still come from outside. This is a personal tool for macOS on Apple Silicon;
portability is not a goal.

## Decision

Link the Homebrew libetpan with `module.linkSystemLibrary("etpan", .{})`,
which resolves flags through `pkg-config`.

## Consequences

- Minimal build code; security fixes arrive with `brew upgrade libetpan`.
- The binary requires Homebrew's libetpan and openssl@3 at runtime.
- Building on another platform would need this decision revisited (vendoring).
