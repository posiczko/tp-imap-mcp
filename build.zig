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
    const test_step = b.step("test", "Run unit tests (no network)");
    test_step.dependOn(&b.addRunArtifact(unit_tests).step);

    // `install` is taken by the default step (which honours --prefix), so the
    // fixed-destination copy gets its own name. MCP clients run this copy
    // (ADR 0024).
    const home = b.graph.environ_map.get("HOME") orelse @panic("HOME is not set");
    const bin_dir = b.pathJoin(&.{ home, ".local", "bin" });
    const installed_bin = b.pathJoin(&.{ bin_dir, exe.name });

    const make_bin_dir = b.addSystemCommand(&.{ "mkdir", "-p", bin_dir });
    make_bin_dir.has_side_effects = true;
    const copy_exe = b.addSystemCommand(&.{ "install", "-m", "755" });
    copy_exe.addFileArg(exe.getEmittedBin());
    copy_exe.addArg(installed_bin);
    copy_exe.has_side_effects = true;
    copy_exe.step.dependOn(&make_bin_dir.step);
    b.step("install-local", "Install the server into $HOME/.local/bin").dependOn(&copy_exe.step);

    const remove_exe = b.addSystemCommand(&.{ "rm", "-f", installed_bin });
    remove_exe.has_side_effects = true;
    b.step("uninstall-local", "Remove the server from $HOME/.local/bin").dependOn(&remove_exe.step);

    addClientSteps(b, home, installed_bin, &copy_exe.step, test_step);

    // Live, read-only checks against a real server; run under `op run`.
    const itest = b.addExecutable(.{
        .name = "itest",
        .root_module = imapModule(b, "src/itest.zig", target, optimize),
    });
    const run_itest = b.addRunArtifact(itest);
    run_itest.addPassthruArgs();
    b.step("itest", "Run live integration checks (needs IMAP_* env)").dependOn(&run_itest.step);

    // Removes the build output and the local cache. The running build lives
    // in .zig-cache, so this is the only step that runs: nothing else
    // depends on the cache afterwards.
    const rm = b.addSystemCommand(&.{ "rm", "-rf" });
    rm.addDirectoryArg(b.path("zig-out"));
    rm.addDirectoryArg(b.path(".zig-cache"));
    rm.has_side_effects = true;
    b.step("clean", "Remove zig-out (the built server binary) and .zig-cache").dependOn(&rm.step);
}

/// install-<client> / uninstall-<client> steps that register the server with
/// each MCP client (ADR 0024). The entry runs a wrapper that loads imap.env:
/// `op run` when it holds op:// references, `/bin/sh` otherwise
/// (-Dsecrets, -Denv-file, -Dop). Installing first runs install-local, so the
/// client always runs $HOME/.local/bin/tp_imap_mcp.
fn addClientSteps(b: *std.Build, home: []const u8, installed_bin: []const u8, install_local: *std.Build.Step, test_step: *std.Build.Step) void {
    const secrets = b.option([]const u8, "secrets", "How the client loads imap.env: auto (default), op or envfile") orelse "auto";
    const env_file = b.option([]const u8, "env-file", "imap.env the client loads (default ~/.config/tp-imap-mcp/imap.env)") orelse
        b.pathJoin(&.{ home, ".config", "tp-imap-mcp", "imap.env" });
    // GUI clients don't inherit the shell's PATH, so `op` is written as an
    // absolute path. Without -Dop the helper looks it up when it runs, and
    // only in 1Password mode.
    const op = b.option([]const u8, "op", "Absolute path of the 1Password CLI (default: found on PATH)") orelse "";

    const helper = b.addExecutable(.{
        .name = "mcp_config",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/mcp_config.zig"),
            .target = b.graph.host,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = helper.root_module })).step);

    const config_dir = b.path("config");
    const settings = [_][]const u8{
        b.fmt("binary={s}", .{installed_bin}),
        b.fmt("env-file={s}", .{env_file}),
        b.fmt("op={s}", .{op}),
        b.fmt("secrets={s}", .{secrets}),
    };

    // Claude Desktop: mcpServers in its JSON config.
    const desktop_config = b.pathJoin(&.{ home, "Library", "Application Support", "Claude", "claude_desktop_config.json" });
    const desktop = b.addRunArtifact(helper);
    desktop.addArg("install-json");
    desktop.addDirectoryArg(config_dir);
    desktop.addArg(desktop_config);
    desktop.addArgs(&settings);
    desktop.has_side_effects = true;
    desktop.step.dependOn(install_local);
    b.step("install-claude-desktop", "Install the server and add it to Claude Desktop (restart Claude afterwards)").dependOn(&desktop.step);

    const desktop_off = b.addRunArtifact(helper);
    desktop_off.addArg("uninstall-json");
    desktop_off.addDirectoryArg(config_dir);
    desktop_off.addArg(desktop_config);
    desktop_off.has_side_effects = true;
    b.step("uninstall-claude-desktop", "Remove the server from Claude Desktop's config").dependOn(&desktop_off.step);

    // Claude Code: through its own CLI, at user scope. add-json refuses to
    // overwrite, so any previous registration is removed first. The entry is
    // computed before anything is removed, so a bad setting changes nothing.
    const code = b.addSystemCommand(&.{ "/bin/sh", "-c",
        \\set -e
        \\command -v claude >/dev/null || { echo "claude (Claude Code) is not on PATH" >&2; exit 1; }
        \\helper=$1 dir=$2; shift 2
        \\name=$("$helper" name "$dir")
        \\entry=$("$helper" entry "$dir" "$@")
        \\claude mcp remove --scope user "$name" >/dev/null 2>&1 || true
        \\claude mcp add-json --scope user "$name" "$entry"
        ,
        "install-claude-code",
    });
    code.addArtifactArg(helper);
    code.addDirectoryArg(config_dir);
    code.addArgs(&settings);
    code.has_side_effects = true;
    code.step.dependOn(install_local);
    b.step("install-claude-code", "Install the server and register it with Claude Code (user scope)").dependOn(&code.step);

    const code_off = b.addSystemCommand(&.{ "/bin/sh", "-c",
        \\set -e
        \\command -v claude >/dev/null || { echo "claude (Claude Code) is not on PATH" >&2; exit 1; }
        \\claude mcp remove --scope user "$("$1" name "$2")"
        ,
        "uninstall-claude-code",
    });
    code_off.addArtifactArg(helper);
    code_off.addDirectoryArg(config_dir);
    code_off.has_side_effects = true;
    b.step("uninstall-claude-code", "Unregister the server from Claude Code (user scope)").dependOn(&code_off.step);

    // ChatGPT desktop app (and Codex CLI): [mcp_servers.*] in config.toml.
    const codex_home = b.graph.environ_map.get("CODEX_HOME") orelse b.pathJoin(&.{ home, ".codex" });
    const codex_config = b.pathJoin(&.{ codex_home, "config.toml" });
    const chatgpt = b.addRunArtifact(helper);
    chatgpt.addArg("install-toml");
    chatgpt.addDirectoryArg(config_dir);
    chatgpt.addArg(codex_config);
    chatgpt.addArgs(&settings);
    chatgpt.has_side_effects = true;
    chatgpt.step.dependOn(install_local);
    b.step("install-chatgpt", "Install the server and add it to ChatGPT/Codex ($CODEX_HOME/config.toml)").dependOn(&chatgpt.step);

    const chatgpt_off = b.addRunArtifact(helper);
    chatgpt_off.addArg("uninstall-toml");
    chatgpt_off.addDirectoryArg(config_dir);
    chatgpt_off.addArg(codex_config);
    chatgpt_off.has_side_effects = true;
    b.step("uninstall-chatgpt", "Remove the server from ChatGPT/Codex's config.toml").dependOn(&chatgpt_off.step);
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
        .files = &.{ "src/c/session.c", "src/c/mime.c", "src/c/regex.c", "src/c/attach.c" },
        .flags = &.{ "-std=c11", "-D_DEFAULT_SOURCE", "-Wall", "-Wextra", "-Werror" },
    });
    mod.linkSystemLibrary("etpan", .{});
    mod.linkSystemLibrary("sqlite3", .{});
    return mod;
}
