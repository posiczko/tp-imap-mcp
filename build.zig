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
    b.step("test", "Run unit tests (no network)").dependOn(&b.addRunArtifact(unit_tests).step);

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
