//! tp-imap-mcp: an MCP server exposing IMAP mailboxes over stdio.

const std = @import("std");
const config = @import("config.zig");
const mcp = @import("mcp.zig");
const Registry = @import("accounts.zig").Registry;

pub fn main(init: std.process.Init) !u8 {
    var err_buf: [1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &err_buf);
    const stderr = &stderr_writer.interface;

    const arena = init.arena.allocator();
    try stderr.writeAll(mcp.server_name ++ ": ");
    const accounts, const settings = blk: {
        const accounts = config.load(arena, init.environ_map, stderr) catch |err| break :blk err;
        const settings = config.loadSettings(arena, init.environ_map, stderr) catch |err| break :blk err;
        break :blk .{ accounts, settings };
    } catch |err| switch (err) {
        error.InvalidConfig => {
            try stderr.writeAll("\n");
            try stderr.flush();
            return 1;
        },
        error.OutOfMemory => return err,
    };
    if (std.c.access(settings.ca_file, 4) != 0) { // R_OK
        try stderr.print("CA bundle {s} is not readable; install ca-certificates (brew install ca-certificates) or set TP_IMAP_MCP_CA_FILE\n", .{settings.ca_file});
        try stderr.flush();
        return 1;
    }
    try stderr.print("serving {d} account(s) on stdio; cache: {s}\n", .{
        accounts.len,
        settings.cache_dir orelse if (settings.cache_dir_unavailable) "off (set HOME or XDG_CACHE_HOME)" else "off",
    });
    try stderr.flush();

    var registry: Registry = try .init(init.gpa, accounts, settings);
    defer registry.deinit();

    var in_buf: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(init.io, &in_buf);
    var out_buf: [64 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &out_buf);

    try mcp.serve(init.gpa, &registry, &stdin_reader.interface, &stdout_writer.interface);
    return 0;
}

test {
    _ = @import("accounts.zig");
    _ = @import("cache/sqlite.zig");
    _ = @import("cache/store.zig");
    _ = @import("listmatch.zig");
    _ = @import("config.zig");
    _ = @import("headers.zig");
    _ = @import("imap/mutf7.zig");
    _ = @import("imap/session.zig");
    _ = @import("mcp.zig");
    _ = @import("mime_test.zig");
    _ = @import("prompts.zig");
    _ = @import("text.zig");
    _ = @import("tools.zig");
    _ = @import("validate.zig");
}
