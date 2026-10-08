//! tp-imap-mcp: an MCP server exposing IMAP mailboxes over stdio.

const std = @import("std");
const config = @import("config.zig");
const filter_load = @import("filter/load.zig");
const mcp = @import("mcp.zig");
const oauth_flow = @import("oauth/flow.zig");
const Registry = @import("accounts.zig").Registry;

pub fn main(init: std.process.Init) !u8 {
    var err_buf: [1024]u8 = undefined;
    var stderr_writer = std.Io.File.stderr().writer(init.io, &err_buf);
    const stderr = &stderr_writer.interface;

    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len >= 2 and std.mem.eql(u8, args[1], "auth")) return authCommand(init, arena, args, stderr);
    try stderr.writeAll(mcp.server_name ++ ": ");
    const accounts, const settings, const active_filters = blk: {
        const accounts = config.load(arena, init.environ_map, stderr) catch |err| break :blk err;
        const settings = config.loadSettings(arena, init.environ_map, stderr) catch |err| break :blk err;
        // Filters fail closed: any problem stops startup (ADR 0017).
        const library = filter_load.loadLibrary(arena, init.gpa, init.io, settings.config_dir, stderr) catch |err| break :blk err;
        const active = filter_load.resolveActive(arena, library, init.environ_map, accounts, stderr) catch |err| break :blk err;
        break :blk .{ accounts, settings, active };
    } catch |err| switch (err) {
        error.InvalidConfig, error.InvalidFilters => {
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
    try stderr.print("serving {d} account(s) on stdio; cache: {s}; filters:", .{
        accounts.len,
        settings.cache_dir orelse if (settings.cache_dir_unavailable) "off (set HOME or XDG_CACHE_HOME)" else "off",
    });
    for (accounts, active_filters) |a, fs| {
        try stderr.print(" {s}=", .{a.name});
        if (fs.len == 0) try stderr.writeAll("none");
        for (fs, 0..) |f, i| try stderr.print("{s}{s}", .{ if (i > 0) "," else "", f.name });
    }
    try stderr.writeAll("\n");
    try stderr.flush();

    var registry: Registry = try .init(init.gpa, init.io, accounts, settings, active_filters);
    defer registry.deinit();

    var in_buf: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().reader(init.io, &in_buf);
    var out_buf: [64 * 1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &out_buf);

    try mcp.serve(init.gpa, &registry, &stdin_reader.interface, &stdout_writer.interface);
    return 0;
}

/// `tp_imap_mcp auth <account>` (ADR 0020).
fn authCommand(init: std.process.Init, arena: std.mem.Allocator, args: []const [:0]const u8, stderr: *std.Io.Writer) !u8 {
    if (args.len != 3) {
        try stderr.writeAll("usage: op run --env-file imap.env -- tp_imap_mcp auth <account>\n");
        try stderr.flush();
        return 2;
    }
    const name = args[2];
    try stderr.writeAll(mcp.server_name ++ ": ");
    const accounts, const settings = blk: {
        const accounts = config.loadWith(arena, init.environ_map, stderr, .{ .auth_account = name }) catch |err| break :blk err;
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
    const account = config.find(accounts, name) orelse {
        try stderr.print("unknown account \"{s}\"\n", .{name});
        try stderr.flush();
        return 1;
    };
    try stderr.writeAll("\n");
    var out_buf: [1024]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &out_buf);
    const code = try oauth_flow.run(init.gpa, init.io, account, settings, &stdout_writer.interface, stderr);
    try stderr.flush();
    return code;
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
    _ = @import("filter/regex.zig");
    _ = @import("filter/glob.zig");
    _ = @import("filter/rules.zig");
    _ = @import("filter/load.zig");
    _ = @import("attachments.zig");
    _ = @import("oauth/pkce.zig");
    _ = @import("oauth/provider.zig");
    _ = @import("oauth/token.zig");
    _ = @import("oauth/flow.zig");
    _ = @import("sanitize/unicode.zig");
    _ = @import("sanitize/entities.zig");
    _ = @import("sanitize/limit.zig");
    _ = @import("sanitize/html.zig");
}
