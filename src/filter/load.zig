//! Loads user filters from `<config_dir>/filters.zon`, merges them with the
//! built-ins, and resolves which filters are active per account (ADR 0017).
//! Every problem is a startup error: filtering must never fail open.

const std = @import("std");
const Allocator = std.mem.Allocator;
const config = @import("../config.zig");
const rules = @import("rules.zig");
const Regex = @import("regex.zig").Regex;

pub const Error = error{InvalidFilters} || Allocator.Error;

pub const file_name = "filters.zon";

// ---- file format ------------------------------------------------------------

const FileCondition = struct {
    field: []const u8,
    contains: ?[]const []const u8 = null,
    glob: ?[]const []const u8 = null,
    regex: ?[]const []const u8 = null,
};

const FileFilter = struct {
    name: []const u8,
    rules: []const []const FileCondition,
};

const File = struct {
    filters: []const FileFilter = &.{},
};

fn fail(diag: *std.Io.Writer, comptime fmt: []const u8, args: anytype) Error {
    diag.print(fmt, args) catch {};
    return error.InvalidFilters;
}

fn validName(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |ch| if (!(std.ascii.isLower(ch) or std.ascii.isDigit(ch) or ch == '_')) return false;
    return true;
}

fn validField(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |ch| if (ch < 0x21 or ch > 0x7E or ch == ':') return false;
    return true;
}

/// Parses and validates ZON `source` (read from `path`, used in messages).
pub fn parseFile(arena: Allocator, gpa: Allocator, source: [:0]const u8, path: []const u8, diag: *std.Io.Writer) Error![]rules.Filter {
    var zdiag: std.zon.parse.Diagnostics = undefined;
    const file = std.zon.parse.fromSlice(File, .{
        .gpa = gpa,
        .arena = arena,
        .source = source,
        .diagnostics = &zdiag,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ParseZon => return fail(diag, "{f}", .{zdiag.fmt(path)}),
    };

    const out = try arena.alloc(rules.Filter, file.filters.len);
    for (file.filters, out, 0..) |ff, *f, fi| {
        if (!validName(ff.name))
            return fail(diag, "{s}: filter #{d}: name \"{s}\" must match [a-z0-9_]+", .{ path, fi + 1, ff.name });
        for (file.filters[0..fi]) |prev| if (std.mem.eql(u8, prev.name, ff.name))
            return fail(diag, "{s}: filter \"{s}\" is defined twice", .{ path, ff.name });
        if (ff.rules.len == 0)
            return fail(diag, "{s}: filter \"{s}\" has no rules", .{ path, ff.name });

        const rs = try arena.alloc(rules.Rule, ff.rules.len);
        for (ff.rules, rs, 1..) |fconds, *r, ri| {
            if (fconds.len == 0)
                return fail(diag, "{s}: filter \"{s}\" rule {d} has no conditions", .{ path, ff.name, ri });
            const cs = try arena.alloc(rules.Condition, fconds.len);
            for (fconds, cs, 1..) |fc, *c, ci| {
                const where = .{ path, ff.name, ri, ci };
                if (!validField(fc.field))
                    return fail(diag, "{s}: filter \"{s}\" rule {d} condition {d}: invalid header field \"{s}\"", where ++ .{fc.field});
                const set = @as(u8, @intFromBool(fc.contains != null)) + @intFromBool(fc.glob != null) + @intFromBool(fc.regex != null);
                if (set != 1)
                    return fail(diag, "{s}: filter \"{s}\" rule {d} condition {d}: set exactly one of .contains, .glob, .regex", where);
                const pats = fc.contains orelse fc.glob orelse fc.regex.?;
                if (pats.len == 0)
                    return fail(diag, "{s}: filter \"{s}\" rule {d} condition {d}: pattern list is empty", where);
                for (pats) |p| if (p.len == 0)
                    return fail(diag, "{s}: filter \"{s}\" rule {d} condition {d}: empty pattern", where);

                c.* = .{
                    .field = try std.ascii.allocLowerString(arena, fc.field),
                    .matcher = if (fc.contains) |v| .{ .contains = v } else if (fc.glob) |v| .{ .glob = v } else blk: {
                        const compiled = try arena.alloc(Regex, pats.len);
                        for (pats, compiled) |p, *re| {
                            var why: []const u8 = "";
                            re.* = Regex.compile(arena, p, &why) catch |err| switch (err) {
                                error.OutOfMemory => return error.OutOfMemory,
                                error.InvalidRegex => return fail(diag, "{s}: filter \"{s}\" rule {d} condition {d}: invalid regex \"{s}\": {s}", where ++ .{ p, why }),
                            };
                        }
                        break :blk .{ .regex = compiled };
                    },
                };
            }
            r.* = .{ .conditions = cs };
        }
        f.* = .{ .name = ff.name, .rules = rs };
    }
    return out;
}

/// Built-ins, with any same-named file filter replacing its built-in, then the
/// remaining file filters in file order.
pub fn merge(arena: Allocator, file_filters: []const rules.Filter) Allocator.Error![]rules.Filter {
    var out: std.ArrayList(rules.Filter) = .empty;
    for (rules.builtins) |b| {
        const replacement = for (file_filters) |f| {
            if (std.mem.eql(u8, f.name, b.name)) break f;
        } else b;
        try out.append(arena, replacement);
    }
    for (file_filters) |f| {
        for (rules.builtins) |b| {
            if (std.mem.eql(u8, f.name, b.name)) break;
        } else try out.append(arena, f);
    }
    return out.items;
}

/// Reads `<config_dir>/filters.zon` if it exists and returns the merged
/// library. A missing directory or file means built-ins only.
pub fn loadLibrary(arena: Allocator, gpa: Allocator, io: std.Io, config_dir: ?[]const u8, diag: *std.Io.Writer) Error![]rules.Filter {
    const dir = config_dir orelse return merge(arena, &.{});
    const path = try std.fs.path.join(arena, &.{ dir, file_name });
    const bytes = std.Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(1 << 20)) catch |err| switch (err) {
        error.FileNotFound => return merge(arena, &.{}),
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(diag, "{s}: cannot read ({t})", .{ path, err }),
    };
    const source = try arena.dupeSentinel(u8, bytes, 0);
    return merge(arena, try parseFile(arena, gpa, source, path, diag));
}

/// Active filters per account, from TP_IMAP_MCP_FILTERS (default
/// "password_reset") and IMAP_<NAME>_FILTERS overrides.
pub fn resolveActive(
    arena: Allocator,
    library: []const rules.Filter,
    env: anytype,
    accounts: []const config.Account,
    diag: *std.Io.Writer,
) Error![]const []const *const rules.Filter {
    const global_key = "TP_IMAP_MCP_FILTERS";
    const global_raw = env.get(global_key) orelse "password_reset";
    const global = try parseList(arena, library, global_key, global_raw, diag);

    const out = try arena.alloc([]const *const rules.Filter, accounts.len);
    for (accounts, out) |a, *o| {
        const key = try std.mem.concat(arena, u8, &.{ "IMAP_", try std.ascii.allocUpperString(arena, a.name), "_FILTERS" });
        o.* = if (env.get(key)) |raw| try parseList(arena, library, key, raw, diag) else global;
    }
    return out;
}

fn parseList(arena: Allocator, library: []const rules.Filter, key: []const u8, raw: []const u8, diag: *std.Io.Writer) Error![]const *const rules.Filter {
    const value = std.mem.trim(u8, raw, " \t");
    if (value.len == 0) return fail(diag, "{s} is empty; use \"none\" to disable filters", .{key});
    var out: std.ArrayList(*const rules.Filter) = .empty;
    var saw_none = false;
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t");
        if (entry.len == 0) return fail(diag, "{s} contains an empty entry", .{key});
        if (std.mem.eql(u8, entry, "none")) {
            saw_none = true;
            continue;
        }
        const f = for (library) |*f| {
            if (std.mem.eql(u8, f.name, entry)) break f;
        } else return fail(diag, "{s}: unknown filter \"{s}\"", .{ key, entry });
        try out.append(arena, f);
    }
    if (saw_none and out.items.len > 0) return fail(diag, "{s}: \"none\" cannot be combined with other filters", .{key});
    return out.items;
}

const testing = std.testing;

const TestEnv = struct {
    map: std.StaticStringMap([]const u8),
    pub fn get(self: TestEnv, key: []const u8) ?[]const u8 {
        return self.map.get(key);
    }
};

fn expectParseError(source: [:0]const u8, comptime expected_fragment: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [1024]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidFilters, parseFile(arena_state.allocator(), testing.allocator, source, "filters.zon", &diag));
    if (std.mem.find(u8, diag.buffered(), expected_fragment) == null) {
        std.debug.print("diag was: {s}\n", .{diag.buffered()});
        return error.TestUnexpectedDiagnostic;
    }
}

test "valid file: user filter plus built-in replacement" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var buf: [1024]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    const parsed = try parseFile(a, testing.allocator,
        \\.{ .filters = .{
        \\    .{ .name = "banking", .rules = .{
        \\        .{ .{ .field = "From", .glob = .{ "*@chase.com" } } },
        \\        .{ .{ .field = "from", .glob = .{ "*@paypal.com" } }, .{ .field = "subject", .regex = .{ "(receipt|statement)" } } },
        \\    } },
        \\    .{ .name = "password_reset", .rules = .{ .{ .{ .field = "subject", .contains = .{ "passwort" } } } } },
        \\} }
    , "filters.zon", &diag);
    try testing.expectEqual(2, parsed.len);
    try testing.expectEqualStrings("from", parsed[0].rules[0].conditions[0].field);

    const lib = try merge(a, parsed);
    try testing.expectEqual(2, lib.len);
    try testing.expectEqualStrings("password_reset", lib[0].name);
    try testing.expectEqualStrings("passwort", lib[0].rules[0].conditions[0].matcher.contains[0]);
    try testing.expectEqualStrings("banking", lib[1].name);

    const hs = try rules.decodeHeaders(a, "From: PayPal <service@paypal.com>\r\nSubject: Your Receipt\r\n\r\n");
    try testing.expect(try rules.filterMatches(a, lib[1], hs));
}

test "invalid files are rejected with a precise message" {
    try expectParseError(".{ .filters = .{ .{ .name = \"Bad Name\", .rules = .{ .{ .{ .field = \"from\", .glob = .{\"*\"} } } } } } }", "must match [a-z0-9_]+");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{} } } }", "has no rules");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{} } } } }", "rule 1 has no conditions");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"from\" } } } } } }", "set exactly one of");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"from\", .glob = .{\"*\"}, .contains = .{\"a\"} } } } } } }", "set exactly one of");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"from\", .glob = .{} } } } } } }", "pattern list is empty");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"from\", .glob = .{\"\"} } } } } } }", "empty pattern");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"bad field\", .glob = .{\"*\"} } } } } } }", "invalid header field");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"subject\", .regex = .{\"(unclosed\"} } } } } } }", "invalid regex \"(unclosed\"");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"from\", .glob = .{\"*\"} } } } }, .{ .name = \"x\", .rules = .{ .{ .{ .field = \"from\", .glob = .{\"*\"} } } } } } }", "defined twice");
    try expectParseError(".{ .filters = .{ .{ .name = \"x\", .rules = .{ .{ .{ .field = \"from\", .glob = .{\"*\"}, .typo = 1 } } } } } }", "filters.zon:");
    try expectParseError(".{ .filters = ", "filters.zon:");
}

test "missing config dir or file means built-ins only" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    const a = arena_state.allocator();
    try testing.expectEqual(rules.builtins.len, (try loadLibrary(a, testing.allocator, testing.io, null, &diag)).len);
    try testing.expectEqual(rules.builtins.len, (try loadLibrary(a, testing.allocator, testing.io, "/nonexistent/tp-imap-mcp", &diag)).len);
}

test "file on disk is read and merged" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "filters.zon", .data = ".{ .filters = .{ .{ .name = \"banking\", .rules = .{ .{ .{ .field = \"from\", .glob = .{\"*@chase.com\"} } } } } } }" });
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    const dir = try a.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    const lib = try loadLibrary(a, testing.allocator, testing.io, dir, &diag);
    try testing.expectEqual(2, lib.len);
    try testing.expectEqualStrings("banking", lib[1].name);
}

test "activation: default, none, per-account override, errors" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const banking: rules.Filter = .{ .name = "banking", .rules = &.{} };
    const lib = try merge(a, &.{banking});
    const accounts = [_]config.Account{
        .{ .name = "work", .host = "h", .port = 993, .login = "l", .password = @constCast(&[_:0]u8{}), .readonly = false, .drafts = null },
        .{ .name = "home", .host = "h", .port = 993, .login = "l", .password = @constCast(&[_:0]u8{}), .readonly = false, .drafts = null },
    };
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);

    const default = try resolveActive(a, lib, TestEnv{ .map = .initComptime(.{}) }, &accounts, &diag);
    try testing.expectEqualStrings("password_reset", default[0][0].name);
    try testing.expectEqual(1, default[1].len);

    const mixed = try resolveActive(a, lib, TestEnv{ .map = .initComptime(.{
        .{ "TP_IMAP_MCP_FILTERS", "none" },
        .{ "IMAP_HOME_FILTERS", " banking , password_reset " },
    }) }, &accounts, &diag);
    try testing.expectEqual(0, mixed[0].len);
    try testing.expectEqualStrings("banking", mixed[1][0].name);
    try testing.expectEqualStrings("password_reset", mixed[1][1].name);

    inline for (.{
        .{ "nope", "TP_IMAP_MCP_FILTERS: unknown filter \"nope\"" },
        .{ "", "TP_IMAP_MCP_FILTERS is empty" },
        .{ "banking,,password_reset", "contains an empty entry" },
        .{ "none,banking", "cannot be combined" },
    }) |case| {
        diag.end = 0;
        try testing.expectError(error.InvalidFilters, resolveActive(a, lib, TestEnv{ .map = .initComptime(.{.{ "TP_IMAP_MCP_FILTERS", case[0] }}) }, &accounts, &diag));
        try testing.expect(std.mem.find(u8, diag.buffered(), case[1]) != null);
    }
}
