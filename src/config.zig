//! Configuration from environment variables: accounts (ADR 0007) and cache
//! settings (ADRs 0013, 0014).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Account = struct {
    name: []const u8, // as written in IMAP_ACCOUNTS
    host: [:0]const u8,
    port: u16,
    login: [:0]const u8,
    password: [:0]u8, // mutable so it can be zeroed
    readonly: bool,
    drafts: ?[]const u8, // UTF-8; null = discover via \Drafts

    pub fn wipe(self: *Account) void {
        std.crypto.secureZero(u8, self.password);
    }
};

pub const Error = error{InvalidConfig} || Allocator.Error;

/// Writes a human-readable reason to `diag` on error.InvalidConfig. Never
/// includes a variable's value. `env` is anything with
/// `fn get(self, []const u8) ?[]const u8`.
pub fn load(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error![]Account {
    const list = nonEmpty(env, "IMAP_ACCOUNTS") orelse
        return fail(diag, "IMAP_ACCOUNTS is missing or empty", .{});

    // Validate the whole name list before reading any per-account variable.
    var names: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |raw_name| {
        const name = std.mem.trim(u8, raw_name, " \t");
        if (name.len == 0) return fail(diag, "IMAP_ACCOUNTS contains an empty name", .{});
        for (name) |c| if (!std.ascii.isAlphanumeric(c) and c != '_')
            return fail(diag, "account name \"{s}\" must match [A-Za-z0-9_]+", .{name});
        for (names.items) |n| if (std.ascii.eqlIgnoreCase(n, name))
            return fail(diag, "account name \"{s}\" is listed twice", .{name});
        try names.append(arena, name);
    }

    var accounts: std.ArrayList(Account) = .empty;
    for (names.items) |name| {
        const prefix = try std.ascii.allocUpperString(arena, name);
        try accounts.append(arena, .{
            .name = name,
            .host = try required(arena, env, diag, prefix, "HOST"),
            .port = try port(arena, env, diag, prefix),
            .login = try required(arena, env, diag, prefix, "LOGIN"),
            .password = try required(arena, env, diag, prefix, "PASSWORD"),
            .readonly = try flag(arena, env, diag, prefix, "READONLY"),
            .drafts = nonEmpty(env, try varName(arena, prefix, "DRAFTS")),
        });
    }
    return accounts.toOwnedSlice(arena);
}

pub const Settings = struct {
    /// `$XDG_CACHE_HOME/tp-imap-mcp` or `$HOME/.cache/tp-imap-mcp`; null when
    /// caching is disabled or no location could be determined.
    cache_dir: ?[]const u8,
    /// Set when caching was wanted but no cache location could be determined.
    cache_dir_unavailable: bool,
    /// Seconds a cached mailbox list stays fresh.
    mailbox_ttl: i64,
    /// PEM bundle used to verify server certificates (ADR 0016).
    ca_file: [:0]const u8,
};

/// Homebrew's `ca-certificates` bundle on Apple Silicon.
pub const default_ca_file = "/opt/homebrew/etc/ca-certificates/cert.pem";

pub const app_dir = "tp-imap-mcp";

/// Reads TP_IMAP_MCP_CACHE, TP_IMAP_MCP_MAILBOX_TTL, TP_IMAP_MCP_CA_FILE,
/// XDG_CACHE_HOME, HOME.
pub fn loadSettings(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error!Settings {
    const ttl_key = "TP_IMAP_MCP_MAILBOX_TTL";
    const ttl: i64 = if (nonEmpty(env, ttl_key)) |v|
        std.fmt.parseInt(u31, v, 10) catch return fail(diag, "{s} must be a number of seconds >= 0", .{ttl_key})
    else
        3600;
    const ca_file = try arena.dupeSentinel(u8, nonEmpty(env, "TP_IMAP_MCP_CA_FILE") orelse default_ca_file, 0);

    if (!try boolVar(env, diag, "TP_IMAP_MCP_CACHE", true))
        return .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = ttl, .ca_file = ca_file };

    const base: ?[]const u8 = blk: {
        if (nonEmpty(env, "XDG_CACHE_HOME")) |x| if (std.fs.path.isAbsolute(x)) break :blk x;
        if (nonEmpty(env, "HOME")) |h| break :blk try std.fs.path.join(arena, &.{ h, ".cache" });
        break :blk null;
    };
    return .{
        .cache_dir = if (base) |b| try std.fs.path.join(arena, &.{ b, app_dir }) else null,
        .cache_dir_unavailable = base == null,
        .mailbox_ttl = ttl,
        .ca_file = ca_file,
    };
}

/// Case-insensitive lookup by configured name.
pub fn find(accounts: []Account, name: []const u8) ?*Account {
    for (accounts) |*a| if (std.ascii.eqlIgnoreCase(a.name, name)) return a;
    return null;
}

fn fail(diag: *std.Io.Writer, comptime fmt: []const u8, args: anytype) Error {
    diag.print(fmt, args) catch {};
    return error.InvalidConfig;
}

fn nonEmpty(env: anytype, key: []const u8) ?[]const u8 {
    const v = env.get(key) orelse return null;
    return if (v.len == 0) null else v;
}

fn varName(arena: Allocator, prefix: []const u8, suffix: []const u8) Allocator.Error![]const u8 {
    return std.mem.concat(arena, u8, &.{ "IMAP_", prefix, "_", suffix });
}

fn required(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8, suffix: []const u8) Error![:0]u8 {
    const key = try varName(arena, prefix, suffix);
    const v = nonEmpty(env, key) orelse return fail(diag, "{s} is missing or empty", .{key});
    return arena.dupeSentinel(u8, v, 0);
}

fn port(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8) Error!u16 {
    const key = try varName(arena, prefix, "PORT");
    const v = nonEmpty(env, key) orelse return 993;
    const p = std.fmt.parseInt(u16, v, 10) catch return fail(diag, "{s} must be a port number 1-65535", .{key});
    if (p == 0) return fail(diag, "{s} must be a port number 1-65535", .{key});
    return p;
}

fn flag(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8, suffix: []const u8) Error!bool {
    return boolVar(env, diag, try varName(arena, prefix, suffix), false);
}

fn boolVar(env: anytype, diag: *std.Io.Writer, key: []const u8, default: bool) Error!bool {
    const v = nonEmpty(env, key) orelse return default;
    const truthy = [_][]const u8{ "1", "true", "yes" };
    const falsy = [_][]const u8{ "0", "false", "no" };
    for (truthy) |t| if (std.ascii.eqlIgnoreCase(v, t)) return true;
    for (falsy) |f| if (std.ascii.eqlIgnoreCase(v, f)) return false;
    return fail(diag, "{s} must be one of 1/true/yes/0/false/no", .{key});
}

const testing = std.testing;

const TestEnv = struct {
    map: std.StaticStringMap([]const u8),
    pub fn get(self: TestEnv, key: []const u8) ?[]const u8 {
        return self.map.get(key);
    }
};

fn testEnv(comptime kvs: anytype) TestEnv {
    return .{ .map = .initComptime(kvs) };
}

fn expectInvalid(e: TestEnv, comptime expected_diag: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidConfig, load(arena_state.allocator(), e, &diag));
    try testing.expectEqualStrings(expected_diag, diag.buffered());
    try testing.expect(std.mem.find(u8, diag.buffered(), "s3cret") == null);
}

test "loads two accounts with defaults and overrides" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    const accounts = try load(arena_state.allocator(), testEnv(.{
        .{ "IMAP_ACCOUNTS", "tetra, work" },
        .{ "IMAP_TETRA_HOST", "mail.example.org" },
        .{ "IMAP_TETRA_LOGIN", "me@example.org" },
        .{ "IMAP_TETRA_PASSWORD", "s3cret" },
        .{ "IMAP_WORK_HOST", "imap.work.test" },
        .{ "IMAP_WORK_PORT", "1993" },
        .{ "IMAP_WORK_LOGIN", "me@work.test" },
        .{ "IMAP_WORK_PASSWORD", "s3cret" },
        .{ "IMAP_WORK_READONLY", "yes" },
        .{ "IMAP_WORK_DRAFTS", "INBOX.Drafts" },
    }), &diag);
    try testing.expectEqual(2, accounts.len);
    try testing.expectEqualStrings("tetra", accounts[0].name);
    try testing.expectEqual(993, accounts[0].port);
    try testing.expect(!accounts[0].readonly);
    try testing.expect(accounts[0].drafts == null);
    try testing.expectEqual(1993, accounts[1].port);
    try testing.expect(accounts[1].readonly);
    try testing.expectEqualStrings("INBOX.Drafts", accounts[1].drafts.?);
    try testing.expect(find(accounts, "WORK") == &accounts[1]);
    try testing.expect(find(accounts, "nope") == null);

    accounts[0].wipe();
    for (accounts[0].password) |c| try testing.expectEqual(0, c);
}

test "rejects missing, malformed, duplicate; never leaks values" {
    try expectInvalid(testEnv(.{}), "IMAP_ACCOUNTS is missing or empty");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "" }}), "IMAP_ACCOUNTS is missing or empty");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "a,,b" }}), "IMAP_ACCOUNTS contains an empty name");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "a," }}), "IMAP_ACCOUNTS contains an empty name");
    try expectInvalid(testEnv(.{.{ "IMAP_ACCOUNTS", "my-mail" }}), "account name \"my-mail\" must match [A-Za-z0-9_]+");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a,A" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_LOGIN", "l" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
    }), "account name \"A\" is listed twice");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
    }), "IMAP_A_LOGIN is missing or empty");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_LOGIN", "l" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
        .{ "IMAP_A_PORT", "99999" },
    }), "IMAP_A_PORT must be a port number 1-65535");
    try expectInvalid(testEnv(.{
        .{ "IMAP_ACCOUNTS", "a" },
        .{ "IMAP_A_HOST", "h" },
        .{ "IMAP_A_LOGIN", "l" },
        .{ "IMAP_A_PASSWORD", "s3cret" },
        .{ "IMAP_A_READONLY", "s3cret" },
    }), "IMAP_A_READONLY must be one of 1/true/yes/0/false/no");
}

fn settingsFrom(arena: Allocator, e: TestEnv) !Settings {
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    return loadSettings(arena, e, &diag);
}

test "settings: XDG cache location, HOME fallback, disable switch, TTL" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const xdg = try settingsFrom(a, testEnv(.{ .{ "XDG_CACHE_HOME", "/x/cache" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/x/cache/tp-imap-mcp", xdg.cache_dir.?);
    try testing.expectEqual(3600, xdg.mailbox_ttl);
    try testing.expectEqualStrings(default_ca_file, xdg.ca_file);

    const ca = try settingsFrom(a, testEnv(.{.{ "TP_IMAP_MCP_CA_FILE", "/etc/ssl/cert.pem" }}));
    try testing.expectEqualStrings("/etc/ssl/cert.pem", ca.ca_file);

    // Relative XDG_CACHE_HOME is ignored per the XDG spec.
    const home = try settingsFrom(a, testEnv(.{ .{ "XDG_CACHE_HOME", "rel" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/home/me/.cache/tp-imap-mcp", home.cache_dir.?);

    const off = try settingsFrom(a, testEnv(.{ .{ "TP_IMAP_MCP_CACHE", "0" }, .{ "HOME", "/home/me" }, .{ "TP_IMAP_MCP_MAILBOX_TTL", "60" } }));
    try testing.expect(off.cache_dir == null and !off.cache_dir_unavailable);
    try testing.expectEqual(60, off.mailbox_ttl);

    const nowhere = try settingsFrom(a, testEnv(.{}));
    try testing.expect(nowhere.cache_dir == null and nowhere.cache_dir_unavailable);

    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_MAILBOX_TTL", "-5" }}), "TP_IMAP_MCP_MAILBOX_TTL must be a number of seconds >= 0");
    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_CACHE", "maybe" }}), "TP_IMAP_MCP_CACHE must be one of 1/true/yes/0/false/no");
}

fn expectInvalidSettings(e: TestEnv, comptime expected_diag: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidConfig, loadSettings(arena_state.allocator(), e, &diag));
    try testing.expectEqualStrings(expected_diag, diag.buffered());
}
