//! Configuration from environment variables: accounts (ADR 0007) and cache
//! settings (ADRs 0013, 0014).

const std = @import("std");
const Allocator = std.mem.Allocator;
const provider = @import("oauth/provider.zig");

/// OAuth 2.0 settings for an account with IMAP_<NAME>_AUTH=oauth2 (ADR 0020).
pub const OAuthConfig = struct {
    provider: provider.Kind,
    client_id: [:0]const u8,
    client_secret: ?[:0]u8, // mutable so it can be zeroed
    refresh_token: ?[:0]u8, // null only in `auth` mode for the account being authorized
    tenant: []const u8, // microsoft
    custom: provider.Endpoints, // custom
};

pub const Auth = union(enum) { password, oauth2: OAuthConfig };

pub const Account = struct {
    name: []const u8, // as written in IMAP_ACCOUNTS
    host: [:0]const u8,
    port: u16,
    login: [:0]const u8,
    password: [:0]u8, // mutable so it can be zeroed
    readonly: bool,
    drafts: ?[]const u8, // UTF-8; null = discover via \Drafts
    auth: Auth = .password,

    pub fn wipe(self: *Account) void {
        std.crypto.secureZero(u8, self.password);
        switch (self.auth) {
            .password => {},
            .oauth2 => |o| {
                if (o.client_secret) |cs| std.crypto.secureZero(u8, cs);
                if (o.refresh_token) |rt| std.crypto.secureZero(u8, rt);
            },
        }
    }
};

pub const LoadOptions = struct {
    /// `auth` mode: this account (case-insensitive) may lack a refresh token.
    auth_account: ?[]const u8 = null,
};

pub const Error = error{InvalidConfig} || Allocator.Error;

/// Writes a human-readable reason to `diag` on error.InvalidConfig. Never
/// includes a variable's value. `env` is anything with
/// `fn get(self, []const u8) ?[]const u8`.
pub fn load(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error![]Account {
    return loadWith(arena, env, diag, .{});
}

pub fn loadWith(arena: Allocator, env: anytype, diag: *std.Io.Writer, opts: LoadOptions) Error![]Account {
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
        const host = try required(arena, env, diag, prefix, "HOST");
        const port_n = try port(arena, env, diag, prefix);
        const login = try required(arena, env, diag, prefix, "LOGIN");
        const auth_key = try varName(arena, prefix, "AUTH");
        const auth_kind = nonEmpty(env, auth_key) orelse "password";
        var password: [:0]u8 = undefined;
        var auth: Auth = .password;
        if (std.ascii.eqlIgnoreCase(auth_kind, "password")) {
            password = try required(arena, env, diag, prefix, "PASSWORD");
        } else if (std.ascii.eqlIgnoreCase(auth_kind, "oauth2")) {
            const pw_key = try varName(arena, prefix, "PASSWORD");
            if (nonEmpty(env, pw_key) != null) return fail(diag, "{s} must not be set when {s}=oauth2", .{ pw_key, auth_key });
            password = try arena.dupeSentinel(u8, "", 0);
            const exempt = if (opts.auth_account) |aa| std.ascii.eqlIgnoreCase(aa, name) else false;
            auth = .{ .oauth2 = try oauthConfig(arena, env, diag, prefix, name, exempt) };
        } else return fail(diag, "{s} must be password or oauth2", .{auth_key});
        try accounts.append(arena, .{
            .name = name,
            .host = host,
            .port = port_n,
            .login = login,
            .password = password,
            .readonly = try flag(arena, env, diag, prefix, "READONLY"),
            .drafts = nonEmpty(env, try varName(arena, prefix, "DRAFTS")),
            .auth = auth,
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
    /// `$XDG_CONFIG_HOME/tp-imap-mcp` or `$HOME/.config/tp-imap-mcp`; null
    /// when neither is usable (ADR 0014). Holds the optional filters.zon.
    config_dir: ?[]const u8 = null,
    /// Per-body cap after sanitizing (ADR 0018).
    max_body_bytes: usize = default_max_body_bytes,
    /// Running budget per per-UID tool response (ADR 0018).
    max_response_bytes: usize = default_max_response_bytes,
    /// Audit log of tool calls (ADR 0023): `$XDG_STATE_HOME/tp-imap-mcp/
    /// audit.log`, `$HOME/.local/state/…`, or TP_IMAP_MCP_AUDIT_FILE; null
    /// when disabled or no location could be determined.
    audit_file: ?[:0]const u8 = null,
};

pub const default_max_body_bytes = 32 * 1024;
pub const default_max_response_bytes = 128 * 1024;

/// Homebrew's `ca-certificates` bundle on Apple Silicon.
pub const default_ca_file = "/opt/homebrew/etc/ca-certificates/cert.pem";

pub const app_dir = "tp-imap-mcp";

/// Reads TP_IMAP_MCP_CACHE, TP_IMAP_MCP_MAILBOX_TTL, TP_IMAP_MCP_CA_FILE,
/// TP_IMAP_MCP_MAX_BODY_BYTES, TP_IMAP_MCP_MAX_RESPONSE_BYTES,
/// TP_IMAP_MCP_AUDIT, TP_IMAP_MCP_AUDIT_FILE, XDG_CONFIG_HOME,
/// XDG_CACHE_HOME, XDG_STATE_HOME, HOME.
pub fn loadSettings(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error!Settings {
    var settings = try loadCoreSettings(arena, env, diag);
    settings.audit_file = try auditFile(arena, env, diag);
    return settings;
}

/// The audit log path, or null when disabled or nowhere to put it.
fn auditFile(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error!?[:0]const u8 {
    if (!try boolVar(env, diag, "TP_IMAP_MCP_AUDIT", true)) return null;
    const key = "TP_IMAP_MCP_AUDIT_FILE";
    if (nonEmpty(env, key)) |p| {
        if (!std.fs.path.isAbsolute(p)) return fail(diag, "{s} must be an absolute path", .{key});
        return try arena.dupeSentinel(u8, p, 0);
    }
    const dir = try xdgDir(arena, env, "XDG_STATE_HOME", ".local/state") orelse return null;
    return try std.fs.path.joinZ(arena, &.{ dir, "audit.log" });
}

fn loadCoreSettings(arena: Allocator, env: anytype, diag: *std.Io.Writer) Error!Settings {
    const ttl_key = "TP_IMAP_MCP_MAILBOX_TTL";
    const ttl: i64 = if (nonEmpty(env, ttl_key)) |v|
        std.fmt.parseInt(u31, v, 10) catch return fail(diag, "{s} must be a number of seconds >= 0", .{ttl_key})
    else
        3600;
    const ca_file = try arena.dupeSentinel(u8, nonEmpty(env, "TP_IMAP_MCP_CA_FILE") orelse default_ca_file, 0);
    const config_dir = try xdgDir(arena, env, "XDG_CONFIG_HOME", ".config");
    const max_body = try sizeVar(env, diag, "TP_IMAP_MCP_MAX_BODY_BYTES", default_max_body_bytes);
    const max_response = try sizeVar(env, diag, "TP_IMAP_MCP_MAX_RESPONSE_BYTES", default_max_response_bytes);

    if (!try boolVar(env, diag, "TP_IMAP_MCP_CACHE", true)) return .{
        .cache_dir = null,
        .cache_dir_unavailable = false,
        .mailbox_ttl = ttl,
        .ca_file = ca_file,
        .config_dir = config_dir,
        .max_body_bytes = max_body,
        .max_response_bytes = max_response,
    };

    const cache_dir = try xdgDir(arena, env, "XDG_CACHE_HOME", ".cache");
    return .{
        .cache_dir = cache_dir,
        .cache_dir_unavailable = cache_dir == null,
        .mailbox_ttl = ttl,
        .ca_file = ca_file,
        .config_dir = config_dir,
        .max_body_bytes = max_body,
        .max_response_bytes = max_response,
    };
}

/// A byte count >= 1024, or `default` when unset.
fn sizeVar(env: anytype, diag: *std.Io.Writer, key: []const u8, default: usize) Error!usize {
    const v = nonEmpty(env, key) orelse return default;
    const n = std.fmt.parseInt(usize, v, 10) catch return fail(diag, "{s} must be a number of bytes >= 1024", .{key});
    if (n < 1024) return fail(diag, "{s} must be a number of bytes >= 1024", .{key});
    return n;
}

/// `$<xdg_var>/tp-imap-mcp` if that variable is absolute, else
/// `$HOME/<home_sub>/tp-imap-mcp`, else null.
fn xdgDir(arena: Allocator, env: anytype, xdg_var: []const u8, home_sub: []const u8) Allocator.Error!?[]const u8 {
    if (nonEmpty(env, xdg_var)) |x| if (std.fs.path.isAbsolute(x)) return try std.fs.path.join(arena, &.{ x, app_dir });
    if (nonEmpty(env, "HOME")) |h| return try std.fs.path.join(arena, &.{ h, home_sub, app_dir });
    return null;
}

/// Case-insensitive lookup by configured name.
pub fn find(accounts: []Account, name: []const u8) ?*Account {
    for (accounts) |*a| if (std.ascii.eqlIgnoreCase(a.name, name)) return a;
    return null;
}

fn oauthConfig(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8, name: []const u8, refresh_optional: bool) Error!OAuthConfig {
    const pkey = try varName(arena, prefix, "OAUTH_PROVIDER");
    const kind = std.meta.stringToEnum(provider.Kind, nonEmpty(env, pkey) orelse "") orelse
        return fail(diag, "{s} must be google, microsoft or custom", .{pkey});
    const client_id = try required(arena, env, diag, prefix, "OAUTH_CLIENT_ID");
    const secret: ?[:0]u8 = if (kind == .google)
        try required(arena, env, diag, prefix, "OAUTH_CLIENT_SECRET")
    else if (nonEmpty(env, try varName(arena, prefix, "OAUTH_CLIENT_SECRET"))) |v| try arena.dupeSentinel(u8, v, 0) else null;
    const rkey = try varName(arena, prefix, "OAUTH_REFRESH_TOKEN");
    const refresh: ?[:0]u8 = if (nonEmpty(env, rkey)) |v| try arena.dupeSentinel(u8, v, 0) else if (refresh_optional) null else
        return fail(diag, "{s} is missing or empty; run `tp_imap_mcp auth {s}` to obtain one", .{ rkey, name });
    const tkey = try varName(arena, prefix, "OAUTH_TENANT");
    const tenant = nonEmpty(env, tkey) orelse "common";
    for (tenant) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '.' and ch != '-')
        return fail(diag, "{s} must match [A-Za-z0-9.-]+", .{tkey});
    var custom: provider.Endpoints = .{ .auth_url = "", .token_url = "", .scope = "" };
    if (kind == .custom) {
        custom.auth_url = try requiredHttps(arena, env, diag, prefix, "OAUTH_AUTH_URL");
        custom.token_url = try requiredHttps(arena, env, diag, prefix, "OAUTH_TOKEN_URL");
        custom.scope = try required(arena, env, diag, prefix, "OAUTH_SCOPE");
    }
    return .{ .provider = kind, .client_id = client_id, .client_secret = secret, .refresh_token = refresh, .tenant = tenant, .custom = custom };
}

fn requiredHttps(arena: Allocator, env: anytype, diag: *std.Io.Writer, prefix: []const u8, suffix: []const u8) Error![:0]u8 {
    const v = try required(arena, env, diag, prefix, suffix);
    if (!std.ascii.startsWithIgnoreCase(v, "https://"))
        return fail(diag, "{s} must start with https://", .{try varName(arena, prefix, suffix)});
    return v;
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

test "settings: audit log in XDG state, file override, disable switch" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const home = try settingsFrom(a, testEnv(.{.{ "HOME", "/home/me" }}));
    try testing.expectEqualStrings("/home/me/.local/state/tp-imap-mcp/audit.log", home.audit_file.?);
    const xdg = try settingsFrom(a, testEnv(.{ .{ "XDG_STATE_HOME", "/x/state" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/x/state/tp-imap-mcp/audit.log", xdg.audit_file.?);
    const file = try settingsFrom(a, testEnv(.{ .{ "TP_IMAP_MCP_AUDIT_FILE", "/var/log/imap.jsonl" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/var/log/imap.jsonl", file.audit_file.?);
    const off = try settingsFrom(a, testEnv(.{ .{ "TP_IMAP_MCP_AUDIT", "0" }, .{ "HOME", "/home/me" } }));
    try testing.expect(off.audit_file == null);
    const nowhere = try settingsFrom(a, testEnv(.{}));
    try testing.expect(nowhere.audit_file == null);

    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_AUDIT_FILE", "audit.log" }}), "TP_IMAP_MCP_AUDIT_FILE must be an absolute path");
    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_AUDIT", "maybe" }}), "TP_IMAP_MCP_AUDIT must be one of 1/true/yes/0/false/no");
}

test "settings: XDG cache location, HOME fallback, disable switch, TTL" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const xdg = try settingsFrom(a, testEnv(.{ .{ "XDG_CACHE_HOME", "/x/cache" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/x/cache/tp-imap-mcp", xdg.cache_dir.?);
    try testing.expectEqual(3600, xdg.mailbox_ttl);
    try testing.expectEqualStrings(default_ca_file, xdg.ca_file);

    try testing.expectEqualStrings("/home/me/.config/tp-imap-mcp", xdg.config_dir.?);
    const cfg = try settingsFrom(a, testEnv(.{ .{ "XDG_CONFIG_HOME", "/x/config" }, .{ "HOME", "/home/me" } }));
    try testing.expectEqualStrings("/x/config/tp-imap-mcp", cfg.config_dir.?);

    try testing.expectEqual(32 * 1024, xdg.max_body_bytes);
    try testing.expectEqual(128 * 1024, xdg.max_response_bytes);
    const caps = try settingsFrom(a, testEnv(.{ .{ "TP_IMAP_MCP_MAX_BODY_BYTES", "4096" }, .{ "TP_IMAP_MCP_MAX_RESPONSE_BYTES", "1048576" } }));
    try testing.expectEqual(4096, caps.max_body_bytes);
    try testing.expectEqual(1048576, caps.max_response_bytes);

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
    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_MAX_BODY_BYTES", "100" }}), "TP_IMAP_MCP_MAX_BODY_BYTES must be a number of bytes >= 1024");
    try expectInvalidSettings(testEnv(.{.{ "TP_IMAP_MCP_MAX_RESPONSE_BYTES", "lots" }}), "TP_IMAP_MCP_MAX_RESPONSE_BYTES must be a number of bytes >= 1024");
}

fn expectInvalidSettings(e: TestEnv, comptime expected_diag: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidConfig, loadSettings(arena_state.allocator(), e, &diag));
    try testing.expectEqualStrings(expected_diag, diag.buffered());
}

fn loadOne(a: Allocator, e: TestEnv, opts: LoadOptions) !Account {
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    return (try loadWith(a, e, &diag, opts))[0];
}

fn expectInvalidWith(e: TestEnv, opts: LoadOptions, comptime expected_diag: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&buf);
    try testing.expectError(error.InvalidConfig, loadWith(arena_state.allocator(), e, &diag, opts));
    try testing.expectEqualStrings(expected_diag, diag.buffered());
    try testing.expect(std.mem.find(u8, diag.buffered(), "s3cret") == null);
}

test "oauth2 accounts: presets, custom, auth-mode exemption" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const ms = try loadOne(a, testEnv(.{
        .{ "IMAP_ACCOUNTS", "work" },                 .{ "IMAP_WORK_HOST", "outlook.office365.com" },
        .{ "IMAP_WORK_LOGIN", "me@contoso.com" },     .{ "IMAP_WORK_AUTH", "oauth2" },
        .{ "IMAP_WORK_OAUTH_PROVIDER", "microsoft" }, .{ "IMAP_WORK_OAUTH_CLIENT_ID", "cid" },
        .{ "IMAP_WORK_OAUTH_REFRESH_TOKEN", "s3cret" },
    }), .{});
    try testing.expectEqual(.microsoft, ms.auth.oauth2.provider);
    try testing.expectEqualStrings("common", ms.auth.oauth2.tenant);
    try testing.expect(ms.auth.oauth2.client_secret == null);
    try testing.expectEqualStrings("s3cret", ms.auth.oauth2.refresh_token.?);

    const custom = try loadOne(a, testEnv(.{
        .{ "IMAP_ACCOUNTS", "x" },                       .{ "IMAP_X_HOST", "h" },
        .{ "IMAP_X_LOGIN", "l" },                        .{ "IMAP_X_AUTH", "oauth2" },
        .{ "IMAP_X_OAUTH_PROVIDER", "custom" },          .{ "IMAP_X_OAUTH_CLIENT_ID", "c" },
        .{ "IMAP_X_OAUTH_REFRESH_TOKEN", "r" },          .{ "IMAP_X_OAUTH_AUTH_URL", "https://idp/a" },
        .{ "IMAP_X_OAUTH_TOKEN_URL", "HTTPS://idp/t" },  .{ "IMAP_X_OAUTH_SCOPE", "imap offline" },
    }), .{});
    try testing.expectEqualStrings("imap offline", custom.auth.oauth2.custom.scope);

    // auth mode: the account being authorized may lack a refresh token.
    const pending = try loadOne(a, testEnv(.{
        .{ "IMAP_ACCOUNTS", "g" },       .{ "IMAP_G_HOST", "imap.gmail.com" },
        .{ "IMAP_G_LOGIN", "me@x" },     .{ "IMAP_G_AUTH", "oauth2" },
        .{ "IMAP_G_OAUTH_PROVIDER", "google" }, .{ "IMAP_G_OAUTH_CLIENT_ID", "c" },
        .{ "IMAP_G_OAUTH_CLIENT_SECRET", "s3cret" },
    }), .{ .auth_account = "G" });
    try testing.expect(pending.auth.oauth2.refresh_token == null);

    var acct = ms;
    acct.wipe();
    for (acct.auth.oauth2.refresh_token.?) |ch| try testing.expectEqual(0, ch);
}

test "oauth2 configuration errors" {
    const base = .{
        .{ "IMAP_ACCOUNTS", "w" }, .{ "IMAP_W_HOST", "h" }, .{ "IMAP_W_LOGIN", "l" },
    };
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "kerberos" } }), .{}, "IMAP_W_AUTH must be password or oauth2");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" }, .{ "IMAP_W_PASSWORD", "s3cret" } }), .{}, "IMAP_W_PASSWORD must not be set when IMAP_W_AUTH=oauth2");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" } }), .{}, "IMAP_W_OAUTH_PROVIDER must be google, microsoft or custom");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" }, .{ "IMAP_W_OAUTH_PROVIDER", "microsoft" } }), .{}, "IMAP_W_OAUTH_CLIENT_ID is missing or empty");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" }, .{ "IMAP_W_OAUTH_PROVIDER", "google" }, .{ "IMAP_W_OAUTH_CLIENT_ID", "c" }, .{ "IMAP_W_OAUTH_REFRESH_TOKEN", "s3cret" } }), .{}, "IMAP_W_OAUTH_CLIENT_SECRET is missing or empty");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" }, .{ "IMAP_W_OAUTH_PROVIDER", "microsoft" }, .{ "IMAP_W_OAUTH_CLIENT_ID", "c" } }), .{}, "IMAP_W_OAUTH_REFRESH_TOKEN is missing or empty; run `tp_imap_mcp auth w` to obtain one");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" }, .{ "IMAP_W_OAUTH_PROVIDER", "microsoft" }, .{ "IMAP_W_OAUTH_CLIENT_ID", "c" }, .{ "IMAP_W_OAUTH_REFRESH_TOKEN", "s3cret" }, .{ "IMAP_W_OAUTH_TENANT", "bad/tenant" } }), .{}, "IMAP_W_OAUTH_TENANT must match [A-Za-z0-9.-]+");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" }, .{ "IMAP_W_OAUTH_PROVIDER", "custom" }, .{ "IMAP_W_OAUTH_CLIENT_ID", "c" }, .{ "IMAP_W_OAUTH_REFRESH_TOKEN", "s3cret" }, .{ "IMAP_W_OAUTH_AUTH_URL", "http://idp/a" }, .{ "IMAP_W_OAUTH_TOKEN_URL", "https://idp/t" }, .{ "IMAP_W_OAUTH_SCOPE", "x" } }), .{}, "IMAP_W_OAUTH_AUTH_URL must start with https://");
    try expectInvalidWith(testEnv(base ++ .{ .{ "IMAP_W_AUTH", "oauth2" }, .{ "IMAP_W_OAUTH_PROVIDER", "custom" }, .{ "IMAP_W_OAUTH_CLIENT_ID", "c" }, .{ "IMAP_W_OAUTH_REFRESH_TOKEN", "s3cret" } }), .{}, "IMAP_W_OAUTH_AUTH_URL is missing or empty");
    // password accounts still need a password
    try expectInvalidWith(testEnv(base), .{}, "IMAP_W_PASSWORD is missing or empty");
}
