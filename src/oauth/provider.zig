//! OAuth provider endpoints and URL/form encoding (ADR 0020, spec §2, §4).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Kind = enum { google, microsoft, custom };

pub const Endpoints = struct {
    auth_url: []const u8,
    token_url: []const u8,
    scope: []const u8,
};

/// Preset endpoints; `custom` uses the configured values as given.
pub fn endpoints(
    arena: Allocator,
    kind: Kind,
    tenant: []const u8,
    custom: Endpoints,
) Allocator.Error!Endpoints {
    return switch (kind) {
        .google => .{
            .auth_url = "https://accounts.google.com/o/oauth2/v2/auth",
            .token_url = "https://oauth2.googleapis.com/token",
            .scope = "https://mail.google.com/",
        },
        .microsoft => .{
            .auth_url = try arena.print("https://login.microsoftonline.com/{s}/oauth2/v2.0/authorize", .{tenant}),
            .token_url = try arena.print("https://login.microsoftonline.com/{s}/oauth2/v2.0/token", .{tenant}),
            .scope = "https://outlook.office.com/IMAP.AccessAsUser.All offline_access",
        },
        .custom => custom,
    };
}

fn isUnreserved(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '.' or ch == '_' or ch == '~';
}

/// RFC 3986 percent-encoding of everything but unreserved characters.
pub fn percentEncode(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    for (s) |ch| {
        if (isUnreserved(ch)) try w.writeByte(ch) else try w.print("%{X:0>2}", .{ch});
    }
}

pub const Pair = struct { []const u8, []const u8 };

/// `k1=v1&k2=v2` with both sides percent-encoded (query strings and
/// application/x-www-form-urlencoded bodies).
pub fn encodePairs(arena: Allocator, pairs: []const Pair) Allocator.Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    for (pairs, 0..) |p, i| {
        if (i > 0) aw.writer.writeByte('&') catch return error.OutOfMemory;
        percentEncode(&aw.writer, p[0]) catch return error.OutOfMemory;
        aw.writer.writeByte('=') catch return error.OutOfMemory;
        percentEncode(&aw.writer, p[1]) catch return error.OutOfMemory;
    }
    return aw.written();
}

/// Authorization URL for the code flow with PKCE (spec §4 step 4). An empty
/// `login_hint` is left out.
pub fn authorizationUrl(
    arena: Allocator,
    kind: Kind,
    ep: Endpoints,
    client_id: []const u8,
    redirect_uri: []const u8,
    state: []const u8,
    code_challenge: []const u8,
    login_hint: []const u8,
) Allocator.Error![]const u8 {
    var pairs: std.ArrayList(Pair) = .empty;
    try pairs.appendSlice(arena, &.{
        .{ "response_type", "code" },
        .{ "client_id", client_id },
        .{ "redirect_uri", redirect_uri },
        .{ "scope", ep.scope },
        .{ "state", state },
        .{ "code_challenge", code_challenge },
        .{ "code_challenge_method", "S256" },
    });
    // Preselects the account to sign in with (the account's IMAP login), so a
    // browser already signed in to another account does not authorize that one.
    // Servers that do not know the parameter must ignore it (RFC 6749 §3.1).
    if (login_hint.len > 0) try pairs.append(arena, .{ "login_hint", login_hint });
    // Google issues a refresh token only for offline access with consent.
    if (kind == .google) try pairs.appendSlice(arena, &.{ .{ "access_type", "offline" }, .{ "prompt", "consent" } });
    const sep: []const u8 = if (std.mem.findScalar(u8, ep.auth_url, '?') != null) "&" else "?";
    return arena.print("{s}{s}{s}", .{ ep.auth_url, sep, try encodePairs(arena, pairs.items) });
}

const testing = std.testing;

test "presets and tenant substitution" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const none: Endpoints = .{ .auth_url = "", .token_url = "", .scope = "" };
    const ms = try endpoints(a, .microsoft, "contoso.onmicrosoft.com", none);
    try testing.expectEqualStrings("https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/token", ms.token_url);
    try testing.expectEqualStrings("https://mail.google.com/", (try endpoints(a, .google, "common", none)).scope);
    const custom: Endpoints = .{ .auth_url = "https://idp.example/auth", .token_url = "https://idp.example/token", .scope = "imap" };
    try testing.expectEqualStrings("imap", (try endpoints(a, .custom, "", custom)).scope);
}

test "authorization URL carries every parameter, percent-encoded" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ep = try endpoints(a, .google, "common", .{ .auth_url = "", .token_url = "", .scope = "" });
    const url = try authorizationUrl(a, .google, ep, "id 1", "http://127.0.0.1:5555/", "st", "ch", "");
    try testing.expectEqualStrings(
        "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=id%201&redirect_uri=http%3A%2F%2F127.0.0.1%3A5555%2F&scope=https%3A%2F%2Fmail.google.com%2F&state=st&code_challenge=ch&code_challenge_method=S256&access_type=offline&prompt=consent",
        url,
    );
    const ms = try endpoints(a, .microsoft, "common", .{ .auth_url = "", .token_url = "", .scope = "" });
    const ms_url = try authorizationUrl(a, .microsoft, ms, "c", "r", "s", "x", "");
    try testing.expect(std.mem.find(u8, ms_url, "access_type") == null);
    try testing.expect(std.mem.find(u8, ms_url, "scope=https%3A%2F%2Foutlook.office.com%2FIMAP.AccessAsUser.All%20offline_access") != null);
}

test "authorization URL carries the login hint, percent-encoded" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const none: Endpoints = .{ .auth_url = "", .token_url = "", .scope = "" };
    const g = try authorizationUrl(a, .google, try endpoints(a, .google, "common", none), "c", "r", "s", "x", "me+imap@example.org");
    try testing.expect(std.mem.find(u8, g, "&code_challenge_method=S256&login_hint=me%2Bimap%40example.org&access_type=offline&prompt=consent") != null);
    const ms = try authorizationUrl(a, .microsoft, try endpoints(a, .microsoft, "common", none), "c", "r", "s", "x", "me@example.org");
    try testing.expect(std.mem.find(u8, ms, "&login_hint=me%40example.org") != null);
}

test "form encoding" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("a=1&b=x%2By%26z", try encodePairs(arena_state.allocator(), &.{ .{ "a", "1" }, .{ "b", "x+y&z" } }));
}
