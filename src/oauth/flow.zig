//! `tp_imap_mcp auth <account>`: OAuth authorization-code flow with PKCE and a
//! 127.0.0.1 loopback redirect; prints the refresh token once (ADR 0020,
//! spec §4). Nothing is written to disk.

const std = @import("std");
const wipe = @import("wipe.zig");
const Allocator = std.mem.Allocator;
const config = @import("../config.zig");
const pkce = @import("pkce.zig");
const provider = @import("provider.zig");
const token = @import("token.zig");
const unicode = @import("../sanitize/unicode.zig");
const text = @import("../text.zig");

pub const timeout_ms = 5 * 60 * 1000;
/// Longest wait for one connection's request line, so a local client that
/// connects and sends nothing cannot stall the flow.
pub const read_timeout_ms = 10 * 1000;

pub const Callback = union(enum) {
    code: []const u8,
    /// The provider reported an error (e.g. access_denied), cleaned.
    provider_error: []const u8,
    state_mismatch,
    /// Not the redirect (favicon, wrong path, malformed): keep waiting.
    ignore,
};

fn percentDecode(arena: Allocator, s: []const u8) Allocator.Error![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '+') {
            try out.append(arena, ' ');
        } else if (s[i] == '%' and i + 2 < s.len) {
            if (std.fmt.parseInt(u8, s[i + 1 .. i + 3], 16)) |b| {
                try out.append(arena, b);
                i += 2;
            } else |_| try out.append(arena, s[i]);
        } else try out.append(arena, s[i]);
    }
    return out.items;
}

/// Interprets the redirect's request line, e.g. `GET /?code=…&state=… HTTP/1.1`.
pub fn parseCallback(arena: Allocator, request_line: []const u8, expected_state: []const u8) Allocator.Error!Callback {
    var parts = std.mem.splitScalar(u8, std.mem.trimEnd(u8, request_line, "\r\n"), ' ');
    const method = parts.next() orelse return .ignore;
    const target = parts.next() orelse return .ignore;
    if (!std.mem.eql(u8, method, "GET")) return .ignore;
    if (!std.mem.startsWith(u8, target, "/?")) return .ignore;
    var code: ?[]const u8 = null;
    var state: ?[]const u8 = null;
    var err: ?[]const u8 = null;
    var it = std.mem.splitScalar(u8, target[2..], '&');
    while (it.next()) |kv| {
        const eq = std.mem.findScalar(u8, kv, '=') orelse continue;
        const v = try percentDecode(arena, kv[eq + 1 ..]);
        const k = kv[0..eq];
        if (std.mem.eql(u8, k, "code")) code = v;
        if (std.mem.eql(u8, k, "state")) state = v;
        if (std.mem.eql(u8, k, "error")) err = v;
    }
    const st = state orelse return .ignore;
    // An error counts only with our state (RFC 6749 §4.1.2.1 echoes it):
    // otherwise any local page could cancel the login.
    if (err) |e| {
        if (!std.mem.eql(u8, st, expected_state)) return .ignore;
        return .{ .provider_error = text.truncateUtf8(try unicode.clean(arena, try text.sanitizeUtf8(arena, e)), 200) };
    }
    if (!std.mem.eql(u8, st, expected_state)) return .state_mismatch;
    const c = code orelse return .ignore;
    if (c.len == 0) return .ignore;
    return .{ .code = c };
}

const page_ok = "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n" ++
    "<!doctype html><title>tp-imap-mcp</title><p>Authorization received. You can close this tab and return to the terminal.</p>";
const page_failed = "HTTP/1.1 400 Bad Request\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n" ++
    "<!doctype html><title>tp-imap-mcp</title><p>Authorization failed. Return to the terminal for details.</p>";
const page_not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Accepts connections until the redirect arrives or `deadline_ms` passes.
pub fn awaitCallback(arena: Allocator, io: std.Io, server: *std.Io.net.Server, expected_state: []const u8, wait_ms: i32) !Callback {
    return awaitCallbackRead(arena, io, server, expected_state, wait_ms, read_timeout_ms);
}

/// `awaitCallback` with `read_ms` as the per-connection read timeout.
fn awaitCallbackRead(arena: Allocator, io: std.Io, server: *std.Io.net.Server, expected_state: []const u8, wait_ms: i32, read_ms: i32) !Callback {
    var remaining = wait_ms;
    while (remaining > 0) {
        const start: std.Io.Timestamp = .now(io, .awake);
        var fds = [_]std.posix.pollfd{.{ .fd = server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = try std.posix.poll(&fds, remaining);
        if (ready == 0) return error.Timeout;
        const stream = server.accept(io) catch |e| switch (e) {
            // The client went away between poll and accept: keep waiting.
            error.ConnectionAborted, error.WouldBlock, error.ProtocolFailure => {
                remaining -= @intCast(@min(start.untilNow(io, .awake).toMilliseconds(), remaining));
                continue;
            },
            else => return e,
        };
        defer stream.close(io);
        var rbuf: [8192]u8 = undefined;
        const line = readRequestLine(io, stream.socket.handle, &rbuf, @min(read_ms, remaining));
        const cb = try parseCallback(arena, line, expected_state);
        var wbuf: [512]u8 = undefined;
        var writer = stream.writer(io, &wbuf);
        writer.interface.writeAll(switch (cb) {
            .ignore => page_not_found,
            .code => page_ok,
            .provider_error, .state_mismatch => page_failed,
        }) catch {};
        writer.interface.flush() catch {};
        if (cb != .ignore) return cb;
        remaining -= @intCast(@min(start.untilNow(io, .awake).toMilliseconds(), remaining));
    }
    return error.Timeout;
}

/// The request line (through '\n'), or "" when none arrives within `ms`:
/// a client that connects and sends nothing, or stops mid-line, gives up its
/// turn instead of stalling the flow. Reads only when poll says data is
/// there, so the blocking socket never blocks.
fn readRequestLine(io: std.Io, fd: std.posix.socket_t, buf: []u8, ms: i32) []const u8 {
    const start: std.Io.Timestamp = .now(io, .awake);
    var n: usize = 0;
    while (n < buf.len) {
        const left = ms - @as(i32, @intCast(@min(start.untilNow(io, .awake).toMilliseconds(), ms)));
        if (left <= 0) return "";
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&fds, left) catch return "";
        if (ready == 0) return "";
        const got = std.c.read(fd, buf[n..].ptr, buf.len - n);
        if (got <= 0) return "";
        const chunk = buf[n .. n + @as(usize, @intCast(got))];
        if (std.mem.findScalar(u8, chunk, '\n')) |i| return buf[0 .. n + i + 1];
        n += chunk.len;
    }
    return buf[0..n]; // over-long: parseCallback ignores it
}

/// Runs the flow for `account`; returns the process exit code.
pub fn run(gpa: Allocator, io: std.Io, account: *const config.Account, settings: config.Settings, out: *std.Io.Writer, err: *std.Io.Writer) !u8 {
    // Holds the code, verifier and token response: wiped when freed.
    var wiping: wipe.Wiping = .{ .parent = gpa };
    var arena_state: std.heap.ArenaAllocator = .init(wiping.allocator());
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const o = switch (account.auth) {
        .oauth2 => |o| o,
        .password => {
            try err.print("account \"{s}\" does not use OAuth (set IMAP_{s}_AUTH=oauth2)\n", .{ account.name, try std.ascii.allocUpperString(arena, account.name) });
            return 1;
        },
    };
    const ep = try provider.endpoints(arena, o.provider, o.tenant, o.custom);
    var verifier, const state = blk: {
        const v = pkce.randomToken(io) catch break :blk null;
        const st = pkce.randomToken(io) catch break :blk null;
        break :blk .{ v, st };
    } orelse {
        try err.writeAll("No secure random source is available; cannot start the authorization.\n");
        return 1;
    };
    defer std.crypto.secureZero(u8, &verifier);
    const challenge = pkce.challenge(&verifier);

    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(io, .{});
    defer server.deinit(io);
    const redirect_uri = try arena.print("http://127.0.0.1:{d}/", .{server.socket.address.getPort()});
    const url = try provider.authorizationUrl(arena, o.provider, ep, o.client_id, redirect_uri, &state, &challenge);

    try err.print("Opening your browser to authorize account \"{s}\".\nIf it does not open, visit:\n\n{s}\n\nWaiting up to 5 minutes for the redirect to {s} ...\n", .{ account.name, url, redirect_uri });
    try err.flush();
    if (std.process.spawn(io, .{ .argv = &.{ "/usr/bin/open", url } })) |child_const| {
        var child = child_const;
        _ = child.wait(io) catch {};
    } else |_| {}

    const cb = awaitCallback(arena, io, &server, &state, timeout_ms) catch |e| switch (e) {
        error.Timeout => {
            try err.writeAll("Timed out waiting for the authorization redirect.\n");
            return 1;
        },
        else => return e,
    };
    const code = switch (cb) {
        .code => |c| c,
        .provider_error => |pe| {
            try err.print("Authorization failed: {s}\n", .{pe});
            return 1;
        },
        .state_mismatch => {
            try err.writeAll("Authorization failed: state mismatch (possible cross-site request); try again.\n");
            return 1;
        },
        .ignore => unreachable,
    };

    var client = token.Client.init(gpa, io, settings.ca_file) catch {
        try err.print("Cannot load the CA bundle {s}.\n", .{settings.ca_file});
        return 1;
    };
    defer client.deinit();
    const resp = client.exchangeCode(arena, ep, o.client_id, o.client_secret, code, redirect_uri, &verifier) catch |e| {
        try err.print("Token request failed ({t}).\n", .{e});
        return 1;
    };
    switch (resp) {
        .failed => |f| {
            try err.print("Token request failed: {s}{s}{s}\n", .{ f.code, if (f.description.len > 0) ": " else "", f.description });
            return 1;
        },
        .ok => |ok| {
            const rt = ok.refresh_token orelse {
                try err.writeAll("The provider returned no refresh token. For Google, revoke the app's access and authorize again (consent must grant offline access); for Microsoft, make sure the offline_access permission is granted.\n");
                return 1;
            };
            try out.print("{s}\n", .{rt});
            try out.flush();
            // Never suggest putting the token on a command line: it would
            // land in shell history and be visible in the process list.
            try err.print("\nStore it in a 1Password password field by pasting it in the 1Password app; do not pass it on a command line.\nTip: run `... tp_imap_mcp auth {s} | pbcopy` to copy it without showing it.\nThen reference it as IMAP_{s}_OAUTH_REFRESH_TOKEN=op://<vault>/<item>/<field>\n", .{ account.name, try std.ascii.allocUpperString(arena, account.name) });
            return 0;
        },
    }
}

const testing = std.testing;

test "callback parsing" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("4/0Ab%x y", (try parseCallback(a, "GET /?code=4%2F0Ab%25x+y&state=S1 HTTP/1.1\r\n", "S1")).code);
    try testing.expectEqual(.state_mismatch, try parseCallback(a, "GET /?code=c&state=EVIL HTTP/1.1\r\n", "S1"));
    try testing.expectEqualStrings("access_denied", (try parseCallback(a, "GET /?error=access_denied&state=S1 HTTP/1.1\r\n", "S1")).provider_error);
    try testing.expectEqual(.ignore, try parseCallback(a, "GET /favicon.ico HTTP/1.1\r\n", "S1"));
    try testing.expectEqual(.ignore, try parseCallback(a, "POST /?code=c&state=S1 HTTP/1.1\r\n", "S1"));
    try testing.expectEqual(.ignore, try parseCallback(a, "garbage", "S1"));
    try testing.expectEqual(.ignore, try parseCallback(a, "GET /?state=S1 HTTP/1.1\r\n", "S1")); // no code
}

test "an error redirect counts only with the matching state" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Any local page could send these; they must not cancel the login.
    try testing.expectEqual(.ignore, try parseCallback(a, "GET /?error=access_denied HTTP/1.1\r\n", "S1"));
    try testing.expectEqual(.ignore, try parseCallback(a, "GET /?error=access_denied&state=EVIL HTTP/1.1\r\n", "S1"));
    try testing.expectEqualStrings("access_denied", (try parseCallback(a, "GET /?state=S1&error=access_denied HTTP/1.1\r\n", "S1")).provider_error);
}

/// Connects and sends nothing for `hold_ms`, like a stuck local client.
fn silentClient(port: u16, hold_ms: u64) void {
    var addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
    const s = addr.connect(testing.io, .{ .mode = .stream }) catch return;
    defer s.close(testing.io);
    std.Io.sleep(testing.io, .fromMilliseconds(@intCast(hold_ms)), .awake) catch {};
}

/// Sends `request` and stores the response's status line in `status`.
fn requestStatus(port: u16, request: []const u8, status: *[64]u8) void {
    @memset(status, 0);
    var addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
    const s = addr.connect(testing.io, .{ .mode = .stream }) catch return;
    defer s.close(testing.io);
    var wbuf: [512]u8 = undefined;
    var w = s.writer(testing.io, &wbuf);
    w.interface.writeAll(request) catch return;
    w.interface.flush() catch return;
    var rbuf: [512]u8 = undefined;
    var r = s.reader(testing.io, &rbuf);
    const line = r.interface.takeDelimiterInclusive('\n') catch return;
    @memcpy(status[0..@min(line.len, 64)], line[0..@min(line.len, 64)]);
}

fn sendRequests(port: u16, requests: []const []const u8) void {
    for (requests) |req| {
        var addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(testing.io, .{ .mode = .stream }) catch return;
        defer s.close(testing.io);
        var wbuf: [512]u8 = undefined;
        var w = s.writer(testing.io, &wbuf);
        w.interface.writeAll(req) catch return;
        w.interface.flush() catch return;
        var rbuf: [512]u8 = undefined;
        var r = s.reader(testing.io, &rbuf);
        _ = r.interface.takeDelimiterInclusive('\n') catch {};
    }
}

test "awaitCallback ignores stray requests and returns the code" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(testing.io, .{});
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();
    const t = try std.Thread.spawn(.{}, sendRequests, .{ port, &[_][]const u8{
        "GET /favicon.ico HTTP/1.1\r\nHost: x\r\n\r\n",
        "GET /?code=THE-CODE&state=S1 HTTP/1.1\r\nHost: x\r\n\r\n",
    } });
    const cb = try awaitCallback(arena_state.allocator(), testing.io, &server, "S1", 10_000);
    t.join();
    try testing.expectEqualStrings("THE-CODE", cb.code);
}

test "awaitCallback times out" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(testing.io, .{});
    defer server.deinit(testing.io);
    try testing.expectError(error.Timeout, awaitCallback(arena_state.allocator(), testing.io, &server, "S1", 50));
}

test "a connection that sends nothing does not stall the wait" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(testing.io, .{});
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();
    const silent = try std.Thread.spawn(.{}, silentClient, .{ port, 3000 });
    defer silent.join();
    std.Io.sleep(testing.io, .fromMilliseconds(50), .awake) catch {}; // silent connects first
    const t = try std.Thread.spawn(.{}, sendRequests, .{ port, &[_][]const u8{"GET /?code=C&state=S1 HTTP/1.1\r\n\r\n"} });
    defer t.join();
    const started: std.Io.Timestamp = .now(testing.io, .awake);
    const cb = try awaitCallbackRead(arena_state.allocator(), testing.io, &server, "S1", 10_000, 200);
    try testing.expectEqualStrings("C", cb.code);
    // Without a read timeout the wait lasts as long as the silent client (3 s).
    try testing.expect(started.untilNow(testing.io, .awake).toMilliseconds() < 2000);
}

test "a failed authorization gets a failure page, not \"Authorization received\"" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(testing.io, .{});
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();
    var status: [64]u8 = undefined;
    const t = try std.Thread.spawn(.{}, requestStatus, .{ port, "GET /?error=access_denied&state=S1 HTTP/1.1\r\n\r\n", &status });
    const cb = try awaitCallback(arena_state.allocator(), testing.io, &server, "S1", 10_000);
    t.join();
    try testing.expectEqualStrings("access_denied", cb.provider_error);
    try testing.expect(std.mem.startsWith(u8, &status, "HTTP/1.1 400"));
}
