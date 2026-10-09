//! OAuth token endpoint client: refresh and code exchange, response parsing,
//! access-token expiry (ADR 0020, spec §3, §4). Token values never appear in
//! diagnostics.

const std = @import("std");
const Allocator = std.mem.Allocator;
const provider = @import("provider.zig");
const unicode = @import("../sanitize/unicode.zig");
const text = @import("../text.zig");

/// Refresh this many seconds before the access token expires.
pub const refresh_margin_sec = 300;

pub const AccessToken = struct {
    value: []u8, // owned by the caller's allocator
    expires_at: i64, // unix seconds
};

pub fn needsRefresh(tok: ?AccessToken, now_sec: i64) bool {
    const t = tok orelse return true;
    return now_sec + refresh_margin_sec >= t.expires_at;
}

pub const Response = union(enum) {
    ok: struct { access_token: []const u8, expires_in: i64, refresh_token: ?[]const u8 },
    /// `error` / `error_description` from the provider, cleaned and capped, or
    /// a description of what was wrong with the response.
    failed: struct { code: []const u8, description: []const u8 },
};

const max_error_field = 200;

fn safeField(arena: Allocator, s: []const u8) Allocator.Error![]const u8 {
    const clean = try unicode.clean(arena, try text.sanitizeUtf8(arena, s));
    return text.truncateUtf8(clean, max_error_field);
}

/// Interprets a token endpoint response (any HTTP status).
pub fn parseResponse(arena: Allocator, status: u16, body: []const u8) Allocator.Error!Response {
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch
        return .{ .failed = .{ .code = "invalid_response", .description = try arena.print("HTTP {d}; response is not JSON", .{status}) } };
    if (parsed != .object) return .{ .failed = .{ .code = "invalid_response", .description = try arena.print("HTTP {d}; response is not a JSON object", .{status}) } };
    const obj = parsed.object;
    if (obj.get("error")) |e| {
        const desc = if (obj.get("error_description")) |d| (if (d == .string) d.string else "") else "";
        return .{ .failed = .{
            .code = if (e == .string) try safeField(arena, e.string) else "error",
            .description = try safeField(arena, desc),
        } };
    }
    if (status < 200 or status >= 300)
        return .{ .failed = .{ .code = "http_error", .description = try arena.print("HTTP {d}", .{status}) } };
    const at = obj.get("access_token") orelse
        return .{ .failed = .{ .code = "invalid_response", .description = "no access_token in response" } };
    if (at != .string or at.string.len == 0)
        return .{ .failed = .{ .code = "invalid_response", .description = "access_token is not a string" } };
    const raw_expires: i64 = if (obj.get("expires_in")) |v| switch (v) {
        .integer => |n| n,
        .string => |s| std.fmt.parseInt(i64, s, 10) catch 3600,
        else => 3600,
    } else 3600;
    // Clamp: a hostile or buggy endpoint must not overflow expiry arithmetic
    // or force a refresh on every call.
    const expires_in = std.math.clamp(raw_expires, 60, 86400);
    const rt: ?[]const u8 = if (obj.get("refresh_token")) |v| (if (v == .string) v.string else null) else null;
    return .{ .ok = .{ .access_token = at.string, .expires_in = expires_in, .refresh_token = rt } };
}

/// Largest token endpoint response read; real ones are a few KB. A larger
/// one fails the request instead of growing memory without bound.
pub const max_body_bytes = 64 * 1024;

pub const Client = struct {
    gpa: Allocator,
    io: std.Io,
    ca_file: []u8, // owned
    /// Test seam: allow plain http to 127.0.0.1 (never set in production).
    allow_insecure_loopback: bool = false,
    /// Overall limit per token request. The request runs on a worker thread so
    /// a stalled endpoint cannot block the (single-threaded) MCP server.
    timeout_ms: u32 = 30_000,

    /// Token-endpoint client trusting exactly the PEM bundle at `ca_file` (the
    /// same bundle used for IMAP, ADR 0016). Fails early if it cannot load.
    pub fn init(gpa: Allocator, io: std.Io, ca_file: []const u8) !Client {
        var probe = try newHttpClient(gpa, io, ca_file);
        probe.deinit();
        return .{ .gpa = gpa, .io = io, .ca_file = try gpa.dupe(u8, ca_file) };
    }

    pub fn deinit(self: *Client) void {
        self.gpa.free(self.ca_file);
        self.* = undefined;
    }

    pub const PostError = error{ InsecureTokenUrl, TokenRequestFailed, TokenRequestTimeout } || Allocator.Error;

    /// POSTs a form; returns the status and body (copied into `arena`).
    fn post(self: *Client, arena: Allocator, url: []const u8, form: []const u8) PostError!struct { status: u16, body: []const u8 } {
        const https = std.ascii.startsWithIgnoreCase(url, "https://");
        const loopback = std.ascii.startsWithIgnoreCase(url, "http://127.0.0.1:");
        if (!https and !(self.allow_insecure_loopback and loopback)) return error.InsecureTokenUrl;

        const job = try Job.create(self.gpa, self.io, self.ca_file, url, form);
        const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch {
            job.release();
            job.release();
            return error.TokenRequestFailed;
        };
        thread.detach();
        defer job.release();

        const start: std.Io.Timestamp = .now(self.io, .awake);
        while (!job.done.load(.acquire)) {
            if (start.untilNow(self.io, .awake).toMilliseconds() >= self.timeout_ms) return error.TokenRequestTimeout;
            self.io.sleep(.fromMilliseconds(10), .awake) catch {};
        }
        if (job.failed) return error.TokenRequestFailed;
        return .{ .status = job.status, .body = try arena.dupe(u8, job.body) };
    }

    /// grant_type=refresh_token.
    pub fn refresh(
        self: *Client,
        arena: Allocator,
        ep: provider.Endpoints,
        client_id: []const u8,
        client_secret: ?[]const u8,
        refresh_token: []const u8,
    ) PostError!Response {
        var pairs: std.ArrayList(provider.Pair) = .empty;
        try pairs.appendSlice(arena, &.{
            .{ "grant_type", "refresh_token" },
            .{ "refresh_token", refresh_token },
            .{ "client_id", client_id },
            .{ "scope", ep.scope },
        });
        if (client_secret) |cs| try pairs.append(arena, .{ "client_secret", cs });
        const r = try self.post(arena, ep.token_url, try provider.encodePairs(arena, pairs.items));
        return parseResponse(arena, r.status, r.body);
    }

    /// grant_type=authorization_code with the PKCE verifier.
    pub fn exchangeCode(
        self: *Client,
        arena: Allocator,
        ep: provider.Endpoints,
        client_id: []const u8,
        client_secret: ?[]const u8,
        code: []const u8,
        redirect_uri: []const u8,
        verifier: []const u8,
    ) PostError!Response {
        var pairs: std.ArrayList(provider.Pair) = .empty;
        try pairs.appendSlice(arena, &.{
            .{ "grant_type", "authorization_code" },
            .{ "code", code },
            .{ "redirect_uri", redirect_uri },
            .{ "client_id", client_id },
            .{ "code_verifier", verifier },
        });
        if (client_secret) |cs| try pairs.append(arena, .{ "client_secret", cs });
        const r = try self.post(arena, ep.token_url, try provider.encodePairs(arena, pairs.items));
        return parseResponse(arena, r.status, r.body);
    }
};

/// A fresh std.http client for one request: CA bundle from `ca_file` and the
/// current time for certificate validity (the system store is never rescanned
/// because `now` is set).
pub fn newHttpClient(gpa: Allocator, io: std.Io, ca_file: []const u8) !std.http.Client {
    var http: std.http.Client = .{ .allocator = gpa, .io = io };
    errdefer http.deinit();
    const now: std.Io.Timestamp = .now(io, .real);
    try http.ca_bundle.addCertsFromFilePathAbsolute(gpa, io, now, ca_file);
    http.now = now;
    return http;
}

/// One token request, shared by the caller and its worker thread; freed by
/// whichever of the two releases it last (the caller may give up on timeout).
const Job = struct {
    gpa: Allocator,
    io: std.Io,
    ca_file: []u8,
    url: []u8,
    form: []u8,
    refs: std.atomic.Value(u8) = .init(2),
    done: std.atomic.Value(bool) = .init(false),
    failed: bool = false,
    status: u16 = 0,
    body: []u8 = &.{},

    fn create(gpa: Allocator, io: std.Io, ca_file: []const u8, url: []const u8, form: []const u8) Allocator.Error!*Job {
        const job = try gpa.create(Job);
        errdefer gpa.destroy(job);
        job.* = .{ .gpa = gpa, .io = io, .ca_file = undefined, .url = undefined, .form = undefined };
        job.ca_file = try gpa.dupe(u8, ca_file);
        errdefer gpa.free(job.ca_file);
        job.url = try gpa.dupe(u8, url);
        errdefer gpa.free(job.url);
        job.form = try gpa.dupe(u8, form);
        return job;
    }

    fn release(job: *Job) void {
        if (job.refs.fetchSub(1, .acq_rel) != 1) return;
        const gpa = job.gpa;
        // The form carries the refresh token and client secret.
        std.crypto.secureZero(u8, job.form);
        std.crypto.secureZero(u8, job.body);
        gpa.free(job.ca_file);
        gpa.free(job.url);
        gpa.free(job.form);
        gpa.free(job.body);
        gpa.destroy(job);
    }

    fn run(job: *Job) void {
        defer job.release();
        job.fetch() catch {
            job.failed = true;
        };
        job.done.store(true, .release);
    }

    fn fetch(job: *Job) !void {
        var http = try newHttpClient(job.gpa, job.io, job.ca_file);
        defer http.deinit();
        const buf = try job.gpa.alloc(u8, max_body_bytes);
        defer {
            std.crypto.secureZero(u8, buf); // holds tokens
            job.gpa.free(buf);
        }
        var body: std.Io.Writer = .fixed(buf);
        const result = try http.fetch(.{
            .location = .{ .url = job.url },
            .method = .POST,
            .payload = job.form,
            .headers = .{ .content_type = .{ .override = "application/x-www-form-urlencoded" } },
            .extra_headers = &.{.{ .name = "accept", .value = "application/json" }},
            .response_writer = &body,
            .keep_alive = false,
        });
        job.status = @intFromEnum(result.status);
        job.body = try job.gpa.dupe(u8, body.buffered());
    }
};

const testing = std.testing;

test "parse: success, defaults, errors, garbage" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const ok = try parseResponse(a, 200, "{\"access_token\":\"AT\",\"expires_in\":3599,\"refresh_token\":\"RT2\",\"token_type\":\"Bearer\",\"extra\":1}");
    try testing.expectEqualStrings("AT", ok.ok.access_token);
    try testing.expectEqual(3599, ok.ok.expires_in);
    try testing.expectEqualStrings("RT2", ok.ok.refresh_token.?);

    try testing.expectEqual(3600, (try parseResponse(a, 200, "{\"access_token\":\"AT\"}")).ok.expires_in);
    try testing.expectEqual(120, (try parseResponse(a, 200, "{\"access_token\":\"AT\",\"expires_in\":\"120\"}")).ok.expires_in);

    const bad = try parseResponse(a, 400, "{\"error\":\"invalid_grant\",\"error_description\":\"Token has been expired or revoked.\"}");
    try testing.expectEqualStrings("invalid_grant", bad.failed.code);
    try testing.expectEqualStrings("Token has been expired or revoked.", bad.failed.description);

    try testing.expectEqualStrings("invalid_response", (try parseResponse(a, 200, "<html>")).failed.code);
    try testing.expectEqualStrings("invalid_response", (try parseResponse(a, 200, "{\"token_type\":\"Bearer\"}")).failed.code);
    try testing.expectEqualStrings("http_error", (try parseResponse(a, 500, "{}")).failed.code);
}

test "error fields are cleaned and capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var long: std.ArrayList(u8) = .empty;
    try long.appendSlice(a, "{\"error\":\"x\\u200by\",\"error_description\":\"");
    try long.appendNTimes(a, 'd', 1000);
    try long.appendSlice(a, "\"}");
    const r = try parseResponse(a, 400, long.items);
    try testing.expectEqualStrings("xy", r.failed.code);
    try testing.expectEqual(200, r.failed.description.len);
}

test "refresh decision" {
    try testing.expect(needsRefresh(null, 1000));
    var v = [_]u8{'x'};
    try testing.expect(needsRefresh(.{ .value = &v, .expires_at = 1200 }, 1000)); // within the margin
    try testing.expect(!needsRefresh(.{ .value = &v, .expires_at = 2000 }, 1000));
}

/// One-shot fake token endpoint on 127.0.0.1 (tests only; also used by
/// accounts.zig tests).
pub const FakeServer = struct {
    server: std.Io.net.Server,
    response: []const u8,
    request: [4096]u8 = undefined,
    request_len: usize = 0,

    pub fn start(response: []const u8) !*FakeServer {
        var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
        const self = try testing.allocator.create(FakeServer);
        self.* = .{ .server = try addr.listen(testing.io, .{ .reuse_address = true }), .response = response };
        return self;
    }

    pub fn port(self: *FakeServer) u16 {
        return self.server.socket.address.getPort();
    }

    pub fn destroy(self: *FakeServer) void {
        self.server.deinit(testing.io);
        testing.allocator.destroy(self);
    }

    pub fn serveOne(self: *FakeServer) void {
        const stream = self.server.accept(testing.io) catch return;
        defer stream.close(testing.io);
        var rbuf: [4096]u8 = undefined;
        var reader = stream.reader(testing.io, &rbuf);
        // Read headers, then the body by Content-Length.
        var len: usize = 0;
        var content_length: usize = 0;
        while (true) {
            const line = reader.interface.takeDelimiterInclusive('\n') catch return;
            @memcpy(self.request[len..][0..line.len], line);
            len += line.len;
            if (std.ascii.startsWithIgnoreCase(line, "content-length:"))
                content_length = std.fmt.parseInt(usize, std.mem.trim(u8, line["content-length:".len..], " \r\n"), 10) catch 0;
            if (std.mem.eql(u8, line, "\r\n")) break;
        }
        const body = reader.interface.take(content_length) catch return;
        @memcpy(self.request[len..][0..body.len], body);
        self.request_len = len + body.len;
        var wbuf: [1024]u8 = undefined;
        var writer = stream.writer(testing.io, &wbuf);
        writer.interface.writeAll(self.response) catch return;
        writer.interface.flush() catch return;
    }
};

fn fakeExchange(response: []const u8, insecure_allowed: bool) !struct { result: Client.PostError!Response, request: []const u8, arena: std.heap.ArenaAllocator } {
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var fake: FakeServer = .{ .server = try addr.listen(testing.io, .{ .reuse_address = true }), .response = response };
    defer fake.server.deinit(testing.io);
    const port = fake.server.socket.address.getPort();
    const thread = try std.Thread.spawn(.{}, FakeServer.serveOne, .{&fake});

    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    const a = arena_state.allocator();
    var client = try Client.init(testing.allocator, testing.io, @import("../config.zig").default_ca_file);
    defer client.deinit();
    client.allow_insecure_loopback = insecure_allowed;
    const url = try a.print("http://127.0.0.1:{d}/token", .{port});
    const result = client.refresh(a, .{ .auth_url = "", .token_url = url, .scope = "imap" }, "cid", "secret", "RT1");
    if (!insecure_allowed) {
        // No request will be made; unblock the server thread.
        const s = try std.Io.net.IpAddress.connect(&try std.Io.net.IpAddress.parse("127.0.0.1", port), testing.io, .{ .mode = .stream });
        s.close(testing.io);
    }
    thread.join();
    return .{ .result = result, .request = try a.dupe(u8, fake.request[0..fake.request_len]), .arena = arena_state };
}

test "fake endpoint: refresh succeeds and sends the right form" {
    var r = try fakeExchange("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 44\r\nConnection: close\r\n\r\n{\"access_token\":\"AT-NEW\",\"expires_in\":3600}", true);
    defer r.arena.deinit();
    const resp = try r.result;
    try testing.expectEqualStrings("AT-NEW", resp.ok.access_token);
    try testing.expect(std.mem.startsWith(u8, r.request, "POST /token HTTP/1.1"));
    try testing.expect(std.mem.find(u8, r.request, "grant_type=refresh_token&refresh_token=RT1&client_id=cid&scope=imap&client_secret=secret") != null);
    try testing.expect(std.ascii.findIgnoreCase(r.request, "content-type: application/x-www-form-urlencoded") != null);
}

test "fake endpoint: invalid_grant and HTTP 500" {
    var r1 = try fakeExchange("HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"error\":\"invalid_grant\"}", true);
    defer r1.arena.deinit();
    try testing.expectEqualStrings("invalid_grant", (try r1.result).failed.code);
    var r2 = try fakeExchange("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}", true);
    defer r2.arena.deinit();
    try testing.expectEqualStrings("http_error", (try r2.result).failed.code);
}

test "plain http is refused without the test seam" {
    var r = try fakeExchange("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", false);
    defer r.arena.deinit();
    try testing.expectError(error.InsecureTokenUrl, r.result);
}

test "client loads the CA bundle used for IMAP" {
    var http = try newHttpClient(testing.allocator, testing.io, @import("../config.zig").default_ca_file);
    defer http.deinit();
    try testing.expect(http.ca_bundle.map.count() > 50);
    try testing.expect(http.now != null); // never rescans the system store
}

test "review: expires_in is clamped to a sane range" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqual(86400, (try parseResponse(a, 200, "{\"access_token\":\"AT\",\"expires_in\":9223372036854775807}")).ok.expires_in);
    try testing.expectEqual(60, (try parseResponse(a, 200, "{\"access_token\":\"AT\",\"expires_in\":-5}")).ok.expires_in);
}

test "review: every request gets a fresh TLS clock" {
    const before = std.Io.Timestamp.now(testing.io, .real).toSeconds();
    var http = try newHttpClient(testing.allocator, testing.io, @import("../config.zig").default_ca_file);
    defer http.deinit();
    try testing.expect(http.now.?.toSeconds() >= before);
}

/// Accepts one connection and never answers until `hang_ms` passes.
fn hangOnce(server: *std.Io.net.Server, hang_ms: u64) void {
    const stream = server.accept(testing.io) catch return;
    testing.io.sleep(.fromMilliseconds(@intCast(hang_ms)), .awake) catch {};
    stream.close(testing.io);
}

test "review: a stalled token endpoint times out instead of blocking the server" {
    var addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = try addr.listen(testing.io, .{ .reuse_address = true });
    defer server.deinit(testing.io);
    const port = server.socket.address.getPort();
    const t = try std.Thread.spawn(.{}, hangOnce, .{ &server, 700 });
    defer t.join();

    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var client = try Client.init(testing.allocator, testing.io, @import("../config.zig").default_ca_file);
    defer client.deinit();
    client.allow_insecure_loopback = true;
    client.timeout_ms = 200;
    const url = try a.print("http://127.0.0.1:{d}/token", .{port});
    const start: std.Io.Timestamp = .now(testing.io, .awake);
    try testing.expectError(error.TokenRequestTimeout, client.refresh(a, .{ .auth_url = "", .token_url = url, .scope = "s" }, "c", null, "r"));
    try testing.expect(start.untilNow(testing.io, .awake).toMilliseconds() < 650);
    // Let the abandoned worker finish (the server closes at 700 ms) so its
    // allocations are released before the leak check.
    testing.io.sleep(.fromMilliseconds(900), .awake) catch {};
}

test "a token response over 64 KiB is refused instead of read without bound" {
    const big_len = max_body_bytes + 1;
    const head = try testing.allocator.dupe(u8, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ");
    defer testing.allocator.free(head);
    var resp: std.ArrayList(u8) = .empty;
    defer resp.deinit(testing.allocator);
    try resp.print(testing.allocator, "{s}{d}\r\nConnection: close\r\n\r\n", .{ head, big_len });
    try resp.appendSlice(testing.allocator, "{\"access_token\":\"AT\",\"pad\":\"");
    try resp.appendNTimes(testing.allocator, 'x', big_len - "{\"access_token\":\"AT\",\"pad\":\"\"}".len);
    try resp.appendSlice(testing.allocator, "\"}");
    var r = try fakeExchange(resp.items, true);
    defer r.arena.deinit();
    try testing.expectError(error.TokenRequestFailed, r.result);

    // Exactly at the limit is still fine.
    var ok_resp: std.ArrayList(u8) = .empty;
    defer ok_resp.deinit(testing.allocator);
    try ok_resp.print(testing.allocator, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{max_body_bytes});
    try ok_resp.appendSlice(testing.allocator, "{\"access_token\":\"AT\",\"pad\":\"");
    try ok_resp.appendNTimes(testing.allocator, 'x', max_body_bytes - "{\"access_token\":\"AT\",\"pad\":\"\"}".len);
    try ok_resp.appendSlice(testing.allocator, "\"}");
    var r2 = try fakeExchange(ok_resp.items, true);
    defer r2.arena.deinit();
    try testing.expectEqualStrings("AT", (try r2.result).ok.access_token);
}
