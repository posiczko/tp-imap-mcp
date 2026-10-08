//! Zig wrapper over the tpi C shim. No C types escape this file: results are
//! copied into caller-provided arena memory and the C buffers freed at once.

const std = @import("std");
const Allocator = std.mem.Allocator;
const c = @import("c.zig");

pub const Error = error{
    /// TCP/TLS connection could not be established.
    ConnectFailed,
    /// Connection dropped mid-command; the session is unusable.
    ConnectionLost,
    /// Server answered NO/BAD; see `Session.lastResponse`.
    ServerRejected,
    /// Server sent something libetpan could not parse.
    ProtocolError,
    /// TLS handshake failed: certificate chain not trusted by the CA bundle.
    TlsFailed,
    /// The server certificate is not valid for the host we connected to.
    HostnameMismatch,
} || Allocator.Error;

fn check(rc: c_int) Error!void {
    return switch (rc) {
        c.OK => {},
        c.ERR_CONNECT => error.ConnectFailed,
        c.ERR_STREAM => error.ConnectionLost,
        c.ERR_SERVER => error.ServerRejected,
        c.ERR_PARSE => error.ProtocolError,
        c.ERR_MEMORY => error.OutOfMemory,
        c.ERR_TLS => error.TlsFailed,
        else => error.ProtocolError,
    };
}

pub const Mailbox = struct {
    name: []const u8, // raw modified UTF-7
    delimiter: ?u8,
    flags: []const []const u8,
};

pub const Status = c.Status;

pub const What = packed struct {
    header: bool = false,
    body: bool = false,
    size: bool = false,
    flags: bool = false,

    fn bits(w: What) c_int {
        var b: c_int = 0;
        if (w.header) b |= c.FETCH_HEADER;
        if (w.body) b |= c.FETCH_BODY;
        if (w.size) b |= c.FETCH_SIZE;
        if (w.flags) b |= c.FETCH_FLAGS;
        return b;
    }
};

pub const BodyPart = struct {
    uid: u32,
    size: u32,
    base64: bool,
    content_type: []const u8,
    disposition: []const u8,
    params: []const u8,
    disp_params: []const u8,
};

pub const Fetched = struct {
    uid: u32,
    size: u32,
    data: ?[]const u8,
    flags: ?[]const []const u8,
};

/// Server extensions the organization tools depend on (ADR 0021).
pub const Caps = struct {
    move: bool = false,
    uidplus: bool = false,
};

/// COPYUID response code: UID ranges as (first, last); a last of 0 is "*".
pub const CopyUid = struct {
    uidvalidity: u32,
    src: []const [2]u32,
    dst: []const [2]u32,
};

pub const Session = struct {
    handle: *c.Session,

    /// Implicit-TLS connect: chain verified against `ca_file`, SNI set, and
    /// the certificate's host name checked before any credential is sent.
    pub fn connect(host: [:0]const u8, port: u16, timeout_sec: c_long, ca_file: [:0]const u8) Error!Session {
        const h = c.tpi_new() orelse return error.OutOfMemory;
        errdefer c.tpi_free(h);
        try check(c.tpi_connect(h, host, port, timeout_sec, ca_file));
        var der: ?[*]u8 = null;
        const n = c.tpi_peer_certificate(h, &der);
        defer c.tpi_buf_free(der);
        const cert = der orelse return error.HostnameMismatch;
        if (n < 0) return error.HostnameMismatch;
        try checkHostName(cert[0..@intCast(n)], host);
        return .{ .handle = h };
    }

    /// Sends LOGOUT (best effort) and frees the session.
    pub fn close(self: *Session) void {
        _ = c.tpi_logout(self.handle);
        c.tpi_free(self.handle);
        self.* = undefined;
    }

    /// Frees without talking to the server (for dead connections).
    pub fn abandon(self: *Session) void {
        c.tpi_free(self.handle);
        self.* = undefined;
    }

    pub fn lastResponse(self: *Session) []const u8 {
        return std.mem.sliceTo(c.tpi_last_response(self.handle), 0);
    }

    pub fn login(self: *Session, user: [:0]const u8, password: [:0]const u8) Error!void {
        try check(c.tpi_login(self.handle, user, password));
    }

    pub fn oauth2Login(self: *Session, user: [:0]const u8, access_token: [:0]const u8) Error!void {
        try check(c.tpi_oauth2_login(self.handle, user, access_token));
    }

    pub fn noop(self: *Session) Error!void {
        try check(c.tpi_noop(self.handle));
    }

    /// Opens `mailbox` read-only; returns its UIDVALIDITY (0 if unreported).
    pub fn examine(self: *Session, mailbox: [:0]const u8) Error!u32 {
        var uv: u32 = 0;
        try check(c.tpi_examine(self.handle, mailbox, &uv));
        return uv;
    }

    /// Opens `mailbox` read-write; returns its UIDVALIDITY (0 if unreported).
    pub fn select(self: *Session, mailbox: [:0]const u8) Error!u32 {
        var uv: u32 = 0;
        try check(c.tpi_select(self.handle, mailbox, &uv));
        return uv;
    }

    /// `criteria` must already be validated (no CR/LF/NUL).
    pub fn uidSearch(self: *Session, arena: Allocator, criteria: [:0]const u8) Error![]u32 {
        var ptr: ?[*]u32 = null;
        var n: usize = 0;
        try check(c.tpi_uid_search(self.handle, criteria, &ptr, &n));
        defer c.tpi_uids_free(ptr);
        const p = ptr orelse return &.{};
        return arena.dupe(u32, p[0..n]);
    }

    pub fn list(self: *Session, arena: Allocator, reference: [:0]const u8, pattern: [:0]const u8) Error![]Mailbox {
        var ptr: ?[*]c.Mailbox = null;
        var n: usize = 0;
        try check(c.tpi_list(self.handle, reference, pattern, &ptr, &n));
        defer c.tpi_mailboxes_free(ptr, n);
        const items = (ptr orelse return &.{})[0..n];
        const out = try arena.alloc(Mailbox, n);
        for (items, out) |src, *dst| dst.* = .{
            .name = try arena.dupe(u8, std.mem.sliceTo(src.name, 0)),
            .delimiter = if (src.delimiter == 0) null else src.delimiter,
            .flags = try splitFlags(arena, std.mem.sliceTo(src.flags, 0)),
        };
        return out;
    }

    pub fn status(self: *Session, mailbox: [:0]const u8) Error!Status {
        var st: c.Status = undefined;
        try check(c.tpi_status_get(self.handle, mailbox, &st));
        return st;
    }

    /// Results are in server order and only for UIDs that exist.
    pub fn uidFetch(self: *Session, arena: Allocator, uids: []const u32, what: What) Error![]Fetched {
        var ptr: ?[*]c.FetchItem = null;
        var n: usize = 0;
        try check(c.tpi_uid_fetch(self.handle, uids.ptr, uids.len, what.bits(), &ptr, &n));
        defer c.tpi_fetch_free(ptr, n);
        const items = (ptr orelse return &.{})[0..n];
        const out = try arena.alloc(Fetched, n);
        for (items, out) |src, *dst| dst.* = .{
            .uid = src.uid,
            .size = src.size,
            .data = if (src.data) |d| try arena.dupe(u8, d[0..src.data_len]) else null,
            .flags = if (src.flags) |f| try splitFlags(arena, std.mem.sliceTo(f, 0)) else null,
        };
        return out;
    }

    /// `flags` must already be validated.
    pub fn uidStoreFlags(self: *Session, arena: Allocator, uids: []const u32, add: bool, flags: []const []const u8) Error!void {
        const zs = try arena.alloc([*:0]const u8, flags.len);
        for (flags, zs) |f, *z| z.* = try arena.dupeSentinel(u8, f, 0);
        try check(c.tpi_uid_store_flags(self.handle, uids.ptr, uids.len, @intFromBool(add), zs.ptr, zs.len));
    }

    /// Leaf MIME parts per UID from BODYSTRUCTURE (no content downloaded).
    pub fn uidBodyParts(self: *Session, arena: Allocator, uids: []const u32) Error![]BodyPart {
        var ptr: ?[*]c.Part = null;
        var n: usize = 0;
        try check(c.tpi_uid_bodystructure(self.handle, uids.ptr, uids.len, &ptr, &n));
        defer c.tpi_parts_free(ptr, n);
        const items = (ptr orelse return &.{})[0..n];
        const out = try arena.alloc(BodyPart, n);
        for (items, out) |src, *dst| dst.* = .{
            .uid = src.uid,
            .size = src.size,
            .base64 = src.base64 != 0,
            .content_type = try arena.dupe(u8, std.mem.sliceTo(src.content_type, 0)),
            .disposition = try arena.dupe(u8, std.mem.sliceTo(src.disposition, 0)),
            .params = try arena.dupe(u8, std.mem.sliceTo(src.params, 0)),
            .disp_params = try arena.dupe(u8, std.mem.sliceTo(src.disp_params, 0)),
        };
        return out;
    }

    pub fn append(self: *Session, mailbox: [:0]const u8, data: []const u8) Error!void {
        try check(c.tpi_append(self.handle, mailbox, data.ptr, data.len));
    }

    pub fn create(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_create(self.handle, mailbox));
    }

    pub fn rename(self: *Session, from: [:0]const u8, to: [:0]const u8) Error!void {
        try check(c.tpi_rename(self.handle, from, to));
    }

    pub fn delete(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_delete(self.handle, mailbox));
    }

    pub fn subscribe(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_subscribe(self.handle, mailbox));
    }

    pub fn unsubscribe(self: *Session, mailbox: [:0]const u8) Error!void {
        try check(c.tpi_unsubscribe(self.handle, mailbox));
    }

    /// MOVE / UIDPLUS support (one CAPABILITY command per connection).
    pub fn capabilities(self: *Session) Error!Caps {
        var mask: c_int = 0;
        try check(c.tpi_capabilities(self.handle, &mask));
        return .{ .move = mask & c.CAP_MOVE != 0, .uidplus = mask & c.CAP_UIDPLUS != 0 };
    }

    /// UID MOVE (`move`) or UID COPY from the selected mailbox. Returns the
    /// server's COPYUID data, or null if it sent none.
    pub fn uidTransfer(self: *Session, arena: Allocator, uids: []const u32, mailbox: [:0]const u8, move: bool) Error!?CopyUid {
        var out: c.CopyUid = undefined;
        try check(c.tpi_uid_transfer(self.handle, uids.ptr, uids.len, mailbox, @intFromBool(move), &out));
        defer c.tpi_copyuid_free(&out);
        if (out.uidvalidity == 0) return null;
        return .{
            .uidvalidity = out.uidvalidity,
            .src = try pairs(arena, out.src, out.src_len),
            .dst = try pairs(arena, out.dst, out.dst_len),
        };
    }

    /// UID EXPUNGE (UIDPLUS) of exactly these UIDs.
    pub fn uidExpunge(self: *Session, uids: []const u32) Error!void {
        try check(c.tpi_uid_expunge(self.handle, uids.ptr, uids.len));
    }
};

/// Checks that the DER certificate `der` is valid for `host` (SAN DNS/IP
/// entries, else CN), using Zig's X.509 parser.
/// Precondition: `der` is a certificate OpenSSL already verified against the
/// CA bundle (re-encoded by i2d_X509), so it is well-formed; std's parser may
/// panic on arbitrary malformed bytes.
pub fn checkHostName(der: []const u8, host: []const u8) error{HostnameMismatch}!void {
    const cert: std.crypto.Certificate = .{ .buffer = der, .index = 0 };
    const parsed = cert.parse() catch return error.HostnameMismatch;
    parsed.verifyHostName(host) catch return error.HostnameMismatch;
}

fn pairs(arena: Allocator, ptr: ?[*]const u32, len: usize) Allocator.Error![]const [2]u32 {
    const p = ptr orelse return &.{};
    const out = try arena.alloc([2]u32, len / 2);
    for (out, 0..) |*o, i| o.* = .{ p[2 * i], p[2 * i + 1] };
    return out;
}

fn splitFlags(arena: Allocator, s: []const u8) Allocator.Error![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    var it = std.mem.tokenizeScalar(u8, s, ' ');
    while (it.next()) |f| try out.append(arena, try arena.dupe(u8, f));
    return out.toOwnedSlice(arena);
}

pub const Extracted = union(enum) {
    text: struct {
        bytes: []const u8, // not yet UTF-8 sanitized
        parts: usize, // matching parts found (0 = none of that subtype)
    },
    encrypted: []const u8, // protocol parameter
};

/// MIME body extraction (no network). `subtype` is "plain" or "html".
pub fn extractText(arena: Allocator, message: []const u8, subtype: [:0]const u8) Error!Extracted {
    var out: ?[*]u8 = null;
    var out_len: usize = 0;
    var parts: usize = 0;
    var proto: ?[*:0]u8 = null;
    try check(c.tpi_extract_text(message.ptr, message.len, subtype, &out, &out_len, &parts, &proto));
    defer c.tpi_buf_free(out);
    defer c.tpi_buf_free(if (proto) |p| p else null);
    if (proto) |p| return .{ .encrypted = try arena.dupe(u8, std.mem.sliceTo(p, 0)) };
    const o = out orelse return .{ .text = .{ .bytes = "", .parts = parts } };
    return .{ .text = .{ .bytes = try arena.dupe(u8, o[0..out_len]), .parts = parts } };
}

/// RFC 2047-decodes a header value to UTF-8 for matching (ADR 0017). Falls
/// back to the raw value if libetpan cannot parse it. Result is in `arena`.
pub fn decodeHeaderValue(arena: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    var out: ?[*]u8 = null;
    var out_len: usize = 0;
    if (c.tpi_decode_header_value(raw.ptr, raw.len, &out, &out_len) != c.OK) return raw;
    defer c.tpi_buf_free(out);
    const o = out orelse return raw;
    // An encoded NUL truncates libetpan's C string; never turn a non-empty
    // value into an empty one (filters would then see nothing).
    if (out_len == 0 and std.mem.trim(u8, raw, " \t").len > 0) return raw;
    return arena.dupe(u8, o[0..out_len]);
}

const testing = std.testing;

test "splitFlags" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const fs = try splitFlags(arena_state.allocator(), "\\Seen $label1 NonJunk");
    try testing.expectEqual(3, fs.len);
    try testing.expectEqualStrings("$label1", fs[1]);
    try testing.expectEqual(0, (try splitFlags(arena_state.allocator(), "")).len);
}

test "checkHostName accepts the certificate's SAN and rejects other hosts" {
    const der = @embedFile("../testdata/mail.example.org.der");
    try checkHostName(der, "mail.example.org");
    try testing.expectError(error.HostnameMismatch, checkHostName(der, "evil.example.net"));
    try testing.expectError(error.HostnameMismatch, checkHostName(der, "example.org"));
    try testing.expectError(error.HostnameMismatch, checkHostName(der, "127.0.0.1"));
}

test "decodeHeaderValue decodes RFC 2047 B and Q words, leaves plain text alone" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("Password reset", try decodeHeaderValue(a, "=?UTF-8?B?UGFzc3dvcmQgcmVzZXQ=?="));
    try testing.expectEqualStrings("Password reset", try decodeHeaderValue(a, "=?UTF-8?Q?Password_reset?="));
    try testing.expectEqualStrings("R\u{e9}initialiser", try decodeHeaderValue(a, "=?ISO-8859-1?Q?R=E9initialiser?="));
    try testing.expectEqualStrings("Reset your password", try decodeHeaderValue(a, "=?UTF-8?Q?Reset_?= =?UTF-8?Q?your_password?="));
    try testing.expectEqualStrings("Plain subject", try decodeHeaderValue(a, "Plain subject"));
}

test "todo: a decode that comes out empty falls back to the raw value" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const raw = "=?UTF-8?B?AFJlc2V0IHlvdXIgcGFzc3dvcmQ=?=";
    try testing.expectEqualStrings(raw, try decodeHeaderValue(arena_state.allocator(), raw));
}
