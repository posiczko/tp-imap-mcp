//! Account registry: lazily connected sessions, health check, one
//! reconnect-and-retry, per-account cache, mailbox list, drafts discovery
//! (spec §5; ADRs 0006, 0013).

const std = @import("std");
const wipe = @import("oauth/wipe.zig");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const config = @import("config.zig");
const imap = @import("imap/session.zig");
const mutf7 = @import("imap/mutf7.zig");
const Store = @import("cache/store.zig").Store;
const Filter = @import("filter/rules.zig").Filter;
const token = @import("oauth/token.zig");
const provider = @import("oauth/provider.zig");
const text = @import("text.zig");
const unicode = @import("sanitize/unicode.zig");
const audit = @import("audit.zig");

pub const Session = imap.Session;
pub const Error = imap.Error || error{LoginFailed};

pub const timeout_sec: c_long = 60;

const log = std.log.scoped(.accounts);

pub const Registry = struct {
    gpa: Allocator,
    io: std.Io,
    /// HTTPS client for OAuth token requests, created on first use.
    token_client: ?token.Client = null,
    /// Test seam: let the token client use plain http to 127.0.0.1.
    allow_insecure_token_loopback: bool = false,
    accounts: []config.Account,
    settings: config.Settings,
    slots: []Slot,
    /// Active sensitive-content filters per account (ADR 0017), one entry per
    /// account. Required at init so filtering can never be silently off.
    active_filters: []const []const *const Filter,
    /// Test seam: every account is served by this in-memory IMAP server
    /// instead of a network connection (tests only; src/imap/fake.zig).
    fake: if (builtin.is_test) ?*imap.Fake else void = if (builtin.is_test) null else {},
    /// Audit log of tool calls (ADR 0023); null when disabled.
    audit: ?*audit.Log = null,
    /// Human-readable cause of the most recent failure (no secrets).
    diag_buf: [512]u8 = undefined,
    diag_len: usize = 0,

    const CacheState = union(enum) { unopened, open: Store, disabled };

    const Slot = struct {
        session: ?Session = null,
        drafts: ?[:0]u8 = null, // wire-encoded, owned by gpa
        cache_path: ?[:0]u8 = null, // owned by gpa; set when the cache is opened
        access: ?token.AccessToken = null, // OAuth access token; value owned by gpa, NUL-terminated
        cache: CacheState = .unopened,
    };

    pub fn init(
        gpa: Allocator,
        io: std.Io,
        accounts: []config.Account,
        settings: config.Settings,
        active_filters: []const []const *const Filter,
    ) (Allocator.Error || error{FilterCountMismatch})!Registry {
        if (active_filters.len != accounts.len) return error.FilterCountMismatch;
        const slots = try gpa.alloc(Slot, accounts.len);
        @memset(slots, .{});
        return .{ .gpa = gpa, .io = io, .accounts = accounts, .settings = settings, .slots = slots, .active_filters = active_filters };
    }

    pub fn deinit(self: *Registry) void {
        for (self.slots, self.accounts) |*slot, *account| {
            if (slot.session) |*s| s.close();
            if (slot.drafts) |d| self.gpa.free(d);
            if (slot.cache_path) |cp| self.gpa.free(cp);
            self.forgetAccessToken(slot);
            switch (slot.cache) {
                .open => |*store| store.close(),
                else => {},
            }
            account.wipe();
        }
        self.gpa.free(self.slots);
        if (self.token_client) |*tc| tc.deinit();
        self.* = undefined;
    }

    fn forgetAccessToken(self: *Registry, slot: *Slot) void {
        if (slot.access) |t| {
            std.crypto.secureZero(u8, t.value);
            self.gpa.free(t.value);
        }
        slot.access = null;
    }

    /// The account's OAuth access token, refreshed when absent, near expiry,
    /// or `force`d (after the server rejected it). Kept only in memory.
    pub fn accessToken(self: *Registry, idx: usize, force: bool) Error![:0]const u8 {
        const slot = &self.slots[idx];
        const a = &self.accounts[idx];
        const o = a.auth.oauth2;
        const now = std.Io.Timestamp.now(self.io, .real).toSeconds();
        if (!force and !token.needsRefresh(slot.access, now)) return slot.access.?.value[0 .. slot.access.?.value.len - 1 :0];
        self.forgetAccessToken(slot);

        const rt = o.refresh_token orelse {
            self.setDiag("account \"{s}\": no OAuth refresh token; run `tp_imap_mcp auth {s}` and store the token as the account's IMAP_<NAME>_OAUTH_REFRESH_TOKEN", .{ a.name, a.name });
            return error.LoginFailed;
        };
        if (self.token_client == null) {
            self.token_client = token.Client.init(self.gpa, self.io, self.settings.ca_file) catch {
                self.setDiag("account \"{s}\": cannot load the CA bundle {s} for OAuth", .{ a.name, self.settings.ca_file });
                return error.LoginFailed;
            };
        }
        self.token_client.?.allow_insecure_loopback = self.allow_insecure_token_loopback;
        // Holds the request form and the response (tokens): wiped when freed.
        var wiping: wipe.Wiping = .{ .parent = self.gpa };
        var arena_state: std.heap.ArenaAllocator = .init(wiping.allocator());
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const ep = try provider.endpoints(arena, o.provider, o.tenant, o.custom);
        const resp = self.token_client.?.refresh(arena, ep, o.client_id, o.client_secret, rt) catch |err| {
            self.setDiag("account \"{s}\": OAuth token request failed ({t})", .{ a.name, err });
            return error.LoginFailed;
        };
        switch (resp) {
            .ok => |ok| {
                // A rotated refresh token in the response is ignored (ADR 0020).
                const value = try self.gpa.dupeSentinel(u8, ok.access_token, 0);
                slot.access = .{ .value = value[0 .. value.len + 1], .expires_at = now + ok.expires_in };
                return value;
            },
            .failed => |f| {
                if (std.mem.eql(u8, f.code, "invalid_grant")) {
                    self.setDiag("account \"{s}\": the OAuth refresh token was rejected (expired or revoked); run `tp_imap_mcp auth {s}` and store the new token", .{ a.name, a.name });
                } else {
                    self.setDiag("account \"{s}\": OAuth token request failed: {s}{s}{s}", .{ a.name, f.code, if (f.description.len > 0) ": " else "", f.description });
                }
                return error.LoginFailed;
            },
        }
    }

    pub fn find(self: *Registry, name: []const u8) ?usize {
        for (self.accounts, 0..) |a, i| if (std.ascii.eqlIgnoreCase(a.name, name)) return i;
        return null;
    }

    pub fn filtersFor(self: *const Registry, idx: usize) []const *const Filter {
        return self.active_filters[idx];
    }

    pub fn diag(self: *const Registry) []const u8 {
        return self.diag_buf[0..self.diag_len];
    }

    fn setDiag(self: *Registry, comptime fmt: []const u8, args: anytype) void {
        var w: std.Io.Writer = .fixed(&self.diag_buf);
        w.print(fmt, args) catch {
            // Overflow: cut on a code-point boundary and mark the truncation.
            const ellipsis = "...";
            const kept = text.truncateUtf8(w.buffered(), self.diag_buf.len - ellipsis.len);
            @memcpy(self.diag_buf[kept.len..][0..ellipsis.len], ellipsis);
            self.diag_len = kept.len + ellipsis.len;
            return;
        };
        self.diag_len = w.buffered().len;
    }

    /// Runs `op.run(*Session) Error!void` on a live session for account `idx`.
    /// If the connection drops mid-call, reconnects once and retries.
    pub fn run(self: *Registry, idx: usize, op: anytype) Error!void {
        self.diag_len = 0;
        var attempt: u2 = 0;
        while (true) : (attempt += 1) {
            const s = try self.live(idx);
            if (op.run(s)) |_| {
                return;
            } else |err| switch (err) {
                error.ConnectionLost => {
                    self.drop(idx);
                    const Op = @typeInfo(@TypeOf(op)).pointer.child;
                    if (comptime !retriesAfterConnectionLoss(Op)) {
                        self.setDiag("account \"{s}\": {s}", .{ self.accounts[idx].name, Op.connection_lost_message });
                        // A change may or may not have happened (a folder
                        // created, renamed, deleted): don't trust the list.
                        if (self.cache(idx)) |store| store.markMailboxesStale() catch |e| self.cacheFailed(idx, e);
                        return err;
                    }
                    if (attempt == 0) continue;
                    self.setDiag("account \"{s}\": connection lost twice; giving up", .{self.accounts[idx].name});
                    return err;
                },
                error.ServerRejected => {
                    var buf: [400]u8 = undefined;
                    self.setDiag("IMAP server rejected the command: {s}", .{unicode.cleanInto(&buf, s.lastResponse())});
                    // The mailbox may have been renamed or deleted elsewhere.
                    if (self.cache(idx)) |store| store.markMailboxesStale() catch |e| self.cacheFailed(idx, e);
                    return err;
                },
                error.ProtocolError => {
                    self.drop(idx);
                    self.setDiag("account \"{s}\": unparseable server response", .{self.accounts[idx].name});
                    return err;
                },
                else => return err,
            }
        }
    }

    /// Returns a connected, logged-in session, reconnecting if the cached one
    /// fails NOOP.
    fn live(self: *Registry, idx: usize) Error!*Session {
        const slot = &self.slots[idx];
        if (comptime builtin.is_test) if (self.fake) |f| {
            if (slot.session == null) slot.session = Session.fromFake(f);
            return &slot.session.?;
        };
        if (slot.session) |*s| {
            if (s.noop()) |_| return s else |_| self.drop(idx);
        }
        const a = &self.accounts[idx];
        var s = Session.connect(a.host, a.port, timeout_sec, self.settings.ca_file) catch |err| {
            switch (err) {
                error.TlsFailed => self.setDiag("account \"{s}\": TLS handshake with {s}:{d} failed; the certificate is not trusted by {s}", .{ a.name, a.host, a.port, self.settings.ca_file }),
                error.HostnameMismatch => self.setDiag("account \"{s}\": the TLS certificate of {s}:{d} is not valid for host {s}", .{ a.name, a.host, a.port, a.host }),
                else => self.setDiag("account \"{s}\": cannot connect to {s}:{d}", .{ a.name, a.host, a.port }),
            }
            return err;
        };
        self.authenticate(idx, &s) catch |err| {
            s.abandon();
            return err;
        };
        slot.session = s;
        return &slot.session.?;
    }

    /// Password LOGIN or XOAUTH2 (one token refresh-and-retry on rejection).
    /// Every failure leaves an account diagnostic.
    fn authenticate(self: *Registry, idx: usize, s: *Session) Error!void {
        const a = &self.accounts[idx];
        switch (a.auth) {
            .password => s.login(a.login, a.password) catch |err| return self.loginFailed(idx, s, "login", err),
            .oauth2 => {
                const first = try self.accessToken(idx, false);
                s.oauth2Login(a.login, first) catch |err| {
                    if (err != error.ServerRejected) return self.loginFailed(idx, s, "OAuth login", err);
                    const fresh = try self.accessToken(idx, true);
                    s.oauth2Login(a.login, fresh) catch |err2| {
                        // A token the server refused twice is not reused.
                        if (err2 == error.ServerRejected) self.forgetAccessToken(&self.slots[idx]);
                        return self.loginFailed(idx, s, "OAuth login", err2);
                    };
                };
            },
        }
    }

    /// Sets the diag for a failed `what` ("login", "OAuth login") and maps a
    /// server rejection to LoginFailed.
    fn loginFailed(self: *Registry, idx: usize, s: *Session, what: []const u8, err: Error) Error {
        const name = self.accounts[idx].name;
        var buf: [400]u8 = undefined;
        switch (err) {
            error.ServerRejected => {
                self.setDiag("account \"{s}\": {s} failed: {s}", .{ name, what, unicode.cleanInto(&buf, s.lastResponse()) });
                return error.LoginFailed;
            },
            error.ConnectionLost => self.setDiag("account \"{s}\": connection lost during {s}", .{ name, what }),
            error.ProtocolError => self.setDiag("account \"{s}\": unparseable server response during {s}", .{ name, what }),
            else => self.setDiag("account \"{s}\": {s} failed ({t})", .{ name, what, err }),
        }
        return err;
    }

    fn drop(self: *Registry, idx: usize) void {
        if (self.slots[idx].session) |*s| s.abandon();
        self.slots[idx].session = null;
    }

    // ---- cache ------------------------------------------------------------

    /// The account's cache, opened on first use; null when caching is
    /// disabled or the cache failed. Never fails a tool call.
    pub fn cache(self: *Registry, idx: usize) ?*Store {
        const slot = &self.slots[idx];
        switch (slot.cache) {
            .open => |*store| return store,
            .disabled => return null,
            .unopened => {},
        }
        slot.cache = .disabled;
        const dir = self.settings.cache_dir orelse return null;
        if (slot.cache_path == null) slot.cache_path = cachePath(self.gpa, dir, self.accounts[idx].name) catch return null;
        const store = openCache(self.gpa, dir, slot.cache_path.?) catch |err| {
            log.warn("account \"{s}\": cache unavailable ({t}); continuing without it", .{ self.accounts[idx].name, err });
            return null;
        };
        slot.cache = .{ .open = store };
        return &slot.cache.open;
    }

    /// Logs a cache failure once and stops using that account's cache.
    pub fn cacheFailed(self: *Registry, idx: usize, err: anyerror) void {
        const slot = &self.slots[idx];
        log.warn("account \"{s}\": cache error ({t}); continuing without it", .{ self.accounts[idx].name, err });
        switch (slot.cache) {
            .open => |*store| store.close(),
            else => {},
        }
        slot.cache = .disabled;
        // Corruption found during use: delete the files so the next start
        // rebuilds the cache instead of failing on it every time.
        if (err == error.SqliteCorrupt) if (slot.cache_path) |cp| deleteCacheFiles(cp);
    }

    /// Deletes all cached rows for the account. False if caching is off.
    pub fn clearCache(self: *Registry, idx: usize) bool {
        const store = self.cache(idx) orelse return false;
        store.clear() catch |err| {
            self.cacheFailed(idx, err);
            return false;
        };
        return true;
    }

    /// Every mailbox on the account (`LIST "" "*"`), from the cache when it is
    /// fresh and `refresh` is false. Names are in wire form.
    pub fn mailboxList(self: *Registry, idx: usize, arena: Allocator, refresh: bool) Error![]imap.Mailbox {
        if (!refresh) if (self.cache(idx)) |store| {
            const cached: ?[]imap.Mailbox = blk: {
                const fresh = store.mailboxesFresh(self.settings.mailbox_ttl) catch |e| break :blk self.cacheMiss(idx, e);
                if (!fresh) break :blk null;
                break :blk store.loadMailboxes(arena) catch |e| self.cacheMiss(idx, e);
            };
            if (cached) |boxes| return boxes;
        };
        var op: ListAll = .{ .arena = arena };
        try self.run(idx, &op);
        if (self.cache(idx)) |store| store.replaceMailboxes(arena, op.result) catch |e| self.cacheFailed(idx, e);
        return op.result;
    }

    /// The cached mailbox list if it is fresh; never contacts the server.
    pub fn freshMailboxes(self: *Registry, idx: usize, arena: Allocator) ?[]imap.Mailbox {
        const store = self.cache(idx) orelse return null;
        const fresh = store.mailboxesFresh(self.settings.mailbox_ttl) catch |e| return self.cacheMiss(idx, e);
        if (!fresh) return null;
        return store.loadMailboxes(arena) catch |e| self.cacheMiss(idx, e);
    }

    /// After CREATE/RENAME/DELETE (ADR 0021): refreshes the mailbox list,
    /// which also drops cached headers of mailboxes that no longer exist. If
    /// the refresh fails the list is marked stale instead; never fails.
    pub fn mailboxesChanged(self: *Registry, idx: usize, arena: Allocator) void {
        defer self.diag_len = 0; // the tool already succeeded
        _ = self.mailboxList(idx, arena, true) catch {
            if (self.cache(idx)) |store| store.markMailboxesStale() catch |e| self.cacheFailed(idx, e);
        };
    }

    /// Drops cached headers of messages moved out of `mailbox`.
    pub fn forgetMoved(self: *Registry, idx: usize, mailbox: []const u8, uidvalidity: u32, uids: []const u32) void {
        const store = self.cache(idx) orelse return;
        store.deleteMessages(mailbox, uidvalidity, uids) catch |e| self.cacheFailed(idx, e);
    }

    fn cacheMiss(self: *Registry, idx: usize, err: anyerror) ?[]imap.Mailbox {
        self.cacheFailed(idx, err);
        return null;
    }

    /// Wire-encoded drafts mailbox: IMAP_<NAME>_DRAFTS, else the \Drafts
    /// special-use mailbox, else "Drafts". Cached per process.
    pub fn drafts(self: *Registry, idx: usize, arena: Allocator) Error![:0]const u8 {
        const slot = &self.slots[idx];
        if (slot.drafts) |d| return d;
        const name: []const u8 = if (self.accounts[idx].drafts) |utf8|
            mutf7.encode(arena, utf8) catch |err| switch (err) {
                error.InvalidUtf8 => utf8,
                error.OutOfMemory => return error.OutOfMemory,
            }
        else blk: {
            for (try self.mailboxList(idx, arena, false)) |b| for (b.flags) |f| {
                if (std.ascii.eqlIgnoreCase(f, "\\Drafts")) break :blk b.name;
            };
            break :blk "Drafts";
        };
        slot.drafts = try self.gpa.dupeSentinel(u8, name, 0);
        return slot.drafts.?;
    }
};

/// Operations are retried once after a dropped connection unless they declare
/// `pub const retry_after_connection_loss = false;` (non-idempotent commands
/// such as APPEND), together with a `connection_lost_message`.
pub fn retriesAfterConnectionLoss(comptime Op: type) bool {
    return !@hasDecl(Op, "retry_after_connection_loss") or Op.retry_after_connection_loss;
}

const ListAll = struct {
    arena: Allocator,
    result: []imap.Mailbox = &.{},

    pub fn run(self: *ListAll, s: *Session) Error!void {
        self.result = try s.list(self.arena, "", "*");
    }
};

/// Creates `dir` (mode 0700) and opens `<dir>/<account>.sqlite3` with a
/// 0077 umask so the database and its WAL files are private. A corrupt file is
/// deleted and recreated once.
fn cachePath(gpa: Allocator, dir: []const u8, account: []const u8) ![:0]u8 {
    const lower = try std.ascii.allocLowerString(gpa, account);
    defer gpa.free(lower);
    return gpa.printSentinel("{s}/{s}.sqlite3", .{ dir, lower }, 0);
}

/// Removes the database and its WAL companions (best effort).
fn deleteCacheFiles(path: [:0]const u8) void {
    _ = std.c.unlink(path);
    var buf: [std.fs.max_path_bytes + 8]u8 = undefined;
    for ([_][]const u8{ "-wal", "-shm" }) |suffix| {
        const p = std.mem.printSentinel(&buf, "{s}{s}", .{ path, suffix }, 0) catch continue;
        _ = std.c.unlink(p);
    }
}

fn openCache(gpa: Allocator, dir: []const u8, path: [:0]const u8) !Store {
    try makePath(gpa, dir);
    const old_mask = std.c.umask(0o077);
    defer _ = std.c.umask(old_mask);
    return Store.open(path) catch |err| switch (err) {
        error.SqliteCorrupt => {
            log.warn("cache file {s} is corrupt; rebuilding", .{path});
            deleteCacheFiles(path);
            return Store.open(path);
        },
        else => return err,
    };
}

/// mkdir -p with mode 0700 for any component it creates.
pub fn makePath(gpa: Allocator, dir: []const u8) !void {
    const z = try gpa.dupeSentinel(u8, dir, 0);
    defer gpa.free(z);
    var i: usize = 1;
    while (i <= z.len) : (i += 1) {
        if (i < z.len and z[i] != '/') continue;
        const saved = z[i];
        z[i] = 0;
        defer z[i] = saved;
        if (std.c.mkdir(z[0..i :0], 0o700) != 0) {
            switch (std.c.errno(-1)) {
                .EXIST => {},
                else => |e| {
                    log.warn("cannot create {s}: {t}", .{ z[0..i], e });
                    return error.CacheDirUnavailable;
                },
            }
        }
    }
}

const testing = std.testing;

const Noop = struct {
    pub fn run(_: *Noop, _: *Session) Error!void {}
};

const no_cache: config.Settings = .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file };
const no_filters_1 = [_][]const *const Filter{&.{}};

fn localAccount(password: [:0]u8, drafts_name: ?[]const u8) config.Account {
    return .{
        .name = "local",
        .host = "127.0.0.1",
        .port = 1, // nothing listens here
        .login = "me",
        .password = password,
        .readonly = false,
        .drafts = drafts_name,
    };
}

test "unreachable server reports a connect diagnostic without the password" {
    const pw = try testing.allocator.dupeSentinel(u8, "s3cret", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();

    try testing.expectEqual(0, reg.find("LOCAL").?);
    try testing.expect(reg.find("other") == null);

    var op: Noop = .{};
    try testing.expectError(error.ConnectFailed, reg.run(0, &op));
    try testing.expectEqualStrings("account \"local\": cannot connect to 127.0.0.1:1", reg.diag());
    try testing.expect(std.mem.find(u8, reg.diag(), "s3cret") == null);
}

test "configured drafts override is encoded without contacting the server" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, "Entwürfe")};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqualStrings("Entw&APw-rfe", try reg.drafts(0, arena_state.allocator()));
}

test "fresh cached mailbox list is served without the server; clearCache empties it" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}/nested/cache", .{&tmp.sub_path});
    defer testing.allocator.free(dir);

    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    // Seed the cache as if a LIST had happened.
    const store = reg.cache(0).?;
    try store.replaceMailboxes(a, &.{.{ .name = "Brouillons", .delimiter = '/', .flags = &.{"\\Drafts"} }});

    // Served from cache: the server (127.0.0.1:1) is never contacted.
    const boxes = try reg.mailboxList(0, a, false);
    try testing.expectEqualStrings("Brouillons", boxes[0].name);
    try testing.expectEqualStrings("Brouillons", try reg.drafts(0, a));

    // refresh forces the server, which is unreachable here.
    try testing.expectError(error.ConnectFailed, reg.mailboxList(0, a, true));

    try testing.expect(reg.clearCache(0));
    try testing.expectError(error.ConnectFailed, reg.mailboxList(0, a, false));
}

test "mailboxesChanged marks the list stale when the refresh fails; forgetMoved drops moved rows" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}/cache", .{&tmp.sub_path});
    defer testing.allocator.free(dir);

    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    const store = reg.cache(0).?;
    try store.replaceMailboxes(a, &.{.{ .name = "INBOX", .delimiter = '/', .flags = &.{} }});
    try store.putMessages("INBOX", 9, &.{
        .{ .uid = 1, .size = 10, .data = "A: 1\r\n\r\n", .flags = null },
        .{ .uid = 2, .size = 20, .data = "A: 2\r\n\r\n", .flags = null },
    });

    reg.forgetMoved(0, "INBOX", 9, &.{1});
    const left = try store.getMessages(a, "INBOX", 9, &.{ 1, 2 });
    try testing.expectEqual(1, left.len);
    try testing.expectEqual(2, left[0].uid);

    try testing.expect(try store.mailboxesFresh(3600));
    reg.mailboxesChanged(0, a); // 127.0.0.1:1 is unreachable: falls back to stale
    try testing.expect(!try store.mailboxesFresh(3600));
    try testing.expectEqualStrings("", reg.diag());
}

test "corrupt cache file is rebuilt" {
    // The rebuild logs a warning by design; keep test output clean.
    testing.log_level = .err;
    defer testing.log_level = .warn;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "local.sqlite3", .data = "not a database, just some text" });
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    defer testing.allocator.free(dir);

    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    try testing.expect(reg.cache(0) != null);
}

test "caching disabled: no store, clearCache reports false" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    try testing.expect(reg.cache(0) == null);
    try testing.expect(!reg.clearCache(0));
}

test "todo: active filters are required and must match the account count" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    try testing.expectError(error.FilterCountMismatch, Registry.init(testing.allocator, testing.io, &accounts, no_cache, &.{}));
}

test "todo: a cache found corrupt during use is deleted (with -wal/-shm) for rebuild" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    defer testing.allocator.free(dir);
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    try testing.expect(reg.cache(0) != null);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "local.sqlite3-wal", .data = "x" });
    testing.log_level = .err;
    defer testing.log_level = .warn;
    reg.cacheFailed(0, error.SqliteCorrupt);
    for ([_][]const u8{ "local.sqlite3", "local.sqlite3-wal", "local.sqlite3-shm" }) |name| {
        try testing.expectError(error.FileNotFound, tmp.dir.access(testing.io, name, .{}));
    }
}


fn oauthAccount(token_url: []const u8, refresh_token: [:0]u8) config.Account {
    return .{
        .name = "ms",
        .host = "127.0.0.1",
        .port = 1,
        .login = "me@contoso.com",
        .password = @constCast(&[_:0]u8{}),
        .readonly = false,
        .drafts = null,
        .auth = .{ .oauth2 = .{
            .provider = .custom,
            .client_id = "cid",
            .client_secret = null,
            .refresh_token = refresh_token,
            .tenant = "common",
            .custom = .{ .auth_url = "https://unused", .token_url = token_url, .scope = "imap" },
        } },
    };
}

test "oauth: access token is fetched once and cached until near expiry" {
    const fake = try token.FakeServer.start("HTTP/1.1 200 OK\r\nContent-Length: 44\r\nConnection: close\r\n\r\n{\"access_token\":\"AT-ONE\",\"expires_in\":3600}");
    defer fake.destroy();
    const thread = try std.Thread.spawn(.{}, token.FakeServer.serveOne, .{fake});
    const url = try testing.allocator.print("http://127.0.0.1:{d}/token", .{fake.port()});
    defer testing.allocator.free(url);
    var rt = [_:0]u8{ 'R', 'T' }; // writable: Registry.deinit wipes it
    var accounts = [_]config.Account{oauthAccount(url, &rt)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    reg.allow_insecure_token_loopback = true;

    try testing.expectEqualStrings("AT-ONE", try reg.accessToken(0, false));
    thread.join();
    // Served from memory: the fake server is gone, so a request would fail.
    try testing.expectEqualStrings("AT-ONE", try reg.accessToken(0, false));
}

test "oauth: invalid_grant tells the user to re-run auth, without the token" {
    const fake = try token.FakeServer.start("HTTP/1.1 400 Bad Request\r\nContent-Length: 25\r\nConnection: close\r\n\r\n{\"error\":\"invalid_grant\"}");
    defer fake.destroy();
    const thread = try std.Thread.spawn(.{}, token.FakeServer.serveOne, .{fake});
    const url = try testing.allocator.print("http://127.0.0.1:{d}/token", .{fake.port()});
    defer testing.allocator.free(url);
    var rt = [_:0]u8{ 'R', 'T' }; // writable: Registry.deinit wipes it
    var accounts = [_]config.Account{oauthAccount(url, &rt)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    reg.allow_insecure_token_loopback = true;

    try testing.expectError(error.LoginFailed, reg.accessToken(0, false));
    thread.join();
    try testing.expect(std.mem.find(u8, reg.diag(), "tp_imap_mcp auth ms") != null);
    try testing.expect(std.mem.find(u8, reg.diag(), "RT") == null);
}

/// Puts `value` in the account's token slot as a valid, unexpired token.
fn seedAccessToken(reg: *Registry, idx: usize, value: []const u8) !void {
    const v = try reg.gpa.dupeSentinel(u8, value, 0);
    reg.slots[idx].access = .{ .value = v[0 .. v.len + 1], .expires_at = std.math.maxInt(i64) };
}

const token_ok = "HTTP/1.1 200 OK\r\nContent-Length: 44\r\nConnection: close\r\n\r\n{\"access_token\":\"AT-ONE\",\"expires_in\":3600}";

test "oauth login: a rejected cached token is refreshed once and the login retried" {
    const server = try token.FakeServer.start(token_ok);
    defer server.destroy();
    const thread = try std.Thread.spawn(.{}, token.FakeServer.serveOne, .{server});
    const url = try testing.allocator.print("http://127.0.0.1:{d}/token", .{server.port()});
    defer testing.allocator.free(url);
    var rt = [_:0]u8{ 'R', 'T' };
    var accounts = [_]config.Account{oauthAccount(url, &rt)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    reg.allow_insecure_token_loopback = true;
    try seedAccessToken(&reg, 0, "STALE");

    var fake: imap.Fake = .init(testing.allocator);
    defer fake.deinit();
    fake.accepted_token = "AT-ONE";
    var s = Session.fromFake(&fake);
    try reg.authenticate(0, &s);
    thread.join();

    try testing.expectEqual(2, fake.commands.items.len);
    try testing.expectEqualStrings("AUTHENTICATE XOAUTH2 me@contoso.com STALE", fake.commands.items[0]);
    try testing.expectEqualStrings("AUTHENTICATE XOAUTH2 me@contoso.com AT-ONE", fake.commands.items[1]);
    // The fresh token is kept for the next connection.
    try testing.expectEqualStrings("AT-ONE", try reg.accessToken(0, false));
}

test "oauth login: a token rejected after the refresh is forgotten, and the diag names the account" {
    const server = try token.FakeServer.start(token_ok);
    defer server.destroy();
    const thread = try std.Thread.spawn(.{}, token.FakeServer.serveOne, .{server});
    const url = try testing.allocator.print("http://127.0.0.1:{d}/token", .{server.port()});
    defer testing.allocator.free(url);
    var rt = [_:0]u8{ 'R', 'T' };
    var accounts = [_]config.Account{oauthAccount(url, &rt)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    reg.allow_insecure_token_loopback = true;
    try seedAccessToken(&reg, 0, "STALE");

    var fake: imap.Fake = .init(testing.allocator);
    defer fake.deinit();
    fake.accepted_token = "SOMETHING-ELSE";
    var s = Session.fromFake(&fake);
    try testing.expectError(error.LoginFailed, reg.authenticate(0, &s));
    thread.join();

    try testing.expect(reg.slots[0].access == null);
    try testing.expect(std.mem.find(u8, reg.diag(), "account \"ms\": OAuth login failed") != null);
    try testing.expect(std.mem.find(u8, reg.diag(), "Invalid credentials") != null);
    try testing.expect(std.mem.find(u8, reg.diag(), "AT-ONE") == null);
}

test "oauth login: a connection lost on the first attempt keeps the token and says so" {
    var rt = [_:0]u8{ 'R', 'T' };
    var accounts = [_]config.Account{oauthAccount("http://127.0.0.1:1/unused", &rt)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();
    try seedAccessToken(&reg, 0, "GOOD");

    var fake: imap.Fake = .init(testing.allocator);
    defer fake.deinit();
    fake.fail = .{ .command = "AUTHENTICATE", .err = error.ConnectionLost, .response = "" };
    var s = Session.fromFake(&fake);
    try testing.expectError(error.ConnectionLost, reg.authenticate(0, &s));

    // Not the token's fault: no refresh, token kept.
    try testing.expectEqual(1, fake.commands.items.len);
    try testing.expect(reg.slots[0].access != null);
    try testing.expectEqualStrings("account \"ms\": connection lost during OAuth login", reg.diag());
}

test "password login: a lost connection gets its own diag, not the last server line" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, no_cache, &no_filters_1);
    defer reg.deinit();

    var fake: imap.Fake = .init(testing.allocator);
    defer fake.deinit();
    fake.fail = .{ .command = "LOGIN", .err = error.ConnectionLost, .response = "" };
    var s = Session.fromFake(&fake);
    try testing.expectError(error.ConnectionLost, reg.authenticate(0, &s));
    try testing.expect(std.mem.endsWith(u8, reg.diag(), "connection lost during login"));
}

test "forgetMoved drops only rows of the given UIDVALIDITY; a stale generation is left for syncUidvalidity" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const dir = try testing.allocator.print(".zig-cache/tmp/{s}", .{&tmp.sub_path});
    defer testing.allocator.free(dir);
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, testing.io, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &no_filters_1);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const store = reg.cache(0).?;
    const rows = [_]imap.Fetched{
        .{ .uid = 1, .size = 10, .data = "h1", .flags = null },
        .{ .uid = 2, .size = 10, .data = "h2", .flags = null },
        .{ .uid = 3, .size = 10, .data = "h3", .flags = null },
    };
    try store.putMessages("INBOX", 7, &rows);

    // The server reports another UIDVALIDITY (the folder was recreated):
    // nothing of generation 7 matches, so nothing is deleted.
    reg.forgetMoved(0, "INBOX", 8, &.{ 1, 2 });
    try testing.expectEqual(3, (try store.getMessages(a, "INBOX", 7, &.{ 1, 2, 3 })).len);
    // Another mailbox with the same UIDs is untouched too.
    reg.forgetMoved(0, "Archive", 7, &.{1});
    try testing.expectEqual(3, (try store.getMessages(a, "INBOX", 7, &.{ 1, 2, 3 })).len);

    // The matching generation loses exactly the moved UIDs.
    reg.forgetMoved(0, "INBOX", 7, &.{ 1, 3 });
    const left = try store.getMessages(a, "INBOX", 7, &.{ 1, 2, 3 });
    try testing.expectEqual(1, left.len);
    try testing.expectEqual(2, left[0].uid);

    // Reading under the new UIDVALIDITY drops the stale generation.
    try store.syncUidvalidity("INBOX", 8);
    try testing.expectEqual(0, (try store.getMessages(a, "INBOX", 7, &.{2})).len);
    try testing.expect(reg.slots[0].cache == .open); // no cache error along the way
}
