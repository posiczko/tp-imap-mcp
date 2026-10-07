//! Account registry: lazily connected sessions, health check, one
//! reconnect-and-retry, per-account cache, mailbox list, drafts discovery
//! (spec §5; ADRs 0006, 0013).

const std = @import("std");
const Allocator = std.mem.Allocator;
const config = @import("config.zig");
const imap = @import("imap/session.zig");
const mutf7 = @import("imap/mutf7.zig");
const Store = @import("cache/store.zig").Store;
const Filter = @import("filter/rules.zig").Filter;
const text = @import("text.zig");
const unicode = @import("sanitize/unicode.zig");

pub const Session = imap.Session;
pub const Error = imap.Error || error{LoginFailed};

pub const timeout_sec: c_long = 60;

const log = std.log.scoped(.accounts);

pub const Registry = struct {
    gpa: Allocator,
    accounts: []config.Account,
    settings: config.Settings,
    slots: []Slot,
    /// Active sensitive-content filters per account (ADR 0017); set by main
    /// after loading filters. Empty means no filtering.
    active_filters: []const []const *const Filter = &.{},
    /// Human-readable cause of the most recent failure (no secrets).
    diag_buf: [512]u8 = undefined,
    diag_len: usize = 0,

    const CacheState = union(enum) { unopened, open: Store, disabled };

    const Slot = struct {
        session: ?Session = null,
        drafts: ?[:0]u8 = null, // wire-encoded, owned by gpa
        cache: CacheState = .unopened,
    };

    pub fn init(gpa: Allocator, accounts: []config.Account, settings: config.Settings) Allocator.Error!Registry {
        const slots = try gpa.alloc(Slot, accounts.len);
        @memset(slots, .{});
        return .{ .gpa = gpa, .accounts = accounts, .settings = settings, .slots = slots };
    }

    pub fn deinit(self: *Registry) void {
        for (self.slots, self.accounts) |*slot, *account| {
            if (slot.session) |*s| s.close();
            if (slot.drafts) |d| self.gpa.free(d);
            switch (slot.cache) {
                .open => |*store| store.close(),
                else => {},
            }
            account.wipe();
        }
        self.gpa.free(self.slots);
        self.* = undefined;
    }

    pub fn find(self: *Registry, name: []const u8) ?usize {
        for (self.accounts, 0..) |a, i| if (std.ascii.eqlIgnoreCase(a.name, name)) return i;
        return null;
    }

    pub fn filtersFor(self: *const Registry, idx: usize) []const *const Filter {
        return if (idx < self.active_filters.len) self.active_filters[idx] else &.{};
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
        s.login(a.login, a.password) catch |err| {
            var buf: [400]u8 = undefined;
            self.setDiag("account \"{s}\": login failed: {s}", .{ a.name, unicode.cleanInto(&buf, s.lastResponse()) });
            s.abandon();
            return switch (err) {
                error.ServerRejected => error.LoginFailed,
                else => err,
            };
        };
        slot.session = s;
        return &slot.session.?;
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
        const store = openCache(self.gpa, dir, self.accounts[idx].name) catch |err| {
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
fn openCache(gpa: Allocator, dir: []const u8, account: []const u8) !Store {
    try makePath(gpa, dir);
    const lower = try std.ascii.allocLowerString(gpa, account);
    defer gpa.free(lower);
    const path = try gpa.printSentinel("{s}/{s}.sqlite3", .{ dir, lower }, 0);
    defer gpa.free(path);

    const old_mask = std.c.umask(0o077);
    defer _ = std.c.umask(old_mask);
    return Store.open(path) catch |err| switch (err) {
        error.SqliteCorrupt => {
            log.warn("cache file {s} is corrupt; rebuilding", .{path});
            _ = std.c.unlink(path);
            return Store.open(path);
        },
        else => return err,
    };
}

/// mkdir -p with mode 0700 for any component it creates.
fn makePath(gpa: Allocator, dir: []const u8) !void {
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
    var reg: Registry = try .init(testing.allocator, &accounts, no_cache);
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
    var reg: Registry = try .init(testing.allocator, &accounts, no_cache);
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
    var reg: Registry = try .init(testing.allocator, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file });
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
    var reg: Registry = try .init(testing.allocator, &accounts, .{ .cache_dir = dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file });
    defer reg.deinit();
    try testing.expect(reg.cache(0) != null);
}

test "caching disabled: no store, clearCache reports false" {
    const pw = try testing.allocator.dupeSentinel(u8, "x", 0);
    defer testing.allocator.free(pw);
    var accounts = [_]config.Account{localAccount(pw, null)};
    var reg: Registry = try .init(testing.allocator, &accounts, no_cache);
    defer reg.deinit();
    try testing.expect(reg.cache(0) == null);
    try testing.expect(!reg.clearCache(0));
}
