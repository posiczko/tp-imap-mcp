//! Per-account on-disk cache (ADR 0013): mailbox list plus message headers
//! and sizes keyed by (mailbox, UIDVALIDITY, UID). Mailbox names are stored in
//! wire form (modified UTF-7).

const std = @import("std");
const Allocator = std.mem.Allocator;
const sqlite = @import("sqlite.zig");
const imap = @import("../imap/session.zig");

pub const Error = sqlite.Error || Allocator.Error;

const schema_version = 1;

const schema =
    \\PRAGMA journal_mode = WAL;
    \\DROP TABLE IF EXISTS meta;
    \\DROP TABLE IF EXISTS mailboxes;
    \\DROP TABLE IF EXISTS messages;
    \\CREATE TABLE meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
    \\CREATE TABLE mailboxes (name TEXT PRIMARY KEY, delimiter TEXT NOT NULL, flags TEXT NOT NULL);
    \\CREATE TABLE messages (
    \\  mailbox TEXT NOT NULL, uidvalidity INTEGER NOT NULL, uid INTEGER NOT NULL,
    \\  size INTEGER NOT NULL, header BLOB NOT NULL,
    \\  PRIMARY KEY (mailbox, uidvalidity, uid)
    \\) WITHOUT ROWID;
    \\PRAGMA user_version = 1;
;

const now_sql = "CAST(strftime('%s','now') AS INTEGER)";

pub const Store = struct {
    db: sqlite.Db,

    /// Opens or creates the cache at `path` (":memory:" in tests). A file with
    /// a different schema version is rebuilt; it is only a cache.
    pub fn open(path: [:0]const u8) Error!Store {
        var db: sqlite.Db = try .open(path);
        errdefer db.close();
        const v = try db.prepare("PRAGMA user_version");
        defer v.finalize();
        const version = if (try v.step()) v.int(0) else 0;
        try v.reset();
        if (version != schema_version) try db.exec(schema);
        return .{ .db = db };
    }

    pub fn close(self: *Store) void {
        self.db.close();
        self.* = undefined;
    }

    /// True if the mailbox list was stored less than `ttl_sec` seconds ago.
    pub fn mailboxesFresh(self: *Store, ttl_sec: i64) Error!bool {
        const q = try self.db.prepare("SELECT 1 FROM meta WHERE key = 'mailboxes_fetched_at' AND value > " ++ now_sql ++ " - ?1");
        defer q.finalize();
        try q.bindInt(1, ttl_sec);
        return q.step();
    }

    pub fn loadMailboxes(self: *Store, arena: Allocator) Error![]imap.Mailbox {
        const q = try self.db.prepare("SELECT name, delimiter, flags FROM mailboxes ORDER BY name");
        defer q.finalize();
        var out: std.ArrayList(imap.Mailbox) = .empty;
        while (try q.step()) {
            const delim = q.text(1);
            var flags: std.ArrayList([]const u8) = .empty;
            var it = std.mem.tokenizeScalar(u8, q.text(2), ' ');
            while (it.next()) |f| try flags.append(arena, try arena.dupe(u8, f));
            try out.append(arena, .{
                .name = try arena.dupe(u8, q.text(0)),
                .delimiter = if (delim.len == 1) delim[0] else null,
                .flags = flags.items,
            });
        }
        return out.items;
    }

    /// Replaces the stored list, drops cached messages of mailboxes that no
    /// longer exist, and marks the list fresh — all in one transaction.
    pub fn replaceMailboxes(self: *Store, arena: Allocator, boxes: []const imap.Mailbox) Error!void {
        try self.db.exec("BEGIN IMMEDIATE");
        errdefer self.db.exec("ROLLBACK") catch {};
        try self.db.exec("DELETE FROM mailboxes");
        const ins = try self.db.prepare("INSERT OR REPLACE INTO mailboxes (name, delimiter, flags) VALUES (?1, ?2, ?3)");
        defer ins.finalize();
        for (boxes) |b| {
            try ins.bindText(1, b.name);
            try ins.bindText(2, if (b.delimiter) |*d| d[0..1] else "");
            try ins.bindText(3, try std.mem.join(arena, " ", b.flags));
            try ins.run();
        }
        try self.db.exec("DELETE FROM messages WHERE mailbox NOT IN (SELECT name FROM mailboxes)");
        try self.db.exec("INSERT OR REPLACE INTO meta (key, value) VALUES ('mailboxes_fetched_at', " ++ now_sql ++ ")");
        try self.db.exec("COMMIT");
    }

    /// Forces the next mailbox-list read to go to the server.
    pub fn markMailboxesStale(self: *Store) Error!void {
        try self.db.exec("DELETE FROM meta WHERE key = 'mailboxes_fetched_at'");
    }

    /// Drops cached messages of `mailbox` whose UIDVALIDITY differs from `uidvalidity`.
    pub fn syncUidvalidity(self: *Store, mailbox: []const u8, uidvalidity: u32) Error!void {
        const q = try self.db.prepare("DELETE FROM messages WHERE mailbox = ?1 AND uidvalidity <> ?2");
        defer q.finalize();
        try q.bindText(1, mailbox);
        try q.bindInt(2, uidvalidity);
        try q.run();
    }

    /// Cached rows for `uids` (missing UIDs are simply absent).
    pub fn getMessages(self: *Store, arena: Allocator, mailbox: []const u8, uidvalidity: u32, uids: []const u32) Error![]imap.Fetched {
        const q = try self.db.prepare("SELECT size, header FROM messages WHERE mailbox = ?1 AND uidvalidity = ?2 AND uid = ?3");
        defer q.finalize();
        var out: std.ArrayList(imap.Fetched) = .empty;
        for (uids) |uid| {
            try q.bindText(1, mailbox);
            try q.bindInt(2, uidvalidity);
            try q.bindInt(3, uid);
            // A size that does not fit u32 means a damaged file: treat as a miss.
            if (try q.step()) if (std.math.cast(u32, q.int(0))) |size| try out.append(arena, .{
                .uid = uid,
                .size = size,
                .data = try arena.dupe(u8, q.blob(1)),
                .flags = null,
            });
            try q.reset();
        }
        return out.items;
    }

    /// Stores header + size rows; items without header data are skipped.
    pub fn putMessages(self: *Store, mailbox: []const u8, uidvalidity: u32, items: []const imap.Fetched) Error!void {
        try self.db.exec("BEGIN IMMEDIATE");
        errdefer self.db.exec("ROLLBACK") catch {};
        const ins = try self.db.prepare("INSERT OR REPLACE INTO messages (mailbox, uidvalidity, uid, size, header) VALUES (?1, ?2, ?3, ?4, ?5)");
        defer ins.finalize();
        for (items) |item| {
            const header = item.data orelse continue;
            try ins.bindText(1, mailbox);
            try ins.bindInt(2, uidvalidity);
            try ins.bindInt(3, item.uid);
            try ins.bindInt(4, item.size);
            try ins.bindBlob(5, header);
            try ins.run();
        }
        try self.db.exec("COMMIT");
    }

    /// Removes rows for UIDs the server no longer has (expunged).
    pub fn deleteMessages(self: *Store, mailbox: []const u8, uidvalidity: u32, uids: []const u32) Error!void {
        const q = try self.db.prepare("DELETE FROM messages WHERE mailbox = ?1 AND uidvalidity = ?2 AND uid = ?3");
        defer q.finalize();
        for (uids) |uid| {
            try q.bindText(1, mailbox);
            try q.bindInt(2, uidvalidity);
            try q.bindInt(3, uid);
            try q.run();
        }
    }

    pub fn clear(self: *Store) Error!void {
        try self.db.exec("BEGIN IMMEDIATE; DELETE FROM messages; DELETE FROM mailboxes; DELETE FROM meta; COMMIT;");
    }
};

const testing = std.testing;

fn box(name: []const u8, flags: []const []const u8) imap.Mailbox {
    return .{ .name = name, .delimiter = '/', .flags = flags };
}

test "mailbox list round-trip, freshness, and staleness" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s: Store = try .open(":memory:");
    defer s.close();

    try testing.expect(!try s.mailboxesFresh(3600));
    try s.replaceMailboxes(a, &.{ box("INBOX", &.{"\\HasChildren"}), box("Drafts", &.{ "\\Drafts", "\\HasNoChildren" }) });
    try testing.expect(try s.mailboxesFresh(3600));
    try testing.expect(!try s.mailboxesFresh(0));

    const got = try s.loadMailboxes(a);
    try testing.expectEqual(2, got.len);
    try testing.expectEqualStrings("Drafts", got[0].name);
    try testing.expectEqual('/', got[0].delimiter.?);
    try testing.expectEqualStrings("\\HasNoChildren", got[0].flags[1]);

    try s.markMailboxesStale();
    try testing.expect(!try s.mailboxesFresh(3600));
}

test "messages: hit, miss, UIDVALIDITY change, vanished mailbox, clear" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s: Store = try .open(":memory:");
    defer s.close();
    try s.replaceMailboxes(a, &.{ box("INBOX", &.{}), box("Old", &.{}) });

    try s.putMessages("INBOX", 7, &.{
        .{ .uid = 1, .size = 100, .data = "Subject: a\r\n\r\n", .flags = null },
        .{ .uid = 2, .size = 200, .data = null, .flags = null }, // no header: skipped
    });
    try s.putMessages("Old", 1, &.{.{ .uid = 9, .size = 9, .data = "X: y\r\n\r\n", .flags = null }});

    const hit = try s.getMessages(a, "INBOX", 7, &.{ 2, 1, 3 });
    try testing.expectEqual(1, hit.len);
    try testing.expectEqual(1, hit[0].uid);
    try testing.expectEqual(100, hit[0].size);
    try testing.expectEqualStrings("Subject: a\r\n\r\n", hit[0].data.?);

    try s.syncUidvalidity("INBOX", 8);
    try testing.expectEqual(0, (try s.getMessages(a, "INBOX", 7, &.{1})).len);

    try s.replaceMailboxes(a, &.{box("INBOX", &.{})}); // "Old" vanished
    try testing.expectEqual(0, (try s.getMessages(a, "Old", 1, &.{9})).len);

    try s.putMessages("INBOX", 8, &.{.{ .uid = 1, .size = 1, .data = "A: b\r\n\r\n", .flags = null }});
    try s.clear();
    try testing.expectEqual(0, (try s.getMessages(a, "INBOX", 8, &.{1})).len);
    try testing.expectEqual(0, (try s.loadMailboxes(a)).len);
}

test "todo: deleteMessages removes only the named UIDs" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var s: Store = try .open(":memory:");
    defer s.close();
    try s.putMessages("INBOX", 7, &.{
        .{ .uid = 1, .size = 1, .data = "A: b\r\n\r\n", .flags = null },
        .{ .uid = 2, .size = 1, .data = "A: c\r\n\r\n", .flags = null },
    });
    try s.deleteMessages("INBOX", 7, &.{1});
    const left = try s.getMessages(a, "INBOX", 7, &.{ 1, 2 });
    try testing.expectEqual(1, left.len);
    try testing.expectEqual(2, left[0].uid);
}

test "schema version mismatch rebuilds the file" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testing.allocator.printSentinel(".zig-cache/tmp/{s}/c.sqlite3", .{&tmp.sub_path}, 0);
    defer testing.allocator.free(path);
    {
        var db: sqlite.Db = try .open(path);
        defer db.close();
        try db.exec("CREATE TABLE junk (x); PRAGMA user_version = 99;");
    }
    var s: Store = try .open(path);
    defer s.close();
    try testing.expect(!try s.mailboxesFresh(3600));
}

test "a non-database file reports SqliteCorrupt" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "bad.sqlite3", .data = "this is not a database, just text padding" });
    const path = try testing.allocator.printSentinel(".zig-cache/tmp/{s}/bad.sqlite3", .{&tmp.sub_path}, 0);
    defer testing.allocator.free(path);
    try testing.expectError(error.SqliteCorrupt, Store.open(path));
}

test "an out-of-range cached size is treated as a miss, not a crash" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    var s: Store = try .open(":memory:");
    defer s.close();
    try s.db.exec("INSERT INTO messages VALUES ('INBOX', 7, 1, 1099511627776, X'00'), ('INBOX', 7, 2, -1, X'00')");
    try testing.expectEqual(0, (try s.getMessages(arena_state.allocator(), "INBOX", 7, &.{ 1, 2 })).len);
}
