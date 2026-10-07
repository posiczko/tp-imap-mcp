//! Minimal SQLite binding: hand-written externs for the system libsqlite3
//! (ADR 0015) plus a thin wrapper. Only what the cache needs.

const std = @import("std");

const sqlite3 = opaque {};
const sqlite3_stmt = opaque {};
/// SQLITE_STATIC (null): SQLite does not copy bound data, so it must outlive
/// the statement's next step/reset. Every caller binds, steps, then resets.
const Destructor = ?*const fn (?*anyopaque) callconv(.c) void;

extern fn sqlite3_open_v2(filename: [*:0]const u8, db: *?*sqlite3, flags: c_int, vfs: ?[*:0]const u8) c_int;
extern fn sqlite3_close_v2(db: ?*sqlite3) c_int;
extern fn sqlite3_errmsg(db: *sqlite3) [*:0]const u8;
extern fn sqlite3_exec(db: *sqlite3, sql: [*:0]const u8, callback: ?*const anyopaque, arg: ?*anyopaque, errmsg: ?*?[*:0]u8) c_int;
extern fn sqlite3_busy_timeout(db: *sqlite3, ms: c_int) c_int;
extern fn sqlite3_prepare_v2(db: *sqlite3, sql: [*]const u8, nbyte: c_int, stmt: *?*sqlite3_stmt, tail: ?*?[*]const u8) c_int;
extern fn sqlite3_bind_text(stmt: *sqlite3_stmt, idx: c_int, text: [*]const u8, n: c_int, destructor: Destructor) c_int;
extern fn sqlite3_bind_blob(stmt: *sqlite3_stmt, idx: c_int, data: ?*const anyopaque, n: c_int, destructor: Destructor) c_int;
extern fn sqlite3_bind_int64(stmt: *sqlite3_stmt, idx: c_int, value: i64) c_int;
extern fn sqlite3_step(stmt: *sqlite3_stmt) c_int;
extern fn sqlite3_reset(stmt: *sqlite3_stmt) c_int;
extern fn sqlite3_finalize(stmt: ?*sqlite3_stmt) c_int;
extern fn sqlite3_column_int64(stmt: *sqlite3_stmt, col: c_int) i64;
extern fn sqlite3_column_text(stmt: *sqlite3_stmt, col: c_int) ?[*]const u8;
extern fn sqlite3_column_blob(stmt: *sqlite3_stmt, col: c_int) ?[*]const u8;
extern fn sqlite3_column_bytes(stmt: *sqlite3_stmt, col: c_int) c_int;

const SQLITE_OK = 0;
const SQLITE_CORRUPT = 11;
const SQLITE_NOTADB = 26;
const SQLITE_ROW = 100;
const SQLITE_DONE = 101;
const SQLITE_OPEN_READWRITE = 0x00000002;
const SQLITE_OPEN_CREATE = 0x00000004;

pub const Error = error{
    SqliteFailed,
    /// The file exists but is not a usable database; safe to delete (cache).
    SqliteCorrupt,
};

fn check(db: *sqlite3, rc: c_int) Error!void {
    if (rc == SQLITE_OK) return;
    std.log.debug("sqlite: {s}", .{sqlite3_errmsg(db)});
    return if (rc == SQLITE_CORRUPT or rc == SQLITE_NOTADB) error.SqliteCorrupt else error.SqliteFailed;
}

fn len(n: usize) c_int {
    return std.math.cast(c_int, n) orelse std.math.maxInt(c_int);
}

pub const Db = struct {
    handle: *sqlite3,

    pub fn open(path: [:0]const u8) Error!Db {
        var h: ?*sqlite3 = null;
        const rc = sqlite3_open_v2(path, &h, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, null);
        const handle = h orelse return error.SqliteFailed;
        errdefer _ = sqlite3_close_v2(handle);
        try check(handle, rc);
        _ = sqlite3_busy_timeout(handle, 5000);
        return .{ .handle = handle };
    }

    pub fn close(self: *Db) void {
        _ = sqlite3_close_v2(self.handle);
        self.* = undefined;
    }

    pub fn exec(self: Db, sql: [:0]const u8) Error!void {
        try check(self.handle, sqlite3_exec(self.handle, sql, null, null, null));
    }

    pub fn prepare(self: Db, sql: []const u8) Error!Stmt {
        var s: ?*sqlite3_stmt = null;
        try check(self.handle, sqlite3_prepare_v2(self.handle, sql.ptr, len(sql.len), &s, null));
        return .{ .handle = s orelse return error.SqliteFailed, .db = self.handle };
    }
};

pub const Stmt = struct {
    handle: *sqlite3_stmt,
    db: *sqlite3,

    pub fn finalize(self: Stmt) void {
        _ = sqlite3_finalize(self.handle);
    }

    /// Parameters are 1-based, as in SQL (`?1`, `?2`, ...).
    pub fn bindText(self: Stmt, idx: c_int, value: []const u8) Error!void {
        try check(self.db, sqlite3_bind_text(self.handle, idx, value.ptr, len(value.len), null));
    }

    pub fn bindBlob(self: Stmt, idx: c_int, data: []const u8) Error!void {
        try check(self.db, sqlite3_bind_blob(self.handle, idx, data.ptr, len(data.len), null));
    }

    pub fn bindInt(self: Stmt, idx: c_int, value: i64) Error!void {
        try check(self.db, sqlite3_bind_int64(self.handle, idx, value));
    }

    /// True when a row is available, false when the statement is done.
    pub fn step(self: Stmt) Error!bool {
        const rc = sqlite3_step(self.handle);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        try check(self.db, rc);
        return error.SqliteFailed;
    }

    /// Steps a statement that returns no rows.
    pub fn run(self: Stmt) Error!void {
        while (try self.step()) {}
        try self.reset();
    }

    pub fn reset(self: Stmt) Error!void {
        try check(self.db, sqlite3_reset(self.handle));
    }

    /// Columns are 0-based.
    pub fn int(self: Stmt, col: c_int) i64 {
        return sqlite3_column_int64(self.handle, col);
    }

    /// Valid until the next step/reset/finalize; copy if kept.
    pub fn text(self: Stmt, col: c_int) []const u8 {
        const p = sqlite3_column_text(self.handle, col) orelse return "";
        return p[0..@intCast(sqlite3_column_bytes(self.handle, col))];
    }

    /// Valid until the next step/reset/finalize; copy if kept.
    pub fn blob(self: Stmt, col: c_int) []const u8 {
        const p = sqlite3_column_blob(self.handle, col) orelse return "";
        return p[0..@intCast(sqlite3_column_bytes(self.handle, col))];
    }
};

const testing = std.testing;

test "round-trips text, blob, and integers" {
    var db: Db = try .open(":memory:");
    defer db.close();
    try db.exec("CREATE TABLE t (a TEXT, b BLOB, c INTEGER)");
    const ins = try db.prepare("INSERT INTO t VALUES (?1, ?2, ?3)");
    defer ins.finalize();
    try ins.bindText(1, "héllo");
    try ins.bindBlob(2, "\x00\xff");
    try ins.bindInt(3, 4294967295);
    try ins.run();

    const sel = try db.prepare("SELECT a, b, c FROM t");
    defer sel.finalize();
    try testing.expect(try sel.step());
    try testing.expectEqualStrings("héllo", sel.text(0));
    try testing.expectEqualSlices(u8, "\x00\xff", sel.blob(1));
    try testing.expectEqual(4294967295, sel.int(2));
    try testing.expect(!try sel.step());
}

test "SQL errors surface as SqliteFailed" {
    var db: Db = try .open(":memory:");
    defer db.close();
    try testing.expectError(error.SqliteFailed, db.exec("NOT SQL"));
    try testing.expectError(error.SqliteFailed, db.prepare("SELECT * FROM missing"));
}
