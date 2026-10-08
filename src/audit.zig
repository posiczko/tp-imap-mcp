//! Audit log of tool calls (ADR 0023): one JSON line per call with the tool,
//! account, arguments, outcome and duration. Changes are logged with their
//! result; reads only with the result's size, so message content (bodies,
//! headers, snippets, attachment names) never reaches the log. Writing is
//! best effort: a log problem never fails a tool call.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const ObjectMap = std.json.ObjectMap;
const Stringify = std.json.Stringify;

const log = std.log.scoped(.audit);

/// Rotate when the log reaches this size; audit.log.1 and audit.log.2 are kept.
pub const max_bytes = 10 * 1024 * 1024;
pub const keep = 2;
/// Arrays longer than this are logged as {"count", "first"}.
pub const array_preview = 10;
/// Strings longer than this are cut (criteria, server messages).
pub const string_max = 512;

/// Tools whose results are logged in full (after summarizing): they change
/// the mailbox or the local cache, and return no message content.
const changing_tools = [_][]const u8{
    "change_keywords", "create_message", "create_mailbox", "rename_mailbox", "delete_mailbox",
    "move_messages",   "copy_messages",  "apply_organization", "clear_cache",
};

pub const Outcome = union(enum) {
    /// The tool's JSON result.
    ok: []const u8,
    invalid_params: []const u8,
    tool_error: []const u8,
};

fn isChanging(tool: []const u8) bool {
    for (changing_tools) |t| if (std.mem.eql(u8, t, tool)) return true;
    return false;
}

/// `v` with long arrays replaced by {"count", "first"} and long strings cut.
fn summarize(arena: Allocator, v: Value) Allocator.Error!Value {
    switch (v) {
        .string => |s| return .{ .string = try cut(arena, s) },
        .array => |a| {
            const n = @min(a.items.len, array_preview);
            var first: std.json.Array = .init(arena);
            for (a.items[0..n]) |item| try first.append(try summarize(arena, item));
            if (a.items.len <= array_preview) return .{ .array = first };
            var o: ObjectMap = .empty;
            try o.put(arena, "count", .{ .integer = @intCast(a.items.len) });
            try o.put(arena, "first", .{ .array = first });
            return .{ .object = o };
        },
        .object => |obj| {
            var o: ObjectMap = .empty;
            var it = obj.iterator();
            while (it.next()) |e| try o.put(arena, e.key_ptr.*, try summarize(arena, e.value_ptr.*));
            return .{ .object = o };
        },
        else => return v,
    }
}

fn cut(arena: Allocator, s: []const u8) Allocator.Error![]const u8 {
    if (s.len <= string_max) return s;
    var end: usize = string_max;
    while (end > 0 and (s[end] & 0xC0) == 0x80) end -= 1; // UTF-8 boundary
    return try arena.print("{s}… [{d} bytes]", .{ s[0..end], s.len });
}

/// Arguments as logged: create_message's raw message becomes its size.
fn loggedArgs(arena: Allocator, tool: []const u8, args: ?ObjectMap) Allocator.Error!Value {
    const a = args orelse return .null;
    var o: ObjectMap = .empty;
    var it = a.iterator();
    while (it.next()) |e| {
        const key = e.key_ptr.*;
        const value = e.value_ptr.*;
        if (std.mem.eql(u8, tool, "create_message") and std.mem.eql(u8, key, "content") and value == .string) {
            var size: ObjectMap = .empty;
            try size.put(arena, "bytes", .{ .integer = @intCast(value.string.len) });
            try o.put(arena, key, .{ .object = size });
            continue;
        }
        try o.put(arena, key, try summarize(arena, value));
    }
    return .{ .object = o };
}

/// The result as logged: changes in full (summarized), reads as their size
/// and, for a JSON array, its length.
fn loggedResult(arena: Allocator, tool: []const u8, result: []const u8) Allocator.Error!Value {
    const parsed: ?Value = std.json.parseFromSliceLeaky(Value, arena, result, .{}) catch null;
    if (isChanging(tool)) if (parsed) |p| return summarize(arena, p);
    var o: ObjectMap = .empty;
    try o.put(arena, "bytes", .{ .integer = @intCast(result.len) });
    if (parsed) |p| if (p == .array) try o.put(arena, "items", .{ .integer = @intCast(p.array.items.len) });
    return .{ .object = o };
}

/// "2026-10-08T22:41:07Z" for Unix time `secs`.
fn rfc3339(arena: Allocator, secs: i64) Allocator.Error![]const u8 {
    const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(@max(secs, 0)) };
    const yd = es.getEpochDay().calculateYearDay();
    const md = yd.calculateMonthDay();
    const ds = es.getDaySeconds();
    return arena.print("{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year, md.month.numeric(), md.day_index + 1, ds.getHoursIntoDay(), ds.getMinutesIntoHour(), ds.getSecondsIntoMinute(),
    });
}

/// One log line (no trailing newline) for a tools/call.
pub fn entry(arena: Allocator, unix_secs: i64, ms: i64, tool: []const u8, args: ?ObjectMap, outcome: Outcome) Allocator.Error![]const u8 {
    const account: ?[]const u8 = if (args) |a| if (a.get("account")) |v| if (v == .string) v.string else null else null else null;
    const kind, const message, const result = switch (outcome) {
        .ok => |r| .{ "ok", null, try loggedResult(arena, tool, r) },
        .invalid_params => |m| .{ "invalid_params", try cut(arena, m), null },
        .tool_error => |m| .{ "tool_error", try cut(arena, m), null },
    };
    return Stringify.valueAlloc(arena, .{
        .ts = try rfc3339(arena, unix_secs),
        .tool = tool,
        .account = account,
        .args = try loggedArgs(arena, tool, args),
        .outcome = kind,
        .message = message,
        .result = result,
        .ms = ms,
    }, .{ .emit_null_optional_fields = false });
}

/// Appends lines to the audit file, rotating at `max_bytes`. Best effort:
/// the first failure is reported once (std.log, to stderr) and later ones
/// are silent.
pub const Log = struct {
    path: [:0]const u8,
    warned: bool = false,

    pub fn append(self: *Log, line: []const u8) void {
        self.rotateIfFull();
        const fd = std.c.open(self.path, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o600));
        if (fd < 0) return self.warn("cannot open");
        defer _ = std.c.close(fd);
        if (!writeAll(fd, line) or !writeAll(fd, "\n")) self.warn("cannot write");
    }

    fn rotateIfFull(self: *Log) void {
        var st: std.c.Stat = undefined;
        if (std.c.stat(self.path, &st) != 0 or st.size < max_bytes) return;
        var from_buf: [std.fs.max_path_bytes]u8 = undefined;
        var to_buf: [std.fs.max_path_bytes]u8 = undefined;
        var i: usize = keep;
        while (i > 0) : (i -= 1) {
            const to = std.mem.printSentinel(&to_buf, "{s}.{d}", .{ self.path, i }, 0) catch return;
            const from = if (i == 1) self.path else std.mem.printSentinel(&from_buf, "{s}.{d}", .{ self.path, i - 1 }, 0) catch return;
            _ = std.c.rename(from, to); // missing older files are fine
        }
    }

    fn warn(self: *Log, what: []const u8) void {
        if (self.warned) return;
        self.warned = true;
        log.warn("audit log {s}: {s} it; tool calls continue unlogged", .{ self.path, what });
    }
};

fn writeAll(fd: std.c.fd_t, bytes: []const u8) bool {
    var rest = bytes;
    while (rest.len > 0) {
        const n = std.c.write(fd, rest.ptr, rest.len);
        if (n <= 0) return false;
        rest = rest[@intCast(n)..];
    }
    return true;
}

const testing = std.testing;

fn parseArgs(arena: Allocator, json: []const u8) !ObjectMap {
    return (try std.json.parseFromSliceLeaky(Value, arena, json, .{})).object;
}

test "entry: a change is logged with its arguments and full result" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const args = try parseArgs(a, "{\"account\":\"tetra\",\"name\":\"gemma/x\",\"new_name\":\"10 Gemma/x\"}");
    const line = try entry(a, 1791499267, 38, "rename_mailbox", args, .{ .ok = "{\"renamed\":\"gemma/x\",\"to\":\"10 Gemma/x\",\"note\":null}" });
    try testing.expectEqualStrings(
        "{\"ts\":\"2026-10-08T22:41:07Z\",\"tool\":\"rename_mailbox\",\"account\":\"tetra\"," ++
            "\"args\":{\"account\":\"tetra\",\"name\":\"gemma/x\",\"new_name\":\"10 Gemma/x\"}," ++
            "\"outcome\":\"ok\",\"result\":{\"renamed\":\"gemma/x\",\"to\":\"10 Gemma/x\",\"note\":null},\"ms\":38}",
        line,
    );
}

test "entry: a read logs only the result's size, never its content" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const args = try parseArgs(a, "{\"account\":\"tetra\",\"directory\":\"INBOX\",\"uids\":[\"1\",\"2\"]}");
    const body = "[\"Dear Pawel, your secret code is 123456\",\"hello\"]";
    const line = try entry(a, 0, 5, "get_text", args, .{ .ok = body });
    try testing.expect(std.mem.find(u8, line, "secret") == null);
    try testing.expect(std.mem.find(u8, line, "\"result\":{\"bytes\":50,\"items\":2}") != null);
    try testing.expect(std.mem.find(u8, line, "\"ts\":\"1970-01-01T00:00:00Z\"") != null);
}

test "entry: create_message content becomes its size; long arrays and strings are summarized" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const draft = try parseArgs(a, "{\"account\":\"tetra\",\"content\":\"Subject: private\\r\\n\\r\\nbody\"}");
    const d = try entry(a, 0, 1, "create_message", draft, .{ .ok = "{\"status\":\"OK\"}" });
    try testing.expect(std.mem.find(u8, d, "private") == null);
    try testing.expect(std.mem.find(u8, d, "\"content\":{\"bytes\":24}") != null);

    var uids: std.ArrayList(u8) = .empty;
    try uids.appendSlice(a, "{\"account\":\"tetra\",\"directory\":\"INBOX\",\"destination\":\"X\",\"uids\":[");
    for (1..13) |i| try uids.print(a, "{s}\"{d}\"", .{ if (i > 1) "," else "", i });
    try uids.appendSlice(a, "]}");
    const m = try entry(a, 0, 1, "move_messages", try parseArgs(a, uids.items), .{ .ok = "{\"moved\":12}" });
    try testing.expect(std.mem.find(u8, m, "\"uids\":{\"count\":12,\"first\":[\"1\",\"2\",\"3\",\"4\",\"5\",\"6\",\"7\",\"8\",\"9\",\"10\"]}") != null);

    const long: [600]u8 = @splat('x');
    const crit = try std.mem.concat(a, u8, &.{ "{\"criteria\":\"", &long, "\"}" });
    const s = try entry(a, 0, 1, "search", try parseArgs(a, crit), .{ .ok = "[]" });
    try testing.expect(std.mem.find(u8, s, "… [600 bytes]") != null);
}

test "entry: errors carry their message and no result" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const line = try entry(a, 0, 3, "delete_mailbox", null, .{ .tool_error = "mailbox is not empty" });
    try testing.expectEqualStrings(
        "{\"ts\":\"1970-01-01T00:00:00Z\",\"tool\":\"delete_mailbox\",\"args\":null,\"outcome\":\"tool_error\",\"message\":\"mailbox is not empty\",\"ms\":3}",
        line,
    );
}

test "Log appends lines and rotates at max_bytes" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir_len = try tmp.dir.realPath(testing.io, &dir_buf);
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.mem.printSentinel(&path_buf, "{s}/audit.log", .{dir_buf[0..dir_len]}, 0);

    var l: Log = .{ .path = path };
    l.append("one");
    l.append("two");
    const got = try tmp.dir.readFileAlloc(testing.io, "audit.log", testing.allocator, .limited(1024));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("one\ntwo\n", got);

    // Grow past the limit, then the next append starts a new file.
    const fd = std.c.open(path, .{ .ACCMODE = .WRONLY, .APPEND = true }, @as(std.c.mode_t, 0));
    try testing.expect(fd >= 0);
    try testing.expectEqual(0, std.c.ftruncate(fd, max_bytes));
    _ = std.c.close(fd);
    l.append("three");
    const fresh = try tmp.dir.readFileAlloc(testing.io, "audit.log", testing.allocator, .limited(1024));
    defer testing.allocator.free(fresh);
    try testing.expectEqualStrings("three\n", fresh);
    var st: std.c.Stat = undefined;
    const rotated = try std.mem.printSentinel(&path_buf, "{s}/audit.log.1", .{dir_buf[0..dir_len]}, 0);
    try testing.expectEqual(0, std.c.stat(rotated, &st));
    try testing.expectEqual(0o600, st.mode & 0o777);
}
