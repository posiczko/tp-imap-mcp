//! Live integration checks against a real IMAP account (spec §9).
//!
//!   op run --env-file imap.env -- zig build itest -- <account> [--write <scratch-mailbox>] [--organize]
//!
//! Read-only by default. Prints only counts and shapes, never message content.
//! Uses a throwaway cache in .zig-cache/itest-cache, never ~/.cache.
//! `--write` adds then removes the keyword $TpImapMcpTest on the newest
//! message of <scratch-mailbox>; use a folder you do not care about.
//! `--organize` exercises the folder and move/copy tools (ADR 0021) on
//! folders it creates (tp-imap-mcp-itest-<random>) and removes them again.

const std = @import("std");
const config = @import("config.zig");
const tools = @import("tools.zig");
const c = @import("imap/c.zig");
const Registry = @import("accounts.zig").Registry;
const filter = @import("filter/rules.zig");
const unicode = @import("sanitize/unicode.zig");
const organize = @import("organize.zig");
const Session = @import("imap/session.zig").Session;

var failures: usize = 0;

fn report(ok: bool, comptime what: []const u8, args: anytype) void {
    std.debug.print("{s} " ++ what ++ "\n", .{if (ok) "PASS" else "FAIL"} ++ args);
    if (!ok) failures += 1;
}

const Harness = struct {
    reg: *Registry,
    arena: std.mem.Allocator,
    account: []const u8,

    /// Calls a tool; returns parsed JSON content (or a JSON string for whoami).
    fn call(h: Harness, name: []const u8, comptime args_fmt: []const u8, args: anytype) !?std.json.Value {
        const args_json = try h.arena.print(args_fmt, args);
        const parsed = try std.json.parseFromSliceLeaky(std.json.Value, h.arena, args_json, .{});
        const outcome = (try tools.call(h.reg, h.arena, name, parsed.object)) orelse return error.UnknownTool;
        switch (outcome) {
            .content => |t| return std.json.parseFromSliceLeaky(std.json.Value, h.arena, t, .{}) catch
                std.json.Value{ .string = t },
            .tool_error, .invalid_params => |t| {
                std.debug.print("     {s}: {s}\n", .{ name, t });
                return null;
            },
        }
    }
};

pub fn main(init: std.process.Init) !u8 {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.debug.print("usage: itest <account> [--write <scratch-mailbox>] [--organize]\n", .{});
        return 2;
    }
    const account = args[1];
    var write_box: ?[]const u8 = null;
    var organize_checks = false;
    var ai: usize = 2;
    while (ai < args.len) : (ai += 1) {
        if (std.mem.eql(u8, args[ai], "--write") and ai + 1 < args.len) {
            ai += 1;
            write_box = args[ai];
        } else if (std.mem.eql(u8, args[ai], "--organize")) {
            organize_checks = true;
        } else {
            std.debug.print("unknown argument {s}\n", .{args[ai]});
            return 2;
        }
    }

    var diag_buf: [256]u8 = undefined;
    var diag: std.Io.Writer = .fixed(&diag_buf);
    const accounts = config.load(arena, init.environ_map, &diag) catch |err| {
        std.debug.print("config: {s} ({t})\n", .{ diag.buffered(), err });
        return 2;
    };
    var settings = config.loadSettings(arena, init.environ_map, &diag) catch |err| {
        std.debug.print("config: {s} ({t})\n", .{ diag.buffered(), err });
        return 2;
    };
    settings.cache_dir = ".zig-cache/itest-cache"; // never touch ~/.cache
    settings.mailbox_ttl = 3600;
    const no_filters = try arena.alloc([]const *const filter.Filter, accounts.len);
    @memset(no_filters, &.{});
    var reg: Registry = try .init(init.gpa, init.io, accounts, settings, no_filters);
    defer reg.deinit();
    const idx = reg.find(account) orelse {
        std.debug.print("unknown account {s}\n", .{account});
        return 2;
    };
    const h: Harness = .{ .reg = &reg, .arena = arena, .account = account };
    const acct = try std.json.Stringify.valueAlloc(arena, account, .{});

    const cleared = try h.call("clear_cache", "{{\"account\":{s}}}", .{acct});
    report(cleared != null and reg.cache(idx) != null, "clear_cache (start from an empty cache)", .{});

    const who = try h.call("whoami", "{{\"account\":{s}}}", .{acct});
    report(who != null and who.? == .string, "whoami", .{});

    const boxes = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"*\"}}", .{acct});
    report(boxes != null and boxes.? == .array and boxes.?.array.items.len > 0, "list_mailboxes: {d} mailboxes", .{if (boxes) |b| b.array.items.len else 0});

    const fresh = if (reg.cache(idx)) |store| store.mailboxesFresh(3600) catch false else false;
    report(fresh, "mailbox list cached after first list_mailboxes", .{});
    const again_boxes = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"*\"}}", .{acct});
    report(again_boxes != null and boxes != null and again_boxes.?.array.items.len == boxes.?.array.items.len, "list_mailboxes from cache matches server", .{});
    const inbox = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"inbox\"}}", .{acct});
    report(inbox != null and inbox.?.array.items.len == 1, "local LIST matching: pattern \"inbox\" finds exactly INBOX", .{});
    const refreshed = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"%\",\"refresh\":true}}", .{acct});
    report(refreshed != null and refreshed.?.array.items.len > 0, "list_mailboxes refresh=true", .{});

    const st = try h.call("mailboxes_status", "{{\"account\":{s},\"directory\":\"INBOX\"}}", .{acct});
    report(st != null and st.?.object.get("MESSAGES") != null, "mailboxes_status INBOX", .{});

    const found = try h.call("search", "{{\"account\":{s},\"directory\":\"INBOX\",\"criteria\":\"ALL\"}}", .{acct});
    const uids = if (found) |f| f.array.items else &.{};
    report(found != null, "search ALL: {d} uids", .{uids.len});

    const bad = try h.call("search", "{{\"account\":{s},\"criteria\":\"BOGUSKEY\"}}", .{acct});
    report(bad == null, "search BOGUSKEY is a tool error", .{});

    if (uids.len > 0) {
        // Newest two UIDs plus one that cannot exist, to check alignment.
        const last = uids[uids.len - 1].string;
        const prev = uids[if (uids.len > 1) uids.len - 2 else 0].string;
        const set = try arena.print("[\"{s}\",\"4294967295\",\"{s}\"]", .{ last, prev });
        const per_uid = [_][]const u8{ "get_header", "get_size", "get_keywords", "get_text", "get_html" };
        for (per_uid) |tool| {
            const r = try h.call(tool, "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
            const ok = r != null and r.? == .array and r.?.array.items.len == 3 and
                (if (std.mem.eql(u8, tool, "get_keywords"))
                    r.?.array.items[1].object.get("4294967295").? == .null
                else
                    r.?.array.items[1] == .null) and
                r.?.array.items[0] != .null;
            report(ok, "{s}: aligned, null for missing uid", .{tool});
        }
        // The header/size calls above populated the cache; a second call must
        // agree with the first and the rows must be on disk.
        const h1 = try h.call("get_header_field", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"],\"field\":\"Message-ID\"}}", .{ acct, last });
        const h2 = try h.call("get_header_field", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"],\"field\":\"Message-ID\"}}", .{ acct, last });
        const same = h1 != null and h2 != null and std.mem.eql(u8,
            try std.json.Stringify.valueAlloc(arena, h1.?, .{}),
            try std.json.Stringify.valueAlloc(arena, h2.?, .{}));
        report(same, "cached header matches live header", .{});
        const cached_rows = if (reg.cache(idx)) |store| blk: {
            const wanted = [_]u32{ try std.fmt.parseInt(u32, last, 10), try std.fmt.parseInt(u32, prev, 10) };
            const rows = store.getMessages(arena, "INBOX", uidvalidityOf(&reg, idx), &wanted) catch break :blk 0;
            break :blk rows.len;
        } else 0;
        report(cached_rows == 2 or (cached_rows == 1 and std.mem.eql(u8, last, prev)), "header rows stored in cache: {d}", .{cached_rows});

        const subj = try h.call("get_header_field", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"],\"field\":\"Subject\"}}", .{ acct, last });
        report(subj != null and subj.?.array.items[0] == .array, "get_header_field Subject", .{});

        // Kill the socket behind the registry's back; the next call must reconnect.
        _ = c.tpi_logout(reg.slots[idx].session.?.handle);
        const again = try h.call("get_size", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":[\"{s}\"]}}", .{ acct, last });
        report(again != null, "reconnects after server-side logout", .{});

        try sanitizeChecks(h, acct, uids);
        try attachmentChecks(h, acct, uids, "newest");
        // The newest messages may have no attachments: also check large
        // messages (> 400 KB), which usually do.
        const large = try h.call("search", "{{\"account\":{s},\"directory\":\"INBOX\",\"criteria\":\"LARGER 400000\"}}", .{acct});
        if (large) |m| if (m.array.items.len > 0) try attachmentChecks(h, acct, m.array.items, "large");
        try filterChecks(h, &reg, idx, acct, set);
    }

    if (write_box) |box| try writeChecks(h, acct, box);
    if (organize_checks) try organizeChecks(h, &reg, idx, acct, init.io);

    const wiped = try h.call("clear_cache", "{{\"account\":{s}}}", .{acct});
    const empty = if (reg.cache(idx)) |store| !(store.mailboxesFresh(3600) catch true) else false;
    report(wiped != null and empty, "clear_cache empties the cache", .{});

    std.debug.print("{d} failure(s)\n", .{failures});
    return if (failures == 0) 0 else 1;
}

fn writeChecks(h: Harness, acct: []const u8, box: []const u8) !void {
    const boxj = try std.json.Stringify.valueAlloc(h.arena, box, .{});
    const found = (try h.call("search", "{{\"account\":{s},\"directory\":{s}}}", .{ acct, boxj })) orelse {
        report(false, "write: search {s}", .{box});
        return;
    };
    if (found.array.items.len == 0) {
        report(false, "write: {s} has no messages to test with", .{box});
        return;
    }
    const uid = found.array.items[found.array.items.len - 1].string;
    const base = "{{\"account\":{s},\"directory\":{s},\"uids\":[\"{s}\"],\"keywords\":[\"$TpImapMcpTest\"],\"set\":{s}}}";
    const added = try h.call("change_keywords", base, .{ acct, boxj, uid, "true" });
    report(added != null and hasKeyword(added.?, uid), "change_keywords set", .{});
    const removed = try h.call("change_keywords", base, .{ acct, boxj, uid, "false" });
    report(removed != null and !hasKeyword(removed.?, uid), "change_keywords unset", .{});
}

fn hasKeyword(v: std.json.Value, uid: []const u8) bool {
    const flags = v.array.items[0].object.get(uid) orelse return false;
    if (flags != .array) return false;
    for (flags.array.items) |f| if (std.mem.eql(u8, f.string, "$TpImapMcpTest")) return true;
    return false;
}

/// UIDVALIDITY of INBOX, read through the registry's live session.
fn uidvalidityOf(reg: *Registry, idx: usize) u32 {
    const s = &(reg.slots[idx].session orelse return 0);
    return s.examine("INBOX") catch 0;
}

/// ADR 0017: with a filter matching every message, bodies and non-visible
/// headers must be withheld; with no filters, content comes back.
fn filterChecks(h: Harness, reg: *Registry, idx: usize, acct: []const u8, set: []const u8) !void {
    const everything: filter.Filter = .{ .name = "everything", .rules = &.{.{ .conditions = &.{.{ .field = "date", .matcher = .{ .glob = &.{"*"} } }} }} };
    const one = [_]*const filter.Filter{&everything};
    const per_account = try h.arena.alloc([]const *const filter.Filter, reg.accounts.len);
    @memset(per_account, &.{});
    per_account[idx] = &one;
    const original = reg.active_filters;
    reg.active_filters = per_account;
    defer reg.active_filters = original;

    const marker = "[withheld by filter \"everything\"]";
    for ([_][]const u8{ "get_text", "get_html" }) |tool| {
        const r = try h.call(tool, "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
        const items = if (r) |v| v.array.items else &.{};
        const ok = items.len == 3 and items[0] == .string and std.mem.eql(u8, items[0].string, marker) and
            items[1] == .null and items[2] == .string and std.mem.eql(u8, items[2].string, marker);
        report(ok, "filter: {s} withholds matched messages", .{tool});
    }
    const att = try h.call("list_attachments", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
    const ok_att = att != null and att.?.array.items.len == 3 and att.?.array.items[0] == .string and
        std.mem.eql(u8, att.?.array.items[0].string, marker) and att.?.array.items[1] == .null;
    report(ok_att, "filter: list_attachments withholds matched messages", .{});

    const hdr = try h.call("get_header", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
    const ok_hdr = blk: {
        const obj = (hdr orelse break :blk false).array.items[0].object;
        if (obj.get("x-tp-imap-mcp-withheld") == null) break :blk false;
        for (obj.keys()) |k| if (!std.mem.eql(u8, k, "date") and !std.mem.eql(u8, k, "from") and !std.mem.eql(u8, k, "x-tp-imap-mcp-withheld")) break :blk false;
        break :blk true;
    };
    report(ok_hdr, "filter: get_header shows only date/from plus marker", .{});

    reg.active_filters = original;
    const plain = try h.call("get_text", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, set });
    const ok_plain = plain != null and plain.?.array.items[0] == .string and !std.mem.startsWith(u8, plain.?.array.items[0].string, "[withheld");
    report(ok_plain, "filter: no active filters returns content", .{});
}

/// ADR 0018: bodies of the newest messages contain no invisible characters,
/// and HTML-converted output (get_html) contains no markup. get_text may
/// legitimately contain `<tag` text: senders sometimes put raw HTML inside
/// the text/plain alternative, which is returned verbatim as inert text.
fn sanitizeChecks(h: Harness, acct: []const u8, uids: []const std.json.Value) !void {
    const n = @min(uids.len, 10);
    var list: std.ArrayList(u8) = .empty;
    try list.append(h.arena, '[');
    for (uids[uids.len - n ..], 0..) |u, i| {
        if (i > 0) try list.append(h.arena, ',');
        try list.print(h.arena, "\"{s}\"", .{u.string});
    }
    try list.append(h.arena, ']');
    for ([_][]const u8{ "get_text", "get_html" }) |tool| {
        const r = try h.call(tool, "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, list.items });
        var ok = r != null;
        var checked: usize = 0;
        if (r) |v| for (v.array.items) |item| {
            if (item != .string) continue;
            const body = item.string;
            checked += 1;
            if (std.mem.eql(u8, tool, "get_html") and containsHtmlTag(body)) ok = false;
            if ((try unicode.clean(h.arena, body)).ptr != body.ptr) ok = false;
        };
        report(ok, "sanitize: {s} on {d} messages has no invisible characters{s}", .{ tool, checked, if (std.mem.eql(u8, tool, "get_html")) " or markup" else "" });
    }
}

/// `<tag` followed by whitespace, `>` or `/`, for common HTML element names.
/// (A bare `<letter` is legitimate in plain text, e.g. `John <john@x.org>`.)
fn containsHtmlTag(body: []const u8) bool {
    const tags = [_][]const u8{ "html", "body", "head", "div", "span", "p", "a", "br", "table", "tr", "td", "img", "script", "style", "font", "center", "ul", "li" };
    var i: usize = 0;
    while (std.mem.findScalarPos(u8, body, i, '<')) |at| : (i = at + 1) {
        const rest = body[at + 1 ..];
        for (tags) |t| {
            if (rest.len > t.len and std.ascii.startsWithIgnoreCase(rest, t)) {
                const next = rest[t.len];
                if (next == '>' or next == '/' or std.ascii.isWhitespace(next)) return true;
            }
        }
    }
    return false;
}

/// list_attachments on the newest messages: one entry per UID, each a list
/// of well-formed, sanitized attachment records. Prints counts only.
fn attachmentChecks(h: Harness, acct: []const u8, uids: []const std.json.Value, label: []const u8) !void {
    const n = @min(uids.len, 10);
    var list: std.ArrayList(u8) = .empty;
    try list.append(h.arena, '[');
    for (uids[uids.len - n ..], 0..) |u, i| {
        if (i > 0) try list.append(h.arena, ',');
        try list.print(h.arena, "\"{s}\"", .{u.string});
    }
    try list.appendSlice(h.arena, ",\"4294967295\"]");
    const r = try h.call("list_attachments", "{{\"account\":{s},\"directory\":\"INBOX\",\"uids\":{s}}}", .{ acct, list.items });
    var ok = r != null and r.?.array.items.len == n + 1 and r.?.array.items[n] == .null;
    var total: usize = 0;
    if (r) |v| for (v.array.items[0..@min(n, v.array.items.len)]) |item| {
        if (item != .array) {
            ok = false;
            continue;
        }
        for (item.array.items) |a| {
            total += 1;
            const o = a.object;
            const name = (o.get("filename") orelse {
                ok = false;
                continue;
            }).string;
            if (name.len == 0 or name.len > 255 or std.mem.findAny(u8, name, "/\\") != null) ok = false;
            if ((try unicode.clean(h.arena, name)).ptr != name.ptr) ok = false;
            if (o.get("content_type") == null or o.get("size") == null or o.get("inline") == null) ok = false;
        }
    };
    report(ok, "list_attachments on {d} {s} messages: {d} attachments, well-formed and sanitized; null for missing uid", .{ n, label, total });
}

const AppendTo = struct {
    mailbox: [:0]const u8,
    data: []const u8,

    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while appending the itest message";

    pub fn run(self: *AppendTo, s: *Session) !void {
        try s.append(self.mailbox, self.data);
    }
};

/// Best-effort removal of the itest folders and their messages, through the
/// session layer (flag \Deleted + UID EXPUNGE, then DELETE). `boxes` lists
/// children before parents.
const Cleanup = struct {
    arena: std.mem.Allocator,
    boxes: []const [:0]const u8,

    pub fn run(self: *Cleanup, s: *Session) !void {
        for (self.boxes) |b| {
            _ = s.select(b) catch continue;
            const uids = s.uidSearch(self.arena, "ALL") catch continue;
            if (uids.len == 0) continue;
            s.uidStoreFlags(self.arena, uids, true, &.{"\\Deleted"}) catch continue;
            s.uidExpunge(uids) catch {};
        }
        _ = s.examine("INBOX") catch {}; // leave the folder before deleting it
        for (self.boxes) |b| {
            s.delete(b) catch {};
            s.unsubscribe(b) catch {};
        }
    }
};

fn intField(v: ?std.json.Value, key: []const u8) ?i64 {
    const o = v orelse return null;
    if (o != .object) return null;
    const f = o.object.get(key) orelse return null;
    return if (f == .integer) f.integer else null;
}

fn messagesIn(h: Harness, acct: []const u8, box: []const u8) !?i64 {
    const r = try h.call("mailboxes_status", "{{\"account\":{s},\"directory\":\"{s}\"}}", .{ acct, box });
    return intField(r, "MESSAGES");
}

/// ADR 0021 tools on folders this check creates; always cleans up.
fn organizeChecks(h: Harness, reg: *Registry, idx: usize, acct: []const u8, io: std.Io) !void {
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    const a = try h.arena.print("tp-imap-mcp-itest-{x}", .{rnd});
    const b = try h.arena.print("{s}-b", .{a});
    const tag = try h.arena.print("tp-imap-mcp organize itest {x}", .{rnd});
    const delim = organize.delimiterOf(try reg.mailboxList(idx, h.arena, false), "") orelse '/';
    const ab = try h.arena.print("{s}{c}{s}", .{ a, delim, b });
    // Folders this run created, newest (deepest) first; only these are
    // cleaned up, so a pre-existing folder of the same name is never touched.
    var made: std.ArrayList([:0]const u8) = .empty;
    defer {
        var cleanup: Cleanup = .{ .arena = h.arena, .boxes = made.items };
        reg.run(idx, &cleanup) catch {};
        reg.mailboxesChanged(idx, h.arena);
        const left = h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"tp-imap-mcp-itest-*\",\"refresh\":true}}", .{acct}) catch null;
        var gone = left != null;
        if (left) |l| for (l.array.items) |m| {
            if (std.mem.startsWith(u8, m.object.get("PATH").?.string, a)) gone = false;
        };
        report(gone, "organize: test folders removed", .{});
    }

    const ca = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, a });
    if (ca != null) try made.insert(h.arena, 0, try h.arena.dupeSentinel(u8, a, 0));
    const cb = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, b });
    if (cb != null) try made.insert(h.arena, 0, try h.arena.dupeSentinel(u8, b, 0));
    report(ca != null and cb != null, "organize: create_mailbox x2", .{});
    const listed = try h.call("list_mailboxes", "{{\"account\":{s},\"directory\":\"\",\"pattern\":\"{s}*\"}}", .{ acct, a });
    report(listed != null and listed.?.array.items.len == 2, "organize: both folders listed (cache refreshed)", .{});
    const dup = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, a });
    report(dup == null, "organize: creating an existing folder is refused", .{});

    const msg = try h.arena.print("From: itest@example.invalid\r\nTo: itest@example.invalid\r\nSubject: {s}\r\nDate: Thu, 08 Oct 2026 12:00:00 +0000\r\nMessage-ID: <{x}@tp-imap-mcp.invalid>\r\n\r\nTest message; safe to delete.\r\n", .{ tag, rnd });
    var append: AppendTo = .{ .mailbox = try h.arena.dupeSentinel(u8, a, 0), .data = msg };
    reg.run(idx, &append) catch {};
    const in_a = try h.call("search", "{{\"account\":{s},\"directory\":\"{s}\",\"criteria\":\"ALL\"}}", .{ acct, a });
    const uid = if (in_a) |v| (if (v.array.items.len == 1) v.array.items[0].string else null) else null;
    report(uid != null, "organize: test message appended", .{});
    if (uid == null) return;

    const copied = try h.call("copy_messages", "{{\"account\":{s},\"directory\":\"{s}\",\"destination\":\"{s}\",\"uids\":[\"{s}\"]}}", .{ acct, a, b, uid.? });
    const has_map = copied != null and copied.?.object.get("uid_map").? == .array;
    report(intField(copied, "copied") == 1 and has_map, "organize: copy_messages by uid, uid_map present", .{});
    report((try messagesIn(h, acct, b)) == 1 and (try messagesIn(h, acct, a)) == 1, "organize: copy keeps the original", .{});

    const crit = try h.arena.print("SUBJECT \\\"{s}\\\"", .{tag});
    const dry = try h.call("move_messages", "{{\"account\":{s},\"directory\":\"{s}\",\"destination\":\"{s}\",\"criteria\":\"{s}\"}}", .{ acct, b, a, crit });
    report(intField(dry, "matched") == 1 and (try messagesIn(h, acct, b)) == 1, "organize: move by criteria is a dry run by default", .{});
    const moved = try h.call("move_messages", "{{\"account\":{s},\"directory\":\"{s}\",\"destination\":\"{s}\",\"criteria\":\"{s}\",\"dry_run\":false}}", .{ acct, b, a, crit });
    report(intField(moved, "moved") == 1, "organize: move_messages dry_run=false moves", .{});
    report((try messagesIn(h, acct, b)) == 0 and (try messagesIn(h, acct, a)) == 2, "organize: source emptied, destination has both", .{});

    const renamed = try h.call("rename_mailbox", "{{\"account\":{s},\"name\":\"{s}\",\"new_name\":\"{s}\"}}", .{ acct, b, ab });
    report(renamed != null, "organize: rename_mailbox moves a folder under another", .{});
    if (renamed != null) for (made.items) |*m| {
        if (std.mem.eql(u8, m.*, b)) m.* = try h.arena.dupeSentinel(u8, ab, 0);
    };
    const nonempty = try h.call("delete_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, a });
    report(nonempty == null, "organize: delete_mailbox refuses a non-empty folder", .{});
    const inbox = try h.call("rename_mailbox", "{{\"account\":{s},\"name\":\"INBOX\",\"new_name\":\"{s}-inbox\"}}", .{ acct, a });
    report(inbox == null, "organize: INBOX cannot be renamed", .{});
    const deleted = try h.call("delete_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, ab });
    report(deleted != null, "organize: delete_mailbox removes an empty folder", .{});

    try triageChecks(h, reg, idx, acct, a, &made, rnd);
}

fn stringField(v: ?std.json.Value, key: []const u8) ?[]const u8 {
    const o = v orelse return null;
    if (o != .object) return null;
    const f = o.object.get(key) orelse return null;
    return if (f == .string) f.string else null;
}

fn hasFlags(v: ?std.json.Value, uid: []const u8, wanted: []const []const u8) bool {
    const o = v orelse return false;
    if (o != .array or o.array.items.len != 1) return false;
    const flags = o.array.items[0].object.get(uid) orelse return false;
    if (flags != .array) return false;
    for (wanted) |w| {
        for (flags.array.items) |f| {
            if (std.mem.eql(u8, f.string, w)) break;
        } else return false;
    }
    return true;
}

/// ADR 0022 on folder `a`, which holds two test messages: gather, dry run,
/// refused wrong hash, execute (move, flag, keep), and the $TpOrganized skip.
/// Creates `<a>-d` as the move destination (cleaned up with the others).
fn triageChecks(h: Harness, reg: *Registry, idx: usize, acct: []const u8, a: []const u8, made: *std.ArrayList([:0]const u8), rnd: [4]u8) !void {
    const d = try h.arena.print("{s}-d", .{a});
    const cd = try h.call("create_mailbox", "{{\"account\":{s},\"name\":\"{s}\"}}", .{ acct, d });
    if (cd != null) try made.insert(h.arena, 0, try h.arena.dupeSentinel(u8, d, 0));
    const msg = try h.arena.print("From: itest@example.invalid\r\nTo: itest@example.invalid\r\nSubject: tp-imap-mcp triage itest {x}\r\nDate: Thu, 08 Oct 2026 12:00:00 +0000\r\nMessage-ID: <t{x}@tp-imap-mcp.invalid>\r\n\r\nThird test message; safe to delete.\r\n", .{ rnd, rnd });
    var append: AppendTo = .{ .mailbox = try h.arena.dupeSentinel(u8, a, 0), .data = msg };
    reg.run(idx, &append) catch {};

    const gathered = try h.call("organize_mailbox", "{{\"account\":{s},\"directory\":\"{s}\",\"limit\":10}}", .{ acct, a });
    const msgs = if (gathered) |g| g.object.get("messages").?.array.items else &.{};
    report(msgs.len == 3 and stringField(gathered, "instructions") != null, "triage: organize_mailbox lists the 3 test messages with instructions", .{});
    if (msgs.len != 3) return;
    const uv = gathered.?.object.get("uidvalidity").?.integer;
    const first = msgs[0].object.get("uid").?.string;
    const second = msgs[1].object.get("uid").?.string;
    const third = msgs[2].object.get("uid").?.string;
    const actions = try h.arena.print("[{{\"uid\":\"{s}\",\"action\":\"move\",\"destination\":\"{s}\"}},{{\"uid\":\"{s}\",\"action\":\"flag\"}},{{\"uid\":\"{s}\",\"action\":\"keep\"}}]", .{ first, d, second, third });
    const base = "{{\"account\":{s},\"directory\":\"{s}\",\"uidvalidity\":{d},\"actions\":{s}";

    const dry = try h.call("apply_organization", base ++ "}}", .{ acct, a, uv, actions });
    const hash = stringField(dry, "plan_hash");
    report(hash != null and (try messagesIn(h, acct, a)) == 3 and (try messagesIn(h, acct, d)) == 0, "triage: dry run returns a plan_hash and changes nothing", .{});
    if (hash == null) return;
    const wrong = try h.call("apply_organization", base ++ ",\"execute\":true,\"plan_hash\":\"0000000000000000\"}}", .{ acct, a, uv, actions });
    report(wrong == null, "triage: execute with a wrong plan_hash is refused", .{});
    const done = try h.call("apply_organization", base ++ ",\"execute\":true,\"plan_hash\":\"{s}\"}}", .{ acct, a, uv, actions, hash.? });
    report(intField(done, "flagged") == 1 and intField(done, "kept") == 1 and (try messagesIn(h, acct, a)) == 2 and (try messagesIn(h, acct, d)) == 1, "triage: execute moves one, flags one, keeps one", .{});
    const kw = try h.call("get_keywords", "{{\"account\":{s},\"directory\":\"{s}\",\"uids\":[\"{s}\"]}}", .{ acct, a, second });
    report(hasFlags(kw, second, &.{ "\\Flagged", "$TpOrganized" }), "triage: flagged message carries \\Flagged and $TpOrganized", .{});
    const again = try h.call("organize_mailbox", "{{\"account\":{s},\"directory\":\"{s}\",\"limit\":10}}", .{ acct, a });
    report(again != null and again.?.object.get("messages").?.array.items.len == 0, "triage: reviewed messages are skipped next time", .{});
}
