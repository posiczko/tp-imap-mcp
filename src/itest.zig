//! Live integration checks against a real IMAP account (spec §9).
//!
//!   op run --env-file imap.env -- zig build itest -- <account> [--write <scratch-mailbox>]
//!
//! Read-only by default. Prints only counts and shapes, never message content.
//! Uses a throwaway cache in .zig-cache/itest-cache, never ~/.cache.
//! `--write` adds then removes the keyword $TpImapMcpTest on the newest
//! message of <scratch-mailbox>; use a folder you do not care about.

const std = @import("std");
const config = @import("config.zig");
const tools = @import("tools.zig");
const c = @import("imap/c.zig");
const Registry = @import("accounts.zig").Registry;
const filter = @import("filter/rules.zig");
const unicode = @import("sanitize/unicode.zig");

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
        std.debug.print("usage: itest <account> [--write <scratch-mailbox>]\n", .{});
        return 2;
    }
    const account = args[1];
    const write_box: ?[]const u8 = if (args.len >= 4 and std.mem.eql(u8, args[2], "--write")) args[3] else null;

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
    var reg: Registry = try .init(init.gpa, accounts, settings, no_filters);
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
        try filterChecks(h, &reg, idx, acct, set);
    }

    if (write_box) |box| try writeChecks(h, acct, box);

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
