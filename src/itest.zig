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
    var reg: Registry = try .init(init.gpa, accounts, settings);
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
