//! MCP tools (spec §6): schemas, argument handling, and handlers.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;

const accounts = @import("accounts.zig");
const body = @import("body.zig");
const desc = @import("descriptions.zig");
const headers = @import("headers.zig");
const listmatch = @import("listmatch.zig");
const filter = @import("filter/rules.zig");
const attachments = @import("attachments.zig");
const unicode = @import("sanitize/unicode.zig");
const limit = @import("sanitize/limit.zig");
const mutf7 = @import("imap/mutf7.zig");
const organize = @import("organize.zig");
const triage = @import("triage.zig");
const imap = @import("imap/session.zig");
const text = @import("text.zig");
const validate = @import("validate.zig");

const Registry = accounts.Registry;
const Session = imap.Session;
const Fetched = imap.Fetched;

pub const Outcome = union(enum) {
    /// Successful result text (JSON, or plain text for whoami).
    content: []const u8,
    /// Tool-level failure: returned as a result with isError: true.
    tool_error: []const u8,
    /// Protocol-level failure: JSON-RPC -32602.
    invalid_params: []const u8,
};

const Failure = error{ InvalidParams, ToolFailed } || Allocator.Error;

const Ctx = struct {
    registry: *Registry,
    arena: Allocator,
    args: ?std.json.ObjectMap,
    problem: []const u8 = "",
    /// Set by `account()`; lets `mailbox()` resolve names via the cache.
    idx: ?usize = null,

    fn invalid(ctx: *Ctx, comptime fmt: []const u8, a: anytype) Failure {
        ctx.problem = try ctx.arena.print(fmt, a);
        return error.InvalidParams;
    }

    fn failed(ctx: *Ctx, comptime fmt: []const u8, a: anytype) Failure {
        ctx.problem = try ctx.arena.print(fmt, a);
        return error.ToolFailed;
    }

    fn get(ctx: *Ctx, key: []const u8) ?std.json.Value {
        const obj = ctx.args orelse return null;
        return obj.get(key);
    }

    fn string(ctx: *Ctx, key: []const u8) Failure![]const u8 {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .string) return ctx.invalid("argument \"{s}\" must be a string", .{key});
        return v.string;
    }

    fn stringOr(ctx: *Ctx, key: []const u8, default: []const u8) Failure![]const u8 {
        if (ctx.get(key) == null) return default;
        return ctx.string(key);
    }

    fn strings(ctx: *Ctx, key: []const u8) Failure![]const []const u8 {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .array) return ctx.invalid("argument \"{s}\" must be an array of strings", .{key});
        const out = try ctx.arena.alloc([]const u8, v.array.items.len);
        for (v.array.items, out) |item, *o| {
            if (item != .string) return ctx.invalid("argument \"{s}\" must be an array of strings", .{key});
            o.* = item.string;
        }
        return out;
    }

    fn booleanOr(ctx: *Ctx, key: []const u8, default: bool) Failure!bool {
        if (ctx.get(key) == null) return default;
        return ctx.boolean(key);
    }

    fn integer(ctx: *Ctx, key: []const u8, min: i64, max: i64) Failure!i64 {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .integer) return ctx.invalid("argument \"{s}\" must be an integer", .{key});
        if (v.integer < min or v.integer > max) return ctx.invalid("argument \"{s}\" must be between {d} and {d}", .{ key, min, max });
        return v.integer;
    }

    fn integerOr(ctx: *Ctx, key: []const u8, default: i64, min: i64, max: i64) Failure!i64 {
        if (ctx.get(key) == null) return default;
        return ctx.integer(key, min, max);
    }

    fn boolean(ctx: *Ctx, key: []const u8) Failure!bool {
        const v = ctx.get(key) orelse return ctx.invalid("missing required argument \"{s}\"", .{key});
        if (v != .bool) return ctx.invalid("argument \"{s}\" must be a boolean", .{key});
        return v.bool;
    }

    fn check(ctx: *Ctx, result: validate.Error!void) Failure!void {
        result catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return ctx.invalid("{s}", .{validate.message(err)}),
        };
    }

    fn uids(ctx: *Ctx) Failure![]u32 {
        const list = try ctx.strings("uids");
        return validate.uids(ctx.arena, list) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return ctx.invalid("{s}", .{validate.message(err)}),
        };
    }

    fn account(ctx: *Ctx) Failure!usize {
        const name = try ctx.string("account");
        if (ctx.registry.find(name)) |idx| {
            ctx.idx = idx;
            return idx;
        }
        var names: std.ArrayList(u8) = .empty;
        for (ctx.registry.accounts, 0..) |a, i| {
            if (i > 0) try names.appendSlice(ctx.arena, ", ");
            try names.appendSlice(ctx.arena, a.name);
        }
        return ctx.failed("unknown account \"{s}\"; configured accounts: {s}", .{ name, names.items });
    }

    fn writable(ctx: *Ctx, idx: usize) Failure!void {
        const a = ctx.registry.accounts[idx];
        if (a.readonly) return ctx.failed("account \"{s}\" is read-only", .{a.name});
    }

    /// UTF-8 mailbox argument -> wire (modified UTF-7), NUL-terminated.
    fn mailbox(ctx: *Ctx, key: []const u8, default: ?[]const u8) Failure![:0]const u8 {
        const utf8 = if (default) |d| try ctx.stringOr(key, d) else try ctx.string(key);
        try ctx.check(validate.mailbox(utf8));
        const encoded = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        // list_mailboxes shows names with invisible characters removed; map
        // such a name back to the real one (fresh cache only, no round trip).
        const boxes = if (ctx.idx) |i| ctx.registry.freshMailboxes(i, ctx.arena) else null;
        const wire = if (boxes) |b| try resolveMailbox(ctx.arena, b, utf8, encoded) else encoded;
        return ctx.arena.dupeSentinel(u8, wire, 0);
    }

    /// Checks the folder arguments `keys` for what needs no server round
    /// trip (NUL, UTF-8), so a malformed call is refused before the LIST.
    /// Missing or non-string values are left to the full parse later.
    fn precheckMailboxes(ctx: *Ctx, keys: []const []const u8) Failure!void {
        for (keys) |key| {
            const v = ctx.get(key) orelse continue;
            if (v != .string) continue;
            try ctx.check(validate.mailbox(v.string));
            if (!std.unicode.utf8ValidateSlice(v.string)) return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key});
        }
    }

    /// A folder name to create or rename to (ADR 0021): validated against
    /// the account's hierarchy delimiter; UTF-8 and wire forms.
    fn folderName(ctx: *Ctx, key: []const u8, delimiter: ?u8) Failure!struct { utf8: []const u8, wire: [:0]const u8 } {
        const utf8 = try ctx.string(key);
        try ctx.check(validate.mailboxName(utf8, delimiter));
        const wire = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        return .{ .utf8 = utf8, .wire = try ctx.arena.dupeSentinel(u8, wire, 0) };
    }

    /// Refuses a `key` argument that resolveMailbox would have to guess:
    /// several folders match it once invisible characters are removed.
    fn unambiguous(ctx: *Ctx, boxes: []const imap.Mailbox, key: []const u8) Failure!void {
        const utf8 = try ctx.string(key);
        const encoded = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        if (try ambiguousMailbox(ctx.arena, boxes, utf8, encoded))
            return ctx.failed("mailbox name \"{s}\" is ambiguous; several folders have this name once invisible characters are removed. Rename them in a mail client first.", .{utf8});
    }

    /// Wire name of the folder create_message appends to (protected).
    fn drafts(ctx: *Ctx, idx: usize) Failure![]const u8 {
        return ctx.registry.drafts(idx, ctx.arena) catch |err| return ctx.imapFailed(err);
    }

    /// The account's mailbox list straight from the server (also refreshes
    /// the cache, so `mailbox()` resolves against it).
    fn freshList(ctx: *Ctx, idx: usize) Failure![]imap.Mailbox {
        return ctx.registry.mailboxList(idx, ctx.arena, true) catch |err| return ctx.imapFailed(err);
    }

    /// Wire name of a folder named in a plan action (UTF-8), resolved like
    /// `mailbox()` against `boxes`.
    fn wireName(ctx: *Ctx, boxes: []const imap.Mailbox, utf8: []const u8) Failure![:0]const u8 {
        try ctx.check(validate.mailbox(utf8));
        const encoded = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("destination \"{s}\" is not valid UTF-8", .{utf8}),
        };
        return ctx.arena.dupeSentinel(u8, try resolveMailbox(ctx.arena, boxes, utf8, encoded), 0);
    }

    /// Runs an IMAP operation; maps failures to a tool error.
    fn imapRun(ctx: *Ctx, idx: usize, op: anytype) Failure!void {
        ctx.registry.run(idx, op) catch |err| return ctx.imapFailed(err);
    }

    fn imapFailed(ctx: *Ctx, err: accounts.Error) Failure {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const d = ctx.registry.diag();
        return ctx.failed("{s}", .{if (d.len > 0) d else @errorName(err)});
    }

    fn json(ctx: *Ctx, value: anytype) Failure![]const u8 {
        return Stringify.valueAlloc(ctx.arena, value, .{});
    }
};

const ParamKind = enum {
    string,
    string_array,
    boolean,
    integer,
    /// apply_organization's `actions`: [{uid, action, destination?}].
    actions,
};

const Param = struct {
    name: []const u8,
    kind: ParamKind,
    description: []const u8,
    default: ?[]const u8 = null,
    required: bool = true,
};

const Tool = struct {
    name: []const u8,
    description: []const u8,
    params: []const Param,
    handler: *const fn (*Ctx) Failure![]const u8,
};

const p_account: Param = .{ .name = "account", .kind = .string, .description = desc.account_param };
const p_directory: Param = .{ .name = "directory", .kind = .string, .description = "Mailbox path, e.g. \"INBOX\" or \"Archives/2024\"" };
const p_uids: Param = .{ .name = "uids", .kind = .string_array, .description = "Message UIDs from search()" };
const p_folder: Param = .{ .name = "name", .kind = .string, .description = "Folder path, e.g. \"Receipts/2026\"" };
const transfer_params = [_]Param{
    p_account,
    .{ .name = "directory", .kind = .string, .description = "Source mailbox, e.g. \"INBOX\"" },
    .{ .name = "destination", .kind = .string, .description = "Destination mailbox, e.g. \"Receipts/2026\"" },
    .{ .name = "uids", .kind = .string_array, .description = "Message UIDs from search(); pass this or criteria", .required = false },
    .{ .name = "criteria", .kind = .string, .description = "IMAP SEARCH criteria selecting the messages; pass this or uids", .required = false },
    .{ .name = "create_missing", .kind = .boolean, .description = "true to create the destination if it does not exist and something matches (default false)", .required = false },
    .{ .name = "dry_run", .kind = .boolean, .description = "true to only report what would happen; default true with criteria, false with uids", .required = false },
};

pub const tools = [_]Tool{
    .{ .name = "list_accounts", .description = desc.list_accounts, .params = &.{}, .handler = listAccounts },
    .{ .name = "whoami", .description = desc.whoami, .params = &.{p_account}, .handler = whoami },
    .{ .name = "list_mailboxes", .description = desc.list_mailboxes, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "Base folder; \"\" for the root" },
        .{ .name = "pattern", .kind = .string, .description = "LIST pattern, e.g. \"*\" or \"Archives%\"" },
        .{ .name = "refresh", .kind = .boolean, .description = "true to bypass the cached mailbox list", .required = false },
    }, .handler = listMailboxes },
    .{ .name = "mailboxes_status", .description = desc.mailboxes_status, .params = &.{
        p_account,
        p_directory,
        .{ .name = "pattern", .kind = .string, .description = "LIST pattern for several folders under directory, e.g. \"*\"; omit for one folder", .required = false },
    }, .handler = mailboxesStatus },
    .{ .name = "search", .description = desc.search, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "Mailbox to search", .default = "INBOX" },
        .{ .name = "criteria", .kind = .string, .description = "IMAP SEARCH criteria", .default = "ALL" },
    }, .handler = search },
    .{ .name = "get_header", .description = desc.get_header, .params = &.{ p_account, p_directory, p_uids }, .handler = getHeader },
    .{ .name = "get_header_field", .description = desc.get_header_field, .params = &.{
        p_account, p_directory, p_uids,
        .{ .name = "field", .kind = .string, .description = "Header field name, e.g. \"Message-ID\"" },
    }, .handler = getHeaderField },
    .{ .name = "get_text", .description = desc.get_text, .params = &.{ p_account, p_directory, p_uids }, .handler = getText },
    .{ .name = "get_html", .description = desc.get_html, .params = &.{ p_account, p_directory, p_uids }, .handler = getHtml },
    .{ .name = "list_attachments", .description = desc.list_attachments, .params = &.{ p_account, p_directory, p_uids }, .handler = listAttachments },
    .{ .name = "get_size", .description = desc.get_size, .params = &.{ p_account, p_directory, p_uids }, .handler = getSize },
    .{ .name = "get_keywords", .description = desc.get_keywords, .params = &.{ p_account, p_directory, p_uids }, .handler = getKeywords },
    .{ .name = "change_keywords", .description = desc.change_keywords, .params = &.{
        p_account, p_directory, p_uids,
        .{ .name = "keywords", .kind = .string_array, .description = "Keywords to add or remove" },
        .{ .name = "set", .kind = .boolean, .description = "true to add, false to remove" },
    }, .handler = changeKeywords },
    .{ .name = "create_message", .description = desc.create_message, .params = &.{
        p_account,
        .{ .name = "content", .kind = .string, .description = "Raw RFC 822 message" },
    }, .handler = createMessage },
    .{ .name = "create_mailbox", .description = desc.create_mailbox, .params = &.{ p_account, p_folder }, .handler = createMailbox },
    .{ .name = "rename_mailbox", .description = desc.rename_mailbox, .params = &.{
        p_account,
        .{ .name = "name", .kind = .string, .description = "Folder to rename, e.g. \"Projects/X\"" },
        .{ .name = "new_name", .kind = .string, .description = "New path; a different parent moves the folder, e.g. \"Archive/2025/X\"" },
    }, .handler = renameMailbox },
    .{ .name = "delete_mailbox", .description = desc.delete_mailbox, .params = &.{ p_account, p_folder }, .handler = deleteMailbox },
    .{ .name = "move_messages", .description = desc.move_messages, .params = &transfer_params, .handler = moveMessages },
    .{ .name = "copy_messages", .description = desc.copy_messages, .params = &transfer_params, .handler = copyMessages },
    .{ .name = "organize_mailbox", .description = desc.organize_mailbox, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "Folder to organize", .default = "INBOX" },
        .{ .name = "limit", .kind = .integer, .description = "Newest messages to return, 1-200 (default 30)", .required = false },
        .{ .name = "criteria", .kind = .string, .description = "Optional IMAP SEARCH criteria narrowing the candidates, e.g. \"UNSEEN\" or \"SINCE 1-Oct-2026\"", .required = false },
        .{ .name = "include_reviewed", .kind = .boolean, .description = "true to include messages an earlier plan kept or flagged ($TpOrganized)", .required = false },
    }, .handler = organizeMailbox },
    .{ .name = "apply_organization", .description = desc.apply_organization, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "The folder passed to organize_mailbox" },
        .{ .name = "uidvalidity", .kind = .integer, .description = "uidvalidity returned by organize_mailbox" },
        .{ .name = "actions", .kind = .actions, .description = "One action per message: move (with destination), delete (to Trash), flag, or keep" },
        .{ .name = "execute", .kind = .boolean, .description = "true to perform the plan; default false (dry run)", .required = false },
        .{ .name = "plan_hash", .kind = .string, .description = "plan_hash from the dry run; required with execute=true", .required = false },
    }, .handler = applyOrganization },
    .{ .name = "clear_cache", .description = desc.clear_cache, .params = &.{p_account}, .handler = clearCache },
};

/// Writes the `tools/list` result array.
pub fn writeList(jw: *Stringify) Stringify.Error!void {
    try jw.beginArray();
    for (tools) |t| {
        try jw.beginObject();
        try jw.objectField("name");
        try jw.write(t.name);
        try jw.objectField("description");
        try jw.write(t.description);
        try jw.objectField("inputSchema");
        try jw.beginObject();
        try jw.objectField("type");
        try jw.write("object");
        try jw.objectField("properties");
        try jw.beginObject();
        for (t.params) |p| {
            try jw.objectField(p.name);
            try jw.beginObject();
            switch (p.kind) {
                .string => {
                    try jw.objectField("type");
                    try jw.write("string");
                },
                .boolean => {
                    try jw.objectField("type");
                    try jw.write("boolean");
                },
                .string_array => {
                    try jw.objectField("type");
                    try jw.write("array");
                    try jw.objectField("items");
                    try jw.write(.{ .type = "string" });
                },
                .integer => {
                    try jw.objectField("type");
                    try jw.write("integer");
                },
                .actions => {
                    try jw.objectField("type");
                    try jw.write("array");
                    try jw.objectField("items");
                    try jw.write(.{
                        .type = "object",
                        .properties = .{
                            .uid = .{ .type = "string" },
                            .action = .{ .type = "string", .@"enum" = [_][]const u8{ "move", "delete", "flag", "keep" } },
                            .destination = .{ .type = "string" },
                        },
                        .required = [_][]const u8{ "uid", "action" },
                    });
                },
            }
            try jw.objectField("description");
            try jw.write(p.description);
            if (p.default) |d| {
                try jw.objectField("default");
                try jw.write(d);
            }
            try jw.endObject();
        }
        try jw.endObject();
        try jw.objectField("required");
        try jw.beginArray();
        for (t.params) |p| if (p.required and p.default == null) try jw.write(p.name);
        try jw.endArray();
        try jw.objectField("additionalProperties");
        try jw.write(false);
        try jw.endObject();
        try jw.endObject();
    }
    try jw.endArray();
}

/// Dispatches `tools/call`. Returns null for an unknown tool name.
pub fn call(registry: *Registry, arena: Allocator, name: []const u8, args: ?std.json.ObjectMap) Allocator.Error!?Outcome {
    for (tools) |t| {
        if (!std.mem.eql(u8, t.name, name)) continue;
        var ctx: Ctx = .{ .registry = registry, .arena = arena, .args = args };
        const result = t.handler(&ctx) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidParams => .{ .invalid_params = ctx.problem },
            error.ToolFailed => .{ .tool_error = ctx.problem },
        };
        return .{ .content = result };
    }
    return null;
}

// ---- handlers -------------------------------------------------------------

fn listAccounts(ctx: *Ctx) Failure![]const u8 {
    const Entry = struct { name: []const u8, login: []const u8, readonly: bool, filters: []const []const u8 };
    const out = try ctx.arena.alloc(Entry, ctx.registry.accounts.len);
    for (ctx.registry.accounts, out, 0..) |a, *e, i| {
        const active = ctx.registry.filtersFor(i);
        const names = try ctx.arena.alloc([]const u8, active.len);
        for (active, names) |f, *n| n.* = f.name;
        e.* = .{ .name = a.name, .login = a.login, .readonly = a.readonly, .filters = names };
    }
    return ctx.json(out);
}

fn whoami(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    return ctx.registry.accounts[idx].login;
}

fn listMailboxes(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const directory = try ctx.string("directory");
    const pattern = try ctx.string("pattern");
    try ctx.check(validate.mailbox(directory));
    try ctx.check(validate.mailbox(pattern));
    const refresh = try ctx.booleanOr("refresh", false);
    const all = ctx.registry.mailboxList(idx, ctx.arena, refresh) catch |err| return ctx.imapFailed(err);

    const Entry = struct { PATH: []const u8, DELIMITER: ?[]const u8, FLAGS: ?[]const []const u8 };
    var out: std.ArrayList(Entry) = .empty;
    for (all) |m| {
        const decoded = mutf7.decode(ctx.arena, m.name) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidMutf7 => try text.sanitizeUtf8(ctx.arena, m.name),
        };
        const path = try unicode.clean(ctx.arena, decoded);
        if (!try listmatch.matches(ctx.arena, path, directory, pattern, m.delimiter)) continue;
        try out.append(ctx.arena, .{
            .PATH = path,
            .DELIMITER = if (m.delimiter) |d| try ctx.arena.dupe(u8, &.{d}) else null,
            .FLAGS = try listedFlags(ctx.arena, m.flags),
        });
    }
    // Absent FLAGS/DELIMITER are left out rather than null: ~600 folders
    // stay near 30 KB (54 KB before).
    return Stringify.valueAlloc(ctx.arena, out.items, .{ .emit_null_optional_fields = false });
}

/// LIST flags worth showing, or null when none are: \HasChildren and
/// \HasNoChildren follow from the paths, \Marked and \Unmarked help no
/// decision, and they made up a third of a large list_mailboxes result.
fn listedFlags(arena: Allocator, flags: []const []const u8) Allocator.Error!?[]const []const u8 {
    const structural = [_][]const u8{ "\\HasChildren", "\\HasNoChildren", "\\Marked", "\\Unmarked" };
    var kept: std.ArrayList([]const u8) = .empty;
    outer: for (flags) |f| {
        for (structural) |s| if (std.ascii.eqlIgnoreCase(f, s)) continue :outer;
        try kept.append(arena, f);
    }
    return if (kept.items.len == 0) null else kept.items;
}

fn mailboxesStatus(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    if (ctx.get("pattern") != null) return foldersStatus(ctx, idx);
    var op: StatusOp = .{ .mailbox = try ctx.mailbox("directory", null) };
    try ctx.imapRun(idx, &op);
    return ctx.json(.{ .MESSAGES = op.result.messages, .RECENT = op.result.recent, .UNSEEN = op.result.unseen });
}

/// Most folders one mailboxes_status call with a pattern reports; keeps the
/// result around 16 KB.
const status_max_folders = 200;

const StatusTarget = struct { path: []const u8, wire: [:0]const u8, selectable: bool };
const StatusTargets = struct { items: []const StatusTarget, omitted: usize };

/// Folders matching `directory` + `pattern` (LIST semantics, as in
/// list_mailboxes), sorted by display path; at most `max`, the rest counted.
fn statusTargets(arena: Allocator, boxes: []const imap.Mailbox, directory: []const u8, pattern: []const u8, max: usize) Allocator.Error!StatusTargets {
    var out: std.ArrayList(StatusTarget) = .empty;
    for (boxes) |m| {
        const path = try displayName(arena, m.name);
        if (!try listmatch.matches(arena, path, directory, pattern, m.delimiter)) continue;
        try out.append(arena, .{ .path = path, .wire = try arena.dupeSentinel(u8, m.name, 0), .selectable = organize.selectable(m) });
    }
    std.mem.sort(StatusTarget, out.items, {}, struct {
        fn lessThan(_: void, x: StatusTarget, y: StatusTarget) bool {
            return std.mem.lessThan(u8, x.path, y.path);
        }
    }.lessThan);
    const n = @min(out.items.len, max);
    return .{ .items = out.items[0..n], .omitted = out.items.len - n };
}

/// mailboxes_status with a pattern: STATUS for every matching folder over
/// one session; a folder the server rejects gets an error, not the call.
fn foldersStatus(ctx: *Ctx, idx: usize) Failure![]const u8 {
    const directory = try ctx.string("directory");
    const pattern = try ctx.string("pattern");
    try ctx.check(validate.mailbox(directory));
    try ctx.check(validate.mailbox(pattern));
    const boxes = try ctx.freshList(idx);
    const targets = try statusTargets(ctx.arena, boxes, directory, pattern, status_max_folders);
    var op: StatusManyOp = .{ .arena = ctx.arena, .targets = targets.items };
    try ctx.imapRun(idx, &op);
    const note: ?[]const u8 = if (targets.omitted == 0) null else try ctx.arena.print("{d} more folders match; narrow directory or pattern to see them", .{targets.omitted});
    // Absent fields are left out rather than null: 200 entries stay small.
    return Stringify.valueAlloc(ctx.arena, .{ .folders = op.result, .omitted = targets.omitted, .note = note }, .{ .emit_null_optional_fields = false });
}

fn search(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", "INBOX");
    const criteria = try ctx.stringOr("criteria", "ALL");
    try ctx.check(validate.criteria(criteria));
    var op: SearchOp = .{
        .arena = ctx.arena,
        .mailbox = mailbox,
        .command = try ctx.arena.printSentinel("CHARSET UTF-8 {s}", .{criteria}, 0),
    };
    try ctx.imapRun(idx, &op);
    std.mem.sort(u32, op.result, {}, std.sort.asc(u32));
    const out = try ctx.arena.alloc([]const u8, op.result.len);
    for (op.result, out) |u, *s| s.* = try ctx.arena.print("{d}", .{u});
    return ctx.json(out);
}

/// Fetches and aligns results to the input UIDs (spec §6.2).
fn fetchAligned(ctx: *Ctx, what: imap.What) Failure!struct { uids: []u32, items: []?*const Fetched } {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: FetchOp = .{ .arena = ctx.arena, .mailbox = mailbox, .uids = uids, .what = what };
    try ctx.imapRun(idx, &op);
    return .{ .uids = uids, .items = try alignToUids(ctx.arena, uids, op.result) };
}

/// Header + size for each UID, from the cache where possible (ADR 0013).
fn fetchHeaders(ctx: *Ctx) Failure!struct { idx: usize, items: []?*const Fetched } {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: CachedHeadersOp = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = uids };
    try ctx.imapRun(idx, &op);
    return .{ .idx = idx, .items = try alignToUids(ctx.arena, uids, op.result) };
}

/// Name of the active filter withholding this message, if any (ADR 0017).
fn withheldBy(arena: Allocator, active: []const *const filter.Filter, raw_header: []const u8) Allocator.Error!?[]const u8 {
    if (active.len == 0) return null;
    return filter.classify(arena, active, try filter.decodeHeaders(arena, raw_header));
}

/// A header value as shown to the model: RFC 2047-decoded, valid UTF-8,
/// invisible characters removed, capped (ADR 0019).
fn displayValue(arena: Allocator, raw: []const u8) Allocator.Error![]const u8 {
    const utf8 = try text.sanitizeUtf8(arena, try imap.decodeHeaderValue(arena, raw));
    return limit.truncate(arena, try unicode.clean(arena, utf8), limit.header_value_max);
}

const HeaderGroups = struct {
    groups: std.array_hash_map.String(std.ArrayList([]const u8)) = .empty,
    size: usize = 0, // bytes of names and values, for the response budget
    omitted: usize = 0, // header lines dropped by the per-item cap
};

/// Display values grouped by name in first-appearance order; for a withheld
/// message only the visible headers.
/// At most `max_bytes` of names and values per message; the rest are counted
/// in `omitted` (one message cannot flood a response).
fn headerGroups(arena: Allocator, hs: []const headers.Header, withheld: ?[]const u8, max_bytes: usize) Allocator.Error!HeaderGroups {
    var out: HeaderGroups = .{};
    for (hs) |h| {
        if (withheld != null and !filter.isVisibleHeader(h.name)) continue;
        if (isOwnMarker(h.name)) continue; // a message must not spoof our markers
        if (out.size >= max_bytes) {
            out.omitted += 1;
            continue;
        }
        const g = try out.groups.getOrPut(arena, h.name);
        if (!g.found_existing) {
            g.value_ptr.* = .empty;
            out.size += limit.jsonLen(h.name);
        }
        const v = try displayValue(arena, h.value);
        try g.value_ptr.append(arena, v);
        out.size += limit.jsonLen(v);
    }
    return out;
}

/// One get_header object, plus the withheld marker header when withheld.
fn writeHeaderObject(jw: *Stringify, hg: HeaderGroups, withheld: ?[]const u8) Failure!void {
    var groups = hg.groups;
    jw.beginObject() catch return error.OutOfMemory;
    var it = groups.iterator();
    while (it.next()) |e| {
        jw.objectField(e.key_ptr.*) catch return error.OutOfMemory;
        jw.write(e.value_ptr.items) catch return error.OutOfMemory;
    }
    if (withheld) |name| {
        jw.objectField("x-tp-imap-mcp-withheld") catch return error.OutOfMemory;
        jw.write(&[_][]const u8{name}) catch return error.OutOfMemory;
    }
    if (hg.omitted > 0) {
        jw.objectField("x-tp-imap-mcp-truncated") catch return error.OutOfMemory;
        var buf: [64]u8 = undefined;
        const note = std.mem.print(&buf, "{d} header lines omitted", .{hg.omitted}) catch unreachable;
        jw.write(&[_][]const u8{note}) catch return error.OutOfMemory;
    }
    jw.endObject() catch return error.OutOfMemory;
}

/// get_header_field values for one message (withheld fields get the marker).
fn headerFieldValues(arena: Allocator, hs: []const headers.Header, field: []const u8, withheld: ?[]const u8) Allocator.Error![]const []const u8 {
    if (withheld) |name| if (!filter.isVisibleHeader(field)) {
        const m = try arena.alloc([]const u8, 1);
        m[0] = try filter.marker(arena, name);
        return m;
    };
    if (isOwnMarker(field)) return &.{};
    var values: std.ArrayList([]const u8) = .empty;
    for (hs) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, field))
            try values.append(arena, try displayValue(arena, h.value));
    }
    return values.items;
}

fn getHeader(ctx: *Ctx) Failure![]const u8 {
    const r = try fetchHeaders(ctx);
    const active = ctx.registry.filtersFor(r.idx);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    jw.beginArray() catch return error.OutOfMemory;
    for (r.items) |maybe| {
        const item = maybe orelse {
            jw.write(null) catch return error.OutOfMemory;
            continue;
        };
        const raw = item.data orelse "";
        const withheld = try withheldBy(ctx.arena, active, raw);
        const hg = try headerGroups(ctx.arena, try headers.parse(ctx.arena, raw), withheld, ctx.registry.settings.max_body_bytes);
        if (admitItem(&budget, hg.size, withheld)) {
            try writeHeaderObject(&jw, hg, withheld);
        } else {
            jw.write(.{ .@"x-tp-imap-mcp-omitted" = .{limit.omitted_reason} }) catch return error.OutOfMemory;
        }
    }
    jw.endArray() catch return error.OutOfMemory;
    return aw.written();
}

fn getHeaderField(ctx: *Ctx) Failure![]const u8 {
    const field = try ctx.string("field");
    try ctx.check(validate.field(field));
    const r = try fetchHeaders(ctx);
    const active = ctx.registry.filtersFor(r.idx);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    const out = try ctx.arena.alloc(?[]const []const u8, r.items.len);
    for (r.items, out) |maybe, *o| {
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        const raw = item.data orelse "";
        const withheld = try withheldBy(ctx.arena, active, raw);
        const values = try headerFieldValues(ctx.arena, try headers.parse(ctx.arena, raw), field, withheld);
        var size: usize = 0;
        for (values) |v| size += limit.jsonLen(v);
        o.* = if (admitItem(&budget, size, withheld)) values else &.{limit.omitted_text};
    }
    return ctx.json(out);
}

fn bodies(ctx: *Ctx, kind: body.Kind) Failure![]const u8 {
    const idx = try ctx.account();
    if (ctx.registry.filtersFor(idx).len > 0) return filteredBodies(ctx, idx, kind);
    const r = try fetchAligned(ctx, .{ .body = true });
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    const out = try ctx.arena.alloc(?[]const u8, r.items.len);
    for (r.items, out) |maybe, *o| {
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        o.* = try renderBudgeted(ctx, item, kind, &budget);
    }
    return ctx.json(out);
}

/// Sanitized body text, or the omission marker once the response budget is
/// spent (sanitization spec §5.2).
fn renderBudgeted(ctx: *Ctx, item: *const Fetched, kind: body.Kind, budget: *limit.Budget) Failure![]const u8 {
    if (budget.exhausted) return limit.omitted_text;
    const rendered = body.render(ctx.arena, item.data orelse "", kind, ctx.registry.settings.max_body_bytes) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return ctx.failed("UID {d}: message could not be parsed as MIME", .{item.uid}),
    };
    return if (budget.admit(limit.jsonLen(rendered))) rendered else limit.omitted_text;
}

/// get_text/get_html with active filters: headers first, classify, then fetch
/// bodies only for messages no filter withholds (ADR 0017).
fn filteredBodies(ctx: *Ctx, idx: usize, kind: body.Kind) Failure![]const u8 {
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: FilteredBodiesOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = uids },
        .active = ctx.registry.filtersFor(idx),
    };
    try ctx.imapRun(idx, &op);
    const items = try alignToUids(ctx.arena, uids, op.bodies);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    const out = try ctx.arena.alloc(?[]const u8, uids.len);
    for (uids, items, out) |u, maybe, *o| {
        if (op.withheld.get(u)) |name| {
            o.* = try filter.marker(ctx.arena, name);
            continue;
        }
        const item = maybe orelse {
            o.* = null;
            continue;
        };
        o.* = try renderBudgeted(ctx, item, kind, &budget);
    }
    return ctx.json(out);
}

fn writeAttachments(jw: *Stringify, atts: []const attachments.Attachment) Stringify.Error!void {
    try jw.beginArray();
    for (atts) |att| try jw.write(.{
        .filename = att.filename,
        .content_type = att.content_type,
        .size = att.size,
        .@"inline" = att.inline_,
    });
    try jw.endArray();
}

fn attachmentsJson(arena: Allocator, atts: []const attachments.Attachment) Allocator.Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    writeAttachments(&jw, atts) catch return error.OutOfMemory;
    return aw.written();
}

fn listAttachments(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    var op: AttachmentsOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = uids },
        .active = ctx.registry.filtersFor(idx),
    };
    try ctx.imapRun(idx, &op);

    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes);
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    jw.beginArray() catch return error.OutOfMemory;
    for (uids) |u| {
        if (op.withheld.get(u)) |name| {
            jw.write(try filter.marker(ctx.arena, name)) catch return error.OutOfMemory;
            continue;
        }
        var leaves: std.ArrayList(attachments.Part) = .empty;
        for (op.parts) |p| if (p.uid == u) try leaves.append(ctx.arena, .{
            .content_type = p.content_type,
            .disposition = p.disposition,
            .params = p.params,
            .disp_params = p.disp_params,
            .size = p.size,
            .base64 = p.base64,
        });
        if (leaves.items.len == 0) {
            jw.write(null) catch return error.OutOfMemory; // no such message
            continue;
        }
        const atts = try attachments.select(ctx.arena, leaves.items);
        var size: usize = 0;
        for (atts) |att| size += limit.jsonLen(att.filename) + limit.jsonLen(att.content_type) + 64;
        if (admitItem(&budget, size, null)) {
            writeAttachments(&jw, atts) catch return error.OutOfMemory;
        } else {
            jw.write(limit.omitted_text) catch return error.OutOfMemory;
        }
    }
    jw.endArray() catch return error.OutOfMemory;
    return aw.written();
}

fn getText(ctx: *Ctx) Failure![]const u8 {
    return bodies(ctx, .plain);
}

fn getHtml(ctx: *Ctx) Failure![]const u8 {
    return bodies(ctx, .html);
}

fn getSize(ctx: *Ctx) Failure![]const u8 {
    const items = (try fetchHeaders(ctx)).items;
    const out = try ctx.arena.alloc(?u32, items.len);
    for (items, out) |maybe, *o| o.* = if (maybe) |item| item.size else null;
    return ctx.json(out);
}

fn keywordsJson(ctx: *Ctx, uids: []const u32, items: []const ?*const Fetched) Failure![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(ctx.arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    jw.beginArray() catch return error.OutOfMemory;
    for (uids, items) |uid, maybe| {
        jw.beginObject() catch return error.OutOfMemory;
        jw.objectField(try ctx.arena.print("{d}", .{uid})) catch return error.OutOfMemory;
        if (maybe) |item| {
            jw.write(item.flags orelse &[_][]const u8{}) catch return error.OutOfMemory;
        } else {
            jw.write(null) catch return error.OutOfMemory;
        }
        jw.endObject() catch return error.OutOfMemory;
    }
    jw.endArray() catch return error.OutOfMemory;
    return aw.written();
}

fn getKeywords(ctx: *Ctx) Failure![]const u8 {
    const r = try fetchAligned(ctx, .{ .flags = true });
    return keywordsJson(ctx, r.uids, r.items);
}

fn changeKeywords(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    const mailbox = try ctx.mailbox("directory", null);
    const uids = try ctx.uids();
    const keywords = try ctx.strings("keywords");
    try ctx.check(validate.keywords(keywords));
    const add = try ctx.boolean("set");
    var op: StoreOp = .{ .arena = ctx.arena, .mailbox = mailbox, .uids = uids, .keywords = keywords, .add = add };
    try ctx.imapRun(idx, &op);
    return keywordsJson(ctx, uids, try alignToUids(ctx.arena, uids, op.result));
}

fn createMessage(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    const content = try ctx.string("content");
    const drafts = ctx.registry.drafts(idx, ctx.arena) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return ctx.failed("{s}", .{ctx.registry.diag()}),
    };
    var op: AppendOp = .{ .mailbox = drafts, .data = try text.toCrlf(ctx.arena, content) };
    try ctx.imapRun(idx, &op);
    return ctx.json(.{ .status = "OK", .data = .{try text.sanitizeUtf8(ctx.arena, op.response)} });
}

/// A wire mailbox name as shown to the model (decoded, cleaned).
fn displayName(arena: Allocator, wire: []const u8) Allocator.Error![]const u8 {
    const decoded = mutf7.decode(arena, wire) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidMutf7 => try text.sanitizeUtf8(arena, wire),
    };
    return unicode.clean(arena, decoded);
}

fn createMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    try ctx.check(validate.mailboxName(try ctx.string("name"), null)); // delimiter rules need the list
    const boxes = try ctx.freshList(idx);
    const d = organize.delimiterOf(boxes, "");
    const name = try ctx.folderName("name", d);
    if (try organize.targetReason(ctx.arena, name.utf8, name.wire, null, d)) |r| return ctx.failed("{s}", .{r});
    if (organize.find(boxes, name.wire) != null) return ctx.failed("mailbox \"{s}\" already exists", .{name.utf8});
    var op: CreateOp = .{ .mailbox = name.wire };
    try ctx.imapRun(idx, &op);
    ctx.registry.mailboxesChanged(idx, ctx.arena);
    return ctx.json(.{ .created = name.utf8, .subscribed = op.subscribed });
}

fn renameMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    try ctx.check(validate.mailboxName(try ctx.string("new_name"), null));
    try ctx.precheckMailboxes(&.{"name"});
    const boxes = try ctx.freshList(idx);
    const from = try ctx.mailbox("name", null);
    try ctx.unambiguous(boxes, "name");
    if (organize.find(boxes, from) == null) return ctx.failed("mailbox \"{s}\" does not exist", .{try displayName(ctx.arena, from)});
    if (try organize.protectedReason(ctx.arena, boxes, from, try ctx.drafts(idx))) |r| return ctx.failed("{s}", .{r});
    const d = organize.delimiterOf(boxes, from);
    const to = try ctx.folderName("new_name", d);
    if (try organize.targetReason(ctx.arena, to.utf8, to.wire, from, d)) |r| return ctx.failed("{s}", .{r});
    if (organize.find(boxes, to.wire) != null) return ctx.failed("mailbox \"{s}\" already exists", .{to.utf8});

    var children: std.ArrayList([2][:0]const u8) = .empty;
    for (boxes) |b| {
        if (!organize.isBelow(b.name, from, d)) continue;
        try children.append(ctx.arena, .{
            try ctx.arena.dupeSentinel(u8, b.name, 0),
            try ctx.arena.printSentinel("{s}{s}", .{ to.wire, b.name[from.len..] }, 0),
        });
    }
    var op: RenameOp = .{ .from = from, .to = to.wire, .children = children.items };
    try ctx.imapRun(idx, &op);
    ctx.registry.mailboxesChanged(idx, ctx.arena);
    const note: ?[]const u8 = if (op.subscribe_failures > 0)
        try ctx.arena.print("could not subscribe {d} renamed folder(s); mail clients that show only subscribed folders may hide them", .{op.subscribe_failures})
    else
        null;
    return ctx.json(.{ .renamed = try displayName(ctx.arena, from), .to = to.utf8, .note = note });
}

fn deleteMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    try ctx.writable(idx);
    try ctx.precheckMailboxes(&.{"name"});
    const boxes = try ctx.freshList(idx);
    const name = try ctx.mailbox("name", null);
    try ctx.unambiguous(boxes, "name");
    const shown = try displayName(ctx.arena, name);
    const box = organize.find(boxes, name) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{shown});
    if (try organize.protectedReason(ctx.arena, boxes, name, try ctx.drafts(idx))) |r| return ctx.failed("{s}", .{r});
    const d = organize.delimiterOf(boxes, name);
    var subfolders: usize = 0;
    for (boxes) |b| {
        if (organize.isBelow(b.name, name, d)) subfolders += 1;
    }
    var op: DeleteOp = .{ .mailbox = name, .selectable = organize.selectable(box), .subfolders = subfolders };
    try ctx.imapRun(idx, &op);
    if (op.refused) return ctx.failed("\"{s}\" is not empty ({d} messages, {d} subfolders); move or delete its contents first", .{ shown, op.messages, subfolders });
    ctx.registry.mailboxesChanged(idx, ctx.arena);
    const note: ?[]const u8 = if (op.unsubscribed) null else "the folder was deleted but could not be unsubscribed";
    return ctx.json(.{ .deleted = shown, .note = note });
}

fn moveMessages(ctx: *Ctx) Failure![]const u8 {
    return transfer(ctx, true);
}

fn copyMessages(ctx: *Ctx) Failure![]const u8 {
    return transfer(ctx, false);
}

const UidPairJson = struct { from: []const u8, to: []const u8 };

/// move_messages / copy_messages (spec §2, §4.2).
fn transfer(ctx: *Ctx, move: bool) Failure![]const u8 {
    const idx = try ctx.account();
    const has_uids = ctx.get("uids") != null;
    const has_criteria = ctx.get("criteria") != null;
    if (organize.selectionProblem(has_uids, has_criteria)) |p| return ctx.invalid("{s}", .{p});
    var given: ?[]const u32 = null;
    var command: [:0]const u8 = "";
    if (has_uids) {
        const u = try ctx.uids();
        if (u.len > organize.max_messages) return ctx.invalid("at most {d} messages per call; got {d} uids", .{ organize.max_messages, u.len });
        given = u;
    } else {
        const criteria = try ctx.string("criteria");
        try ctx.check(validate.criteria(criteria));
        command = try ctx.arena.printSentinel("CHARSET UTF-8 {s}", .{criteria}, 0);
    }
    const dry_run = try ctx.booleanOr("dry_run", has_criteria);
    const create_missing = try ctx.booleanOr("create_missing", false);
    const dest_utf8 = try ctx.string("destination");
    try ctx.check(validate.mailbox(dest_utf8));
    if (!dry_run) try ctx.writable(idx);

    try ctx.precheckMailboxes(&.{"directory"});
    const boxes = try ctx.freshList(idx);
    const source = try ctx.mailbox("directory", null);
    const destination = try ctx.mailbox("destination", null);
    // INBOX matches in any case: "INBOX" and "inbox" are one folder.
    if (organize.sameMailbox(boxes, source, destination)) return ctx.invalid("destination must differ from directory", .{});
    const source_shown = try displayName(ctx.arena, source);
    const src_box = organize.find(boxes, source) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{source_shown});
    if (!organize.selectable(src_box)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{source_shown});
    if (move) if (try organize.moveSourceReason(ctx.arena, src_box)) |r| return ctx.failed("{s}", .{r});
    const dest_box = organize.find(boxes, destination);
    if (dest_box) |b| {
        if (!organize.selectable(b)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{dest_utf8});
    } else {
        if (!create_missing) return ctx.failed("mailbox \"{s}\" does not exist; create it with create_mailbox (or pass create_missing=true)", .{dest_utf8});
        const d = organize.delimiterOf(boxes, destination);
        try ctx.check(validate.mailboxName(dest_utf8, d));
        if (try organize.targetReason(ctx.arena, dest_utf8, destination, null, d)) |r| return ctx.failed("{s}", .{r});
    }
    const dest_shown = if (dest_box != null) try displayName(ctx.arena, destination) else dest_utf8;

    var op: TransferOp = .{
        .arena = ctx.arena,
        .source = source,
        .destination = destination,
        .move = move,
        .dry_run = dry_run,
        .create_destination = dest_box == null,
        .uids = given,
        .command = command,
    };
    ctx.registry.run(idx, &op) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const d = ctx.registry.diag();
        const why = if (d.len > 0) d else @errorName(err);
        const msg = if (op.progress.pending > 0)
            try partialMoveMessage(ctx.arena, op.progress.done, op.matched.len, op.progress.pending, dest_shown, source_shown, why)
        else if (op.progress.done > 0)
            try ctx.arena.print("{d} of {d} messages were {s} before the error: {s}", .{ op.progress.done, op.matched.len, if (move) "moved" else "copied", why })
        else
            try ctx.arena.dupe(u8, why);
        if (op.created) ctx.registry.mailboxesChanged(idx, ctx.arena);
        if (move and op.progress.done > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.matched[0..op.progress.done]);
        return ctx.failed("{s}", .{msg});
    };
    if (op.refused) |r| return ctx.failed("{s}", .{r});
    if (op.matched.len > organize.max_messages and !dry_run)
        return ctx.failed("{d} messages match; at most {d} per call. Narrow the criteria or split the work.", .{ op.matched.len, organize.max_messages });
    if (op.created) ctx.registry.mailboxesChanged(idx, ctx.arena);
    if (move and op.progress.done > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.matched[0..op.progress.done]);
    const note = try organize.transferNote(ctx.arena, organize.destinationNote(dest_box), op.matched.len, dry_run, dest_box == null);

    if (dry_run) {
        const preview = op.matched[0..@min(op.matched.len, organize.dry_run_preview)];
        const strs = try ctx.arena.alloc([]const u8, preview.len);
        for (preview, strs) |u, *o| o.* = try ctx.arena.print("{d}", .{u});
        return ctx.json(.{ .dry_run = true, .matched = op.matched.len, .uids = strs, .source = source_shown, .destination = dest_shown, .note = note });
    }
    var uid_map: ?[]UidPairJson = null;
    var uid_map_omitted: ?usize = null;
    if (op.progress.map_complete and op.progress.pairs.items.len > 0) {
        const preview = organize.uidMapPreview(op.progress.pairs.items);
        const m = try ctx.arena.alloc(UidPairJson, preview.shown.len);
        for (preview.shown, m) |pair, *o| o.* = .{ .from = try ctx.arena.print("{d}", .{pair.from}), .to = try ctx.arena.print("{d}", .{pair.to}) };
        uid_map = m;
        if (preview.omitted > 0) uid_map_omitted = preview.omitted;
    }
    if (move) return ctx.json(.{ .moved = op.progress.done, .source = source_shown, .destination = dest_shown, .uid_map = uid_map, .uid_map_omitted = uid_map_omitted, .note = note });
    return ctx.json(.{ .copied = op.progress.done, .source = source_shown, .destination = dest_shown, .uid_map = uid_map, .uid_map_omitted = uid_map_omitted, .note = note });
}

/// First value of header `name`, decoded and sanitized; "" when absent.
fn firstField(arena: Allocator, hs: []const headers.Header, name: []const u8) Allocator.Error![]const u8 {
    for (hs) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return displayValue(arena, h.value);
    return "";
}

const OrganizeItem = struct {
    uid: []const u8,
    date: []const u8,
    from: []const u8,
    to: ?[]const u8 = null,
    subject: ?[]const u8 = null,
    size: ?u32 = null,
    flags: ?[]const []const u8 = null,
    snippet: ?[]const u8 = null,
    withheld: ?[]const u8 = null,
};

const organize_next = "Classify every message using `instructions`: one action each (move with a destination from `folders`, delete, flag, or keep). Then call apply_organization with execute=false, show the user the grouped plan, and call it again with execute=true and the plan_hash only after the user confirms.";

/// organize_mailbox (spec §2.1): instructions, folders and the newest
/// candidate messages for the model to classify. Read-only.
fn organizeMailbox(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const limit_n: usize = @intCast(try ctx.integerOr("limit", triage.default_limit, 1, triage.max_limit));
    const include_reviewed = try ctx.booleanOr("include_reviewed", false);
    var command: []const u8 = if (include_reviewed) "ALL" else "NOT KEYWORD " ++ triage.reviewed_keyword;
    if (ctx.get("criteria") != null) {
        const criteria = try ctx.string("criteria");
        try ctx.check(validate.criteria(criteria));
        command = try ctx.arena.print("{s} ({s})", .{ command, criteria });
    }
    const instructions = switch (try triage.loadInstructions(ctx.arena, ctx.registry.io, ctx.registry.settings.config_dir, ctx.registry.accounts[idx].name)) {
        .ok => |i| i,
        .problem => |p| return ctx.failed("{s}", .{p}),
    };

    try ctx.precheckMailboxes(&.{"directory"});
    const boxes = try ctx.freshList(idx);
    const mailbox = try ctx.mailbox("directory", "INBOX");
    const shown = try displayName(ctx.arena, mailbox);
    const box = organize.find(boxes, mailbox) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{shown});
    if (!organize.selectable(box)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{shown});

    var op: GatherOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = mailbox, .uids = &.{} },
        .active = ctx.registry.filtersFor(idx),
        .command = try ctx.arena.printSentinel("CHARSET UTF-8 {s}", .{command}, 0),
        .limit = limit_n,
    };
    try ctx.imapRun(idx, &op);

    const choices = try triage.folderChoices(ctx.arena, boxes, mailbox);
    const folders = try ctx.arena.alloc([]const u8, choices.len);
    var fixed: usize = limit.jsonLen(instructions.text) + 512;
    for (choices, folders) |c, *f| {
        f.* = try displayName(ctx.arena, c.name);
        fixed += limit.jsonLen(f.*) + 4;
    }
    const trash: ?[]const u8 = if (triage.trashFolder(boxes)) |t| try displayName(ctx.arena, t.name) else null;

    const header_items = try alignToUids(ctx.arena, op.uids, op.headers.result);
    const flag_items = try alignToUids(ctx.arena, op.uids, op.flags);
    const body_items = try alignToUids(ctx.arena, op.uids, op.bodies);
    var budget: limit.Budget = .init(ctx.registry.settings.max_response_bytes -| fixed);
    var messages: std.ArrayList(OrganizeItem) = .empty;
    var omitted: usize = 0;
    for (op.uids, header_items, flag_items, body_items) |u, h, f, b| {
        const raw = (h orelse continue).data orelse continue; // vanished meanwhile
        const hs = try headers.parse(ctx.arena, raw);
        var item: OrganizeItem = .{
            .uid = try ctx.arena.print("{d}", .{u}),
            .date = try firstField(ctx.arena, hs, "date"),
            .from = try firstField(ctx.arena, hs, "from"),
        };
        if (op.withheld.get(u)) |name| {
            item.withheld = name;
        } else {
            item.to = try firstField(ctx.arena, hs, "to");
            item.subject = try firstField(ctx.arena, hs, "subject");
            item.size = h.?.size;
            item.flags = if (f) |x| x.flags else null;
            const rendered = if (b) |x| body.render(ctx.arena, x.data orelse "", .plain, triage.partial_bytes) catch "" else "";
            item.snippet = try triage.snippet(ctx.arena, rendered);
        }
        const size = limit.jsonLen(item.date) + limit.jsonLen(item.from) + limit.jsonLen(item.to orelse "") +
            limit.jsonLen(item.subject orelse "") + limit.jsonLen(item.snippet orelse "") + 160;
        if (!admitItem(&budget, size, item.withheld)) {
            omitted += 1;
            continue;
        }
        try messages.append(ctx.arena, item);
    }
    return Stringify.valueAlloc(ctx.arena, .{
        .account = ctx.registry.accounts[idx].name,
        .directory = shown,
        .uidvalidity = op.uidvalidity,
        .instructions = instructions.text,
        .instructions_source = instructions.source,
        .folders = folders,
        .trash = trash,
        .messages = messages.items,
        .omitted = omitted,
        .next = organize_next,
    }, .{ .emit_null_optional_fields = false });
}

const PlanMessage = struct { uid: []const u8, from: []const u8, subject: []const u8 };
const PlanGroup = struct { action: []const u8, destination: ?[]const u8 = null, count: usize, messages: ?[]const PlanMessage = null };

/// The dry run's JSON, or null when it exceeds `max` bytes: a plan shown cut
/// off could be confirmed by a user who never saw all of it.
fn dryRunJson(arena: Allocator, hash: [16]u8, groups: []const PlanGroup, missing: []const []const u8, max: usize) Allocator.Error!?[]const u8 {
    const json = try Stringify.valueAlloc(arena, .{ .dry_run = true, .plan_hash = &hash, .groups = groups, .missing = missing }, .{ .emit_null_optional_fields = false });
    return if (json.len > max) null else json;
}

/// apply_organization (spec §2.2): validates the model's plan, shows it as a
/// dry run, or executes it when `execute` and the dry run's plan_hash match.
fn applyOrganization(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    const uidvalidity: u32 = @intCast(try ctx.integer("uidvalidity", 1, std.math.maxInt(u32)));
    const actions = switch (try triage.parseActions(ctx.arena, ctx.get("actions"))) {
        .ok => |a| a,
        .problem => |p| return ctx.invalid("{s}", .{p}),
    };
    const execute = try ctx.booleanOr("execute", false);
    if (execute and ctx.get("plan_hash") == null)
        return ctx.invalid("execute=true needs the plan_hash from a dry run (execute=false)", .{});
    const given_hash = if (execute) try ctx.string("plan_hash") else "";
    if (execute) try ctx.writable(idx);

    try ctx.precheckMailboxes(&.{"directory"});
    const boxes = try ctx.freshList(idx);
    const source = try ctx.mailbox("directory", null);
    const source_shown = try displayName(ctx.arena, source);
    const src_box = organize.find(boxes, source) orelse return ctx.failed("mailbox \"{s}\" does not exist", .{source_shown});
    if (!organize.selectable(src_box)) return ctx.failed("\"{s}\" cannot hold messages (\\Noselect)", .{source_shown});

    const groups = try triage.group(ctx.arena, actions);
    const dests = try ctx.arena.alloc([:0]const u8, groups.len);
    const dests_shown = try ctx.arena.alloc([]const u8, groups.len);
    var moves_out = false;
    for (groups, dests, dests_shown) |g, *d, *ds| {
        d.* = "";
        ds.* = "";
        switch (g.kind) {
            .move => {
                d.* = try ctx.wireName(boxes, g.destination.?);
                if (try triage.destinationProblem(ctx.arena, boxes, source, d.*, g.destination.?)) |p| return ctx.failed("{s}", .{p});
                ds.* = try displayName(ctx.arena, d.*);
                moves_out = true;
            },
            .delete => {
                const t = triage.trashFolder(boxes) orelse
                    return ctx.failed("this account has no Trash folder (\\Trash), so \"delete\" is not available", .{});
                if (organize.sameMailbox(boxes, source, t.name)) return ctx.failed("\"{s}\" is the Trash folder; \"delete\" is not available here", .{source_shown});
                d.* = try ctx.arena.dupeSentinel(u8, t.name, 0);
                ds.* = try displayName(ctx.arena, t.name);
                moves_out = true;
            },
            .flag, .keep => {},
        }
    }
    if (moves_out) if (try organize.moveSourceReason(ctx.arena, src_box)) |r| return ctx.failed("{s}", .{r});

    const uids = try ctx.arena.alloc(u32, actions.len);
    for (actions, uids) |a, *u| u.* = a.uid;
    var op: ApplyOp = .{
        .arena = ctx.arena,
        .headers = .{ .arena = ctx.arena, .registry = ctx.registry, .idx = idx, .mailbox = source, .uids = uids },
        .active = ctx.registry.filtersFor(idx),
        .expected_uidvalidity = uidvalidity,
        .execute = execute,
        .account = ctx.registry.accounts[idx].name,
        .actions = actions,
        .given_hash = given_hash,
        .groups = groups,
        .dests = dests,
        .steps = try executionOrder(ctx.arena, groups),
    };
    ctx.registry.run(idx, &op) catch |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const d = ctx.registry.diag();
        const why = if (d.len > 0) d else @errorName(err);
        const msg = try applyFailureMessage(ctx.arena, &op, dests_shown, source_shown, why);
        if (op.moved.items.len > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.moved.items);
        return ctx.failed("{s}", .{msg});
    };
    if (op.refused) |r| return ctx.failed("{s}", .{r});
    if (op.moved.items.len > 0) ctx.registry.forgetMoved(idx, source, op.uidvalidity, op.moved.items);

    var missing: std.ArrayList([]const u8) = .empty;
    for (uids) |u| if (!op.present.contains(u)) try missing.append(ctx.arena, try ctx.arena.print("{d}", .{u}));

    if (!execute) {
        const header_items = try alignToUids(ctx.arena, uids, op.headers.result);
        const out = try ctx.arena.alloc(PlanGroup, groups.len);
        for (groups, dests_shown, out) |g, ds, *o| {
            var count: usize = 0;
            var listed: std.ArrayList(PlanMessage) = .empty;
            for (g.uids) |u| {
                if (!op.present.contains(u)) continue;
                count += 1;
                if (g.kind == .keep) continue;
                const i = std.mem.findScalar(u32, uids, u).?;
                const hs = try headers.parse(ctx.arena, header_items[i].?.data orelse "");
                try listed.append(ctx.arena, .{
                    .uid = try ctx.arena.print("{d}", .{u}),
                    .from = try firstField(ctx.arena, hs, "from"),
                    .subject = try firstField(ctx.arena, hs, "subject"),
                });
            }
            o.* = .{
                .action = @tagName(g.kind),
                .destination = if (ds.len > 0) ds else null,
                .count = count,
                .messages = if (g.kind == .keep) null else listed.items,
            };
        }
        const max = ctx.registry.settings.max_response_bytes;
        return try dryRunJson(ctx.arena, op.hash, out, missing.items, max) orelse
            ctx.failed("the dry run is larger than the response limit ({d} bytes) and would be shown cut off; split the plan into several apply_organization calls with fewer actions", .{max});
    }

    const Moved = struct { destination: []const u8, count: usize };
    var moved: std.ArrayList(Moved) = .empty;
    var deleted: usize = 0;
    var flagged: usize = 0;
    var kept: usize = 0;
    for (groups, dests_shown, op.counts) |g, ds, n| switch (g.kind) {
        .move => try moved.append(ctx.arena, .{ .destination = ds, .count = n }),
        .delete => deleted = n,
        .flag => flagged = n,
        .keep => kept = n,
    };
    const note: ?[]const u8 = if (op.keyword_refused)
        "the server refused the $TpOrganized keyword; kept and flagged messages will be offered again by organize_mailbox"
    else
        null;
    return Stringify.valueAlloc(ctx.arena, .{
        .executed = true,
        .flagged = flagged,
        .moved = moved.items,
        .deleted = deleted,
        .kept = kept,
        .missing = missing.items,
        .note = note,
    }, .{ .emit_null_optional_fields = false });
}

/// What an interrupted plan did and did not do (spec §2.2).
fn applyFailureMessage(arena: Allocator, op: *const ApplyOp, dests_shown: []const []const u8, source_shown: []const u8, why: []const u8) Allocator.Error![]const u8 {
    var done: std.ArrayList(u8) = .empty;
    var not_done: std.ArrayList(u8) = .empty;
    var at: []const u8 = "";
    for (op.steps, 0..) |gi, step| {
        const label = try stepLabel(arena, op.groups, gi, dests_shown, op.presentCount(op.groups[gi].uids));
        if (step < op.completed) {
            try done.print(arena, "{s}{s}", .{ if (done.items.len > 0) "; " else "", label });
        } else if (step == op.completed) {
            const g = op.groups[gi];
            const total = op.presentCount(g.uids);
            at = if ((g.kind == .move or g.kind == .delete) and op.current.pending > 0)
                try partialMoveMessage(arena, op.current.done, total, op.current.pending, dests_shown[gi], source_shown, why)
            else if (op.current.done > 0)
                try arena.print("{s}: {d} of {d} were moved before the error: {s}", .{ label, op.current.done, total, why })
            else
                try arena.print("{s}: {s}", .{ label, why });
        } else {
            try not_done.print(arena, "{s}{s}", .{ if (not_done.items.len > 0) "; " else "", label });
        }
    }
    if (op.completed >= op.steps.len) at = try arena.print("marking reviewed messages: {s}", .{why});
    return arena.print("the plan stopped at {s}. Completed: {s}. Not attempted: {s}.", .{
        at,
        if (done.items.len > 0) done.items else "nothing",
        if (not_done.items.len > 0) not_done.items else "nothing",
    });
}

fn stepLabel(arena: Allocator, groups: []const triage.Group, gi: usize, dests_shown: []const []const u8, n: usize) Allocator.Error![]const u8 {
    return switch (groups[gi].kind) {
        .move => arena.print("move {d} to \"{s}\"", .{ n, dests_shown[gi] }),
        .delete => arena.print("delete {d} (to \"{s}\")", .{ n, dests_shown[gi] }),
        .flag => arena.print("flag {d}", .{n}),
        .keep => arena.print("keep {d}", .{n}),
    };
}

fn clearCache(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    if (!ctx.registry.clearCache(idx)) return ctx.json(.{ .status = "OK", .note = "caching is disabled for this account" });
    return ctx.json(.{ .status = "OK" });
}

// ---- IMAP operations run through Registry.run --------------------------------

const StatusOp = struct {
    mailbox: [:0]const u8,
    result: imap.Status = undefined,

    pub fn run(self: *StatusOp, s: *Session) accounts.Error!void {
        self.result = try s.status(self.mailbox);
    }
};

const FolderStatus = struct {
    PATH: []const u8,
    MESSAGES: ?u32 = null,
    RECENT: ?u32 = null,
    UNSEEN: ?u32 = null,
    noselect: ?bool = null,
    @"error": ?[]const u8 = null,
};

const StatusManyOp = struct {
    arena: Allocator,
    targets: []const StatusTarget,
    result: []FolderStatus = &.{},

    pub fn run(self: *StatusManyOp, s: *Session) accounts.Error!void {
        const out = try self.arena.alloc(FolderStatus, self.targets.len);
        for (self.targets, out) |t, *o| {
            o.* = .{ .PATH = t.path };
            if (!t.selectable) {
                o.noselect = true;
                continue;
            }
            const st = s.status(t.wire) catch |err| switch (err) {
                error.ServerRejected => {
                    o.@"error" = try unicode.clean(self.arena, try text.sanitizeUtf8(self.arena, s.lastResponse()));
                    continue;
                },
                else => return err,
            };
            o.MESSAGES = st.messages;
            o.RECENT = st.recent;
            o.UNSEEN = st.unseen;
        }
        self.result = out;
    }
};

const SearchOp = struct {
    arena: Allocator,
    mailbox: [:0]const u8,
    command: [:0]const u8,
    result: []u32 = &.{},

    pub fn run(self: *SearchOp, s: *Session) accounts.Error!void {
        _ = try s.examine(self.mailbox);
        self.result = try s.uidSearch(self.arena, self.command);
    }
};

const FetchOp = struct {
    arena: Allocator,
    mailbox: [:0]const u8,
    uids: []const u32,
    what: imap.What,
    result: []Fetched = &.{},

    pub fn run(self: *FetchOp, s: *Session) accounts.Error!void {
        _ = try s.examine(self.mailbox);
        self.result = try s.uidFetch(self.arena, self.uids, self.what);
    }
};

const CachedHeadersOp = struct {
    arena: Allocator,
    registry: *Registry,
    idx: usize,
    mailbox: [:0]const u8,
    uids: []const u32,
    result: []Fetched = &.{},

    pub fn run(self: *CachedHeadersOp, s: *Session) accounts.Error!void {
        try self.afterExamine(s, try s.examine(self.mailbox));
    }

    /// The mailbox is already open; serve from cache, fetch the rest.
    fn afterExamine(self: *CachedHeadersOp, s: *Session, uidvalidity: u32) accounts.Error!void {
        // Without a UIDVALIDITY, cached UIDs cannot be trusted: go live.
        const store = if (uidvalidity != 0) self.registry.cache(self.idx) else null;

        var cached: []Fetched = &.{};
        if (store) |st| {
            if (st.syncUidvalidity(self.mailbox, uidvalidity)) |_| {
                cached = st.getMessages(self.arena, self.mailbox, uidvalidity, self.uids) catch |e| blk: {
                    self.registry.cacheFailed(self.idx, e);
                    break :blk &.{};
                };
            } else |e| self.registry.cacheFailed(self.idx, e);
        }

        // Cached headers outlive expunged messages: confirm the hits still
        // exist (one UID SEARCH) and forget the ones that are gone.
        var gone: []const u32 = &.{};
        if (cached.len > 0) {
            var set: std.ArrayList(u8) = .empty;
            try set.appendSlice(self.arena, "UID ");
            for (cached, 0..) |c, i| try set.print(self.arena, "{s}{d}", .{ if (i > 0) "," else "", c.uid });
            const existing = try s.uidSearch(self.arena, try self.arena.dupeSentinel(u8, set.items, 0));
            const pruned = try pruneCached(self.arena, cached, existing);
            if (pruned.gone.len > 0) if (store) |st|
                st.deleteMessages(self.mailbox, uidvalidity, pruned.gone) catch |e| self.registry.cacheFailed(self.idx, e);
            cached = pruned.kept;
            gone = pruned.gone;
        }

        var missing: std.ArrayList(u32) = .empty;
        for (self.uids) |u| {
            for (cached) |c| {
                if (c.uid == u) break;
            } else for (gone) |g| {
                if (g == u) break; // known expunged: do not refetch
            } else try missing.append(self.arena, u);
        }
        var fetched: []Fetched = &.{};
        if (missing.items.len > 0) {
            fetched = try s.uidFetch(self.arena, missing.items, .{ .header = true, .size = true });
            if (self.registry.cache(self.idx)) |st| if (uidvalidity != 0)
                st.putMessages(self.mailbox, uidvalidity, fetched) catch |e| self.registry.cacheFailed(self.idx, e);
        }
        self.result = try std.mem.concat(self.arena, Fetched, &.{ cached, fetched });
    }
};

const FilteredBodiesOp = struct {
    arena: Allocator,
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    bodies: []Fetched = &.{},
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,

    pub fn run(self: *FilteredBodiesOp, s: *Session) accounts.Error!void {
        // A retry after reconnect starts from scratch.
        self.withheld.clearRetainingCapacity();
        self.bodies = &.{};
        try self.headers.afterExamine(s, try s.examine(self.headers.mailbox));
        const allowed = try classifyForBodies(self.arena, self.active, self.headers.uids, self.headers.result, &self.withheld);
        if (allowed.len > 0)
            self.bodies = try s.uidFetch(self.arena, allowed, .{ .body = true });
    }
};

/// Fail closed: a UID is allowed only if its merged header data was seen and
/// no active filter matches it. Withheld UIDs are recorded in `withheld`.
fn classifyForBodies(
    arena: Allocator,
    active: []const *const filter.Filter,
    uids: []const u32,
    header_results: []const Fetched,
    withheld: *std.AutoHashMapUnmanaged(u32, []const u8),
) Allocator.Error![]const u32 {
    const merged = try alignToUids(arena, uids, header_results);
    var allowed: std.ArrayList(u32) = .empty;
    for (uids, merged) |u, maybe| {
        const item = maybe orelse continue; // no such message
        const data = item.data orelse continue; // headers never arrived: do not fetch
        if (withheld.contains(u)) continue;
        if (try withheldBy(arena, active, data)) |name| {
            try withheld.put(arena, u, name);
        } else {
            for (allowed.items) |x| {
                if (x == u) break;
            } else try allowed.append(arena, u);
        }
    }
    return allowed.items;
}

/// list_attachments: classify by headers first when filters are active (fail
/// closed), then BODYSTRUCTURE for the allowed UIDs only.
const AttachmentsOp = struct {
    arena: Allocator,
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    parts: []imap.BodyPart = &.{},
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,

    pub fn run(self: *AttachmentsOp, s: *Session) accounts.Error!void {
        self.withheld.clearRetainingCapacity();
        self.parts = &.{};
        const uidvalidity = try s.examine(self.headers.mailbox);
        const allowed: []const u32 = if (self.active.len == 0) self.headers.uids else blk: {
            try self.headers.afterExamine(s, uidvalidity);
            break :blk try classifyForBodies(self.arena, self.active, self.headers.uids, self.headers.result, &self.withheld);
        };
        if (allowed.len > 0) self.parts = try s.uidBodyParts(self.arena, allowed);
    }
};

const StoreOp = struct {
    arena: Allocator,
    mailbox: [:0]const u8,
    uids: []const u32,
    keywords: []const []const u8,
    add: bool,
    result: []Fetched = &.{},

    pub fn run(self: *StoreOp, s: *Session) accounts.Error!void {
        _ = try s.select(self.mailbox);
        try s.uidStoreFlags(self.arena, self.uids, self.add, self.keywords);
        self.result = try s.uidFetch(self.arena, self.uids, .{ .flags = true });
    }
};

const AppendOp = struct {
    mailbox: [:0]const u8,
    data: []const u8,
    response: []const u8 = "",

    // APPEND is not idempotent: retrying after a lost connection could save
    // the draft twice.
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while saving the draft; it may or may not have been saved. Check the Drafts folder before retrying.";

    pub fn run(self: *AppendOp, s: *Session) accounts.Error!void {
        try s.append(self.mailbox, self.data);
        self.response = s.lastResponse();
    }
};

/// A SUBSCRIBE-style call whose refusal must not fail the tool (spec §4.4):
/// true on success, false if the server said NO/BAD.
fn bestEffort(result: accounts.Error!void) accounts.Error!bool {
    result catch |err| switch (err) {
        error.ServerRejected => return false,
        else => return err,
    };
    return true;
}

const CreateOp = struct {
    mailbox: [:0]const u8,
    subscribed: bool = false,

    // Not retried: a resent CREATE fails with "already exists" (ADR 0021).
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while creating the mailbox; it may or may not exist now. Check with list_mailboxes (refresh=true) before retrying.";

    pub fn run(self: *CreateOp, s: *Session) accounts.Error!void {
        try s.create(self.mailbox);
        self.subscribed = try bestEffort(s.subscribe(self.mailbox));
    }
};

const RenameOp = struct {
    from: [:0]const u8,
    to: [:0]const u8,
    /// Subfolders (old, new wire names); their subscriptions follow.
    children: []const [2][:0]const u8,
    subscribe_failures: usize = 0,

    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while renaming the mailbox; it may or may not have been renamed. Check with list_mailboxes (refresh=true) before retrying.";

    pub fn run(self: *RenameOp, s: *Session) accounts.Error!void {
        _ = try s.examine("INBOX"); // leave the folder if a move selected it
        try s.rename(self.from, self.to);
        try self.follow(s, self.from, self.to);
        for (self.children) |c| try self.follow(s, c[0], c[1]);
    }

    fn follow(self: *RenameOp, s: *Session, old: [:0]const u8, new: [:0]const u8) accounts.Error!void {
        _ = try bestEffort(s.unsubscribe(old)); // often not subscribed: ignore
        if (!try bestEffort(s.subscribe(new))) self.subscribe_failures += 1;
    }
};

const DeleteOp = struct {
    mailbox: [:0]const u8,
    selectable: bool,
    subfolders: usize,
    messages: u32 = 0,
    refused: bool = false,
    unsubscribed: bool = false,

    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while deleting the mailbox; it may or may not have been deleted. Check with list_mailboxes (refresh=true) before retrying.";

    pub fn run(self: *DeleteOp, s: *Session) accounts.Error!void {
        // Leave the folder if a move selected it: no STATUS or DELETE of the
        // selected mailbox (RFC 3501 6.3.10; some servers refuse).
        _ = try s.examine("INBOX");
        if (self.selectable) self.messages = (try s.status(self.mailbox)).messages;
        if (self.messages > 0 or self.subfolders > 0) {
            self.refused = true;
            return;
        }
        // Unsubscribe first: Gmail drops a deleted label's subscription and
        // then refuses UNSUBSCRIBE. If DELETE fails, subscribe again so the
        // folder stays visible in clients that show subscribed folders only.
        self.unsubscribed = try bestEffort(s.unsubscribe(self.mailbox));
        s.delete(self.mailbox) catch |err| {
            if (self.unsubscribed) _ = bestEffort(s.subscribe(self.mailbox)) catch {};
            return err;
        };
    }
};

const unsupported_move = "the server supports neither MOVE nor UIDPLUS, so messages cannot be moved safely; use copy_messages and remove the originals in your mail client";

const TransferOp = struct {
    arena: Allocator,
    source: [:0]const u8,
    destination: [:0]const u8,
    move: bool,
    dry_run: bool,
    create_destination: bool,
    /// Given UIDs, or null to select by `command` (UID SEARCH arguments).
    uids: ?[]const u32,
    command: [:0]const u8,

    matched: []const u32 = &.{},
    uidvalidity: u32 = 0,
    refused: ?[]const u8 = null,
    created: bool = false,
    /// Messages moved/copied so far: a prefix of `matched`.
    progress: Batches = .{},

    // Not retried: a resent COPY duplicates messages (ADR 0021).
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while moving or copying messages; some may have been moved or copied. Check with search before retrying.";

    pub fn run(self: *TransferOp, s: *Session) accounts.Error!void {
        const acting = !self.dry_run;
        // Checked on dry runs too, so a dry run does not promise a move the
        // server cannot do.
        const strategy: organize.MoveStrategy = if (self.move) organize.moveStrategy(try s.capabilities()) else .move;
        if (strategy == .unsupported) {
            self.refused = unsupported_move;
            return;
        }
        self.uidvalidity = if (self.move and acting) try s.select(self.source) else try s.examine(self.source);
        self.matched = if (self.uids) |given| try existingUids(self.arena, s, given) else blk: {
            const found = try s.uidSearch(self.arena, self.command);
            std.mem.sort(u32, found, {}, std.sort.asc(u32));
            break :blk found;
        };
        if (!acting or self.matched.len > organize.max_messages) return;
        if (self.create_destination and self.matched.len > 0) {
            try s.create(self.destination);
            self.created = true;
            _ = try bestEffort(s.subscribe(self.destination));
        }
        try self.progress.run(self.arena, s, self.matched, self.destination, self.move, strategy);
    }
};

/// Batched UID MOVE (or COPY + \Deleted + UID EXPUNGE under the fallback
/// strategy), or UID COPY when `move` is false, of `uids` from the selected
/// mailbox to `dest` (ADR 0021, spec §4.2). Records how far it got.
const Batches = struct {
    /// Messages moved/copied so far: a prefix of the UIDs passed to `run`.
    done: usize = 0,
    /// Size of the batch the copy+expunge fallback copied but failed to
    /// remove (0 otherwise).
    pending: usize = 0,
    pairs: std.ArrayList(organize.UidPair) = .empty,
    map_complete: bool = true,

    fn run(self: *Batches, arena: Allocator, s: *Session, uids: []const u32, dest: [:0]const u8, move: bool, strategy: organize.MoveStrategy) accounts.Error!void {
        for (0..organize.batchCount(uids.len)) |i| {
            const b = organize.batch(uids, i);
            const cu = try s.uidTransfer(arena, b, dest, move and strategy == .move);
            if (move and strategy == .copy_expunge) {
                s.uidStoreFlags(arena, b, true, &.{"\\Deleted"}) catch |err| {
                    self.pending = b.len;
                    return err;
                };
                s.uidExpunge(b) catch |err| {
                    self.pending = b.len;
                    return err;
                };
            }
            self.done += b.len;
            if (try organize.uidMap(arena, cu)) |m| try self.pairs.appendSlice(arena, m) else self.map_complete = false;
        }
    }
};

/// organize_mailbox's IMAP work: the newest candidates, their headers (cached
/// where possible), flags, and the first bytes of the allowed bodies.
const GatherOp = struct {
    arena: Allocator,
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    /// UID SEARCH arguments.
    command: [:0]const u8,
    limit: usize,

    uidvalidity: u32 = 0,
    /// Newest first, at most `limit`.
    uids: []const u32 = &.{},
    flags: []Fetched = &.{},
    bodies: []Fetched = &.{},
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,

    pub fn run(self: *GatherOp, s: *Session) accounts.Error!void {
        // A retry after reconnect starts from scratch.
        self.withheld.clearRetainingCapacity();
        self.uids = &.{};
        self.flags = &.{};
        self.bodies = &.{};
        self.uidvalidity = try s.examine(self.headers.mailbox);
        const found = try s.uidSearch(self.arena, self.command);
        std.mem.sort(u32, found, {}, std.sort.desc(u32));
        self.uids = found[0..@min(found.len, self.limit)];
        if (self.uids.len == 0) return;
        self.headers.uids = self.uids;
        try self.headers.afterExamine(s, self.uidvalidity);
        self.flags = try s.uidFetch(self.arena, self.uids, .{ .flags = true });
        const allowed = try classifyForBodies(self.arena, self.active, self.uids, self.headers.result, &self.withheld);
        if (allowed.len > 0) self.bodies = try s.uidFetch(self.arena, allowed, .{ .body = true, .partial = true });
    }
};

/// apply_organization's IMAP work (spec §2.2): checks UIDVALIDITY, which UIDs
/// exist and which are withheld; when executing, flags, moves, deletes (to
/// Trash) and marks the reviewed messages, in that order.
const ApplyOp = struct {
    arena: Allocator,
    /// `uids`: every UID in the plan.
    headers: CachedHeadersOp,
    active: []const *const filter.Filter,
    expected_uidvalidity: u32,
    execute: bool,
    groups: []const triage.Group,
    /// Per group: destination wire name (move), the Trash folder (delete), "".
    dests: []const [:0]const u8,
    /// Group indices in execution order (from `executionOrder`).
    steps: []const usize,
    /// For the plan hash, computed once the folder's messages are known.
    account: []const u8,
    actions: []const triage.Action,
    /// The caller's plan_hash (execute only).
    given_hash: []const u8,
    hash: [16]u8 = undefined,

    uidvalidity: u32 = 0,
    refused: ?[]const u8 = null,
    present: std.AutoHashMapUnmanaged(u32, void) = .empty,
    withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty,
    /// Execution steps finished (an index into `order(groups)`).
    completed: usize = 0,
    /// Progress inside the step being executed.
    current: Batches = .{},
    /// Messages moved out of the folder (moves and deletes), for the cache.
    moved: std.ArrayList(u32) = .empty,
    /// Messages acted on per group (present ones).
    counts: []usize = &.{},
    keyword_refused: bool = false,

    // Not retried: a resent MOVE or STORE after a partial run is ambiguous.
    pub const retry_after_connection_loss = false;
    pub const connection_lost_message = "connection lost while applying the plan; part of it may have been done. Run organize_mailbox again to see the current state.";

    pub fn run(self: *ApplyOp, s: *Session) accounts.Error!void {
        self.uidvalidity = if (self.execute) try s.select(self.headers.mailbox) else try s.examine(self.headers.mailbox);
        if (self.uidvalidity != self.expected_uidvalidity) {
            self.refused = "the folder changed since organize_mailbox (UIDVALIDITY differs); run organize_mailbox again";
            return;
        }
        try self.headers.afterExamine(s, self.uidvalidity);
        for (self.headers.result) |f| if (f.data != null) try self.present.put(self.arena, f.uid, {});
        _ = try classifyForBodies(self.arena, self.active, self.headers.uids, self.headers.result, &self.withheld);
        for (self.groups) |g| {
            if (g.kind == .keep) continue;
            for (g.uids) |u| if (self.withheld.get(u)) |name| {
                self.refused = try self.arena.print("message {d} is withheld by filter \"{s}\"; only \"keep\" is allowed", .{ u, name });
                return;
            };
        }
        var missing: std.ArrayList(u32) = .empty;
        for (self.actions) |a| if (!self.present.contains(a.uid)) try missing.append(self.arena, a.uid);
        self.hash = try triage.planHash(self.arena, self.account, self.headers.mailbox, self.expected_uidvalidity, self.actions, missing.items);
        if (self.execute and !std.mem.eql(u8, self.given_hash, &self.hash)) {
            self.refused = "plan_hash does not match these actions or the folder's messages changed since the dry run; run a dry run (execute=false) and show it to the user again";
            return;
        }
        self.counts = try self.arena.alloc(usize, self.groups.len);
        for (self.groups, self.counts) |g, *n| n.* = self.presentCount(g.uids);
        if (!self.execute) return;

        var strategy: organize.MoveStrategy = .move;
        for (self.groups) |g| if (g.kind == .move or g.kind == .delete) {
            strategy = organize.moveStrategy(try s.capabilities());
            break;
        };
        if (strategy == .unsupported) {
            self.refused = unsupported_move;
            return;
        }
        for (self.steps) |gi| {
            const g = self.groups[gi];
            const ids = try self.presentUids(g.uids);
            self.current = .{};
            switch (g.kind) {
                .flag => for (0..organize.batchCount(ids.len)) |i| {
                    try s.uidStoreFlags(self.arena, organize.batch(ids, i), true, &.{"\\Flagged"});
                },
                .move, .delete => {
                    try self.current.run(self.arena, s, ids, self.dests[gi], true, strategy);
                    try self.moved.appendSlice(self.arena, ids);
                },
                .keep => {},
            }
            self.completed += 1;
        }
        var reviewed: std.ArrayList(u32) = .empty;
        for (self.groups) |g| if (g.kind == .flag or g.kind == .keep) try reviewed.appendSlice(self.arena, try self.presentUids(g.uids));
        for (0..organize.batchCount(reviewed.items.len)) |i| {
            s.uidStoreFlags(self.arena, organize.batch(reviewed.items, i), true, &.{triage.reviewed_keyword}) catch |err| switch (err) {
                error.ServerRejected => {
                    self.keyword_refused = true;
                    break;
                },
                else => return err,
            };
        }
    }

    fn presentCount(self: *const ApplyOp, uids: []const u32) usize {
        var n: usize = 0;
        for (uids) |u| {
            if (self.present.contains(u)) n += 1;
        }
        return n;
    }

    fn presentUids(self: *const ApplyOp, uids: []const u32) Allocator.Error![]const u32 {
        var out: std.ArrayList(u32) = .empty;
        for (uids) |u| if (self.present.contains(u)) try out.append(self.arena, u);
        return out.items;
    }
};

/// Group indices in execution order (spec §2.2): flag first, then the moves,
/// then delete, keep last.
fn executionOrder(arena: Allocator, groups: []const triage.Group) Allocator.Error![]const usize {
    var out: std.ArrayList(usize) = .empty;
    for ([_]triage.Kind{ .flag, .move, .delete, .keep }) |k| {
        for (groups, 0..) |g, i| if (g.kind == k) try out.append(arena, i);
    }
    return out.items;
}

/// The given UIDs that exist in the selected mailbox, in input order without
/// duplicates (so counts and UID maps describe real messages).
fn existingUids(arena: Allocator, s: *Session, given: []const u32) accounts.Error![]const u32 {
    var present: std.AutoHashMapUnmanaged(u32, void) = .empty;
    for (0..organize.batchCount(given.len)) |i| {
        for (try s.uidFetch(arena, organize.batch(given, i), .{ .size = true })) |f| try present.put(arena, f.uid, {});
    }
    return keepPresent(arena, given, &present);
}

fn keepPresent(arena: Allocator, given: []const u32, present: *const std.AutoHashMapUnmanaged(u32, void)) Allocator.Error![]const u32 {
    var seen: std.AutoHashMapUnmanaged(u32, void) = .empty;
    var out: std.ArrayList(u32) = .empty;
    for (given) |u| {
        if (!present.contains(u)) continue;
        if ((try seen.getOrPut(arena, u)).found_existing) continue;
        try out.append(arena, u);
    }
    return out.items;
}

/// Response-budget decision for one item; withheld entries are always kept
/// (sanitization spec §5.2).
fn admitItem(budget: *limit.Budget, size: usize, withheld: ?[]const u8) bool {
    if (withheld != null) return true;
    return budget.admit(size);
}

/// True for header names in this server's own `x-tp-imap-mcp-` namespace.
fn isOwnMarker(name: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(name, "x-tp-imap-mcp-");
}

/// Wire name for a `directory` argument: the encoded input when a mailbox has
/// exactly that name; otherwise a mailbox whose decoded name, after
/// invisible-character cleaning, equals the input (what list_mailboxes
/// showed); otherwise the encoded input unchanged.
fn resolveMailbox(arena: Allocator, boxes: []const imap.Mailbox, utf8: []const u8, encoded: []const u8) Allocator.Error![]const u8 {
    for (boxes) |b| if (std.mem.eql(u8, b.name, encoded)) return encoded;
    for (boxes) |b| {
        const decoded = mutf7.decode(arena, b.name) catch continue;
        if (std.mem.eql(u8, try unicode.clean(arena, decoded), utf8)) return b.name;
    }
    return encoded;
}

/// True when no mailbox is named `encoded` exactly but several match `utf8`
/// after invisible-character cleaning (resolveMailbox would pick the first).
fn ambiguousMailbox(arena: Allocator, boxes: []const imap.Mailbox, utf8: []const u8, encoded: []const u8) Allocator.Error!bool {
    for (boxes) |b| if (std.mem.eql(u8, b.name, encoded)) return false;
    var n: usize = 0;
    for (boxes) |b| {
        const decoded = mutf7.decode(arena, b.name) catch continue;
        if (std.mem.eql(u8, try unicode.clean(arena, decoded), utf8)) n += 1;
    }
    return n > 1;
}

/// Error text when the copy+expunge fallback fails at batch k: batches
/// before it were moved, batch k (`pending`) copied but not removed, later
/// ones not touched.
fn partialMoveMessage(arena: Allocator, done: usize, total: usize, pending: usize, destination: []const u8, source: []const u8, why: []const u8) Allocator.Error![]const u8 {
    const rest = total -| (done + pending);
    const untouched = if (rest > 0) try arena.print("; the remaining {d} were not touched", .{rest}) else "";
    return arena.print("{d} of {d} messages were moved; the next {d} were copied to \"{s}\" but not removed from \"{s}\" (they may be flagged \\Deleted){s}: {s}", .{ done, total, pending, destination, source, untouched, why });
}

/// Splits cached entries into those the server still has and the UIDs gone.
fn pruneCached(arena: Allocator, cached: []const Fetched, existing: []const u32) Allocator.Error!struct { kept: []Fetched, gone: []u32 } {
    var kept: std.ArrayList(Fetched) = .empty;
    var gone: std.ArrayList(u32) = .empty;
    for (cached) |c| {
        if (std.mem.findScalar(u32, existing, c.uid) != null) {
            try kept.append(arena, c);
        } else {
            try gone.append(arena, c.uid);
        }
    }
    return .{ .kept = kept.items, .gone = gone.items };
}

/// One entry per input UID (duplicates repeat), null where the server
/// returned nothing for that UID. Several FETCH responses for one UID (e.g.
/// an unsolicited flag update next to the real one) are merged field by field.
pub fn alignToUids(arena: Allocator, uids: []const u32, fetched: []const Fetched) Allocator.Error![]?*const Fetched {
    var by_uid: std.AutoHashMapUnmanaged(u32, *Fetched) = .empty;
    for (fetched) |f| {
        const slot = try by_uid.getOrPut(arena, f.uid);
        if (!slot.found_existing) {
            slot.value_ptr.* = try arena.create(Fetched);
            slot.value_ptr.*.* = f;
            continue;
        }
        const merged = slot.value_ptr.*;
        if (merged.data == null) merged.data = f.data;
        if (merged.flags == null) merged.flags = f.flags;
        if (merged.size == 0) merged.size = f.size;
    }
    const out = try arena.alloc(?*const Fetched, uids.len);
    for (uids, out) |u, *o| o.* = by_uid.get(u);
    return out;
}

const testing = std.testing;
const config = @import("config.zig");

test "alignToUids follows input order, repeats duplicates, nulls missing" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const fetched = [_]Fetched{
        .{ .uid = 3, .size = 30, .data = null, .flags = null },
        .{ .uid = 5, .size = 50, .data = null, .flags = null },
    };
    const out = try alignToUids(arena_state.allocator(), &.{ 5, 4, 3, 5 }, &fetched);
    try testing.expectEqual(50, out[0].?.size);
    try testing.expect(out[1] == null);
    try testing.expectEqual(30, out[2].?.size);
    try testing.expectEqual(50, out[3].?.size);
}

fn testRegistry(accts: []config.Account) !Registry {
    const none = [_][]const *const filter.Filter{ &.{}, &.{} };
    return Registry.init(testing.allocator, testing.io, accts, .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &none);
}

fn testAccounts() [2]config.Account {
    return .{
        .{ .name = "rw", .host = "127.0.0.1", .port = 1, .login = "rw@example.org", .password = @constCast(&[_:0]u8{}), .readonly = false, .drafts = null },
        .{ .name = "ro", .host = "127.0.0.1", .port = 1, .login = "ro@example.org", .password = @constCast(&[_:0]u8{}), .readonly = true, .drafts = null },
    };
}

fn callJson(reg: *Registry, arena: Allocator, name: []const u8, json_args: []const u8) !?Outcome {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, json_args, .{});
    return call(reg, arena, name, v.object);
}

test "listedFlags drops structural flags and keeps the meaningful ones" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expect((try listedFlags(a, &.{ "\\HasChildren", "\\Unmarked" })) == null);
    try testing.expect((try listedFlags(a, &.{ "\\hasnochildren", "\\Marked" })) == null);
    try testing.expect((try listedFlags(a, &.{})) == null);
    const kept = (try listedFlags(a, &.{ "\\HasNoChildren", "\\Trash", "\\Noselect", "\\NonExistent", "$Custom" })).?;
    try testing.expectEqual(4, kept.len);
    try testing.expectEqualStrings("\\Trash", kept[0]);
    try testing.expectEqualStrings("$Custom", kept[3]);
}

test "statusTargets: folders matching directory+pattern, sorted by path, capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const boxes = [_]imap.Mailbox{
        .{ .name = "Reading/Tech", .delimiter = '/', .flags = &.{ "\\Noselect", "\\HasChildren" } },
        .{ .name = "Reading/R&AOk-sum&AOk-s", .delimiter = '/', .flags = &.{} },
        .{ .name = "Reading", .delimiter = '/', .flags = &.{"\\HasChildren"} },
        .{ .name = "INBOX", .delimiter = '/', .flags = &.{} },
        .{ .name = "Readings", .delimiter = '/', .flags = &.{} },
    };
    const all = try statusTargets(a, &boxes, "Reading/", "*", 10);
    try testing.expectEqual(0, all.omitted);
    try testing.expectEqual(2, all.items.len);
    try testing.expectEqualStrings("Reading/R\u{e9}sum\u{e9}s", all.items[0].path);
    try testing.expectEqualStrings("Reading/R&AOk-sum&AOk-s", all.items[0].wire);
    try testing.expect(all.items[0].selectable);
    try testing.expectEqualStrings("Reading/Tech", all.items[1].path);
    try testing.expect(!all.items[1].selectable);

    const capped = try statusTargets(a, &boxes, "", "*", 2);
    try testing.expectEqual(2, capped.items.len);
    try testing.expectEqual(3, capped.omitted);
    try testing.expectEqualStrings("INBOX", capped.items[0].path);
    try testing.expectEqualStrings("Reading", capped.items[1].path);

    try testing.expectEqual(0, (try statusTargets(a, &boxes, "Nope/", "*", 10)).items.len);
}

test "offline tools: list_accounts, whoami" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try testing.expectEqualStrings(
        "[{\"name\":\"rw\",\"login\":\"rw@example.org\",\"readonly\":false,\"filters\":[]},{\"name\":\"ro\",\"login\":\"ro@example.org\",\"readonly\":true,\"filters\":[]}]",
        (try callJson(&reg, a, "list_accounts", "{}")).?.content,
    );
    try testing.expectEqualStrings("ro@example.org", (try callJson(&reg, a, "whoami", "{\"account\":\"RO\"}")).?.content);
    try testing.expect((try callJson(&reg, a, "nope", "{}")) == null);
}

test "errors that never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    try testing.expectEqualStrings(
        "unknown account \"x\"; configured accounts: rw, ro",
        (try callJson(&reg, a, "whoami", "{\"account\":\"x\"}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "account \"ro\" is read-only",
        (try callJson(&reg, a, "create_message", "{\"account\":\"ro\",\"content\":\"x\"}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "account \"ro\" is read-only",
        (try callJson(&reg, a, "change_keywords", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"uids\":[\"1\"],\"keywords\":[\"\\\\Seen\"],\"set\":true}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "missing required argument \"account\"",
        (try callJson(&reg, a, "whoami", "{}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "criteria must not contain CR, LF, or NUL",
        (try callJson(&reg, a, "search", "{\"account\":\"rw\",\"criteria\":\"ALL\\r\\nA1 DELETE INBOX\"}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "each uid must be a decimal string between 1 and 4294967295",
        (try callJson(&reg, a, "get_size", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"uids\":[\"1:*\"]}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "argument \"uids\" must be an array of strings",
        (try callJson(&reg, a, "get_size", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"uids\":\"1\"}")).?.invalid_params,
    );
    try testing.expectEqualStrings(
        "account \"rw\": cannot connect to 127.0.0.1:1",
        (try callJson(&reg, a, "search", "{\"account\":\"rw\"}")).?.tool_error,
    );
}

test "tools/list schema shape" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    const list = parsed.value.array.items;
    try testing.expectEqual(tools.len, list.len);
    const s = list[4].object; // search
    try testing.expectEqualStrings("search", s.get("name").?.string);
    const schema = s.get("inputSchema").?.object;
    try testing.expectEqualStrings("INBOX", schema.get("properties").?.object.get("directory").?.object.get("default").?.string);
    const req = schema.get("required").?.array.items;
    try testing.expectEqual(1, req.len);
    try testing.expectEqualStrings("account", req[0].string);
}

test "alignToUids merges duplicate FETCH responses instead of letting the last win" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    // Real response, then an unsolicited flag update for the same UID.
    const fetched = [_]Fetched{
        .{ .uid = 5, .size = 50, .data = "Subject: x\r\n\r\n", .flags = null },
        .{ .uid = 5, .size = 0, .data = null, .flags = &.{"\\Seen"} },
    };
    const out = try alignToUids(arena_state.allocator(), &.{5}, &fetched);
    try testing.expectEqualStrings("Subject: x\r\n\r\n", out[0].?.data.?);
    try testing.expectEqual(50, out[0].?.size);
    try testing.expectEqualStrings("\\Seen", out[0].?.flags.?[0]);
}

test "list_accounts reports each account's active filters" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    const active = [_][]const *const filter.Filter{ &.{&filter.password_reset}, &.{} };
    reg.active_filters = &active;
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const got = (try callJson(&reg, arena_state.allocator(), "list_accounts", "{}")).?.content;
    try testing.expect(std.mem.find(u8, got, "\"name\":\"rw\",\"login\":\"rw@example.org\",\"readonly\":false,\"filters\":[\"password_reset\"]") != null);
    try testing.expect(std.mem.find(u8, got, "\"readonly\":true,\"filters\":[]") != null);
}

test "withheld message: get_header keeps only date/from plus marker; get_header_field withholds the rest" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const raw = "Date: Tue, 7 Oct 2026 10:00:00 +0000\r\nFrom: GitHub <noreply@github.com>\r\nSubject: =?UTF-8?Q?Reset_your_password?=\r\nX-Code: 482913\r\n\r\n";
    const active = [_]*const filter.Filter{&filter.password_reset};
    const withheld = try withheldBy(a, &active, raw);
    try testing.expectEqualStrings("password_reset", withheld.?);
    try testing.expect((try withheldBy(a, &.{}, raw)) == null);

    const hs = try headers.parse(a, raw);
    var aw: std.Io.Writer.Allocating = .init(a);
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeHeaderObject(&jw, try headerGroups(a, hs, withheld, 32 * 1024), withheld);
    try testing.expectEqualStrings(
        "{\"date\":[\"Tue, 7 Oct 2026 10:00:00 +0000\"],\"from\":[\"GitHub <noreply@github.com>\"],\"x-tp-imap-mcp-withheld\":[\"password_reset\"]}",
        aw.written(),
    );

    try testing.expectEqualStrings("[withheld by filter \"password_reset\"]", (try headerFieldValues(a, hs, "Subject", withheld))[0]);
    try testing.expectEqualStrings("[withheld by filter \"password_reset\"]", (try headerFieldValues(a, hs, "x-code", withheld))[0]);
    try testing.expectEqualStrings("GitHub <noreply@github.com>", (try headerFieldValues(a, hs, "FROM", withheld))[0]);
    // Not withheld: the subject comes back decoded (ADR 0019).
    try testing.expectEqualStrings("Reset your password", (try headerFieldValues(a, hs, "subject", null))[0]);
}

test "header values are decoded, cleaned of invisible characters, and capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // "Invoice\u{200B} due" base64-encoded, with a zero-width space hidden inside.
    try testing.expectEqualStrings("Invoice due", try displayValue(a, "=?UTF-8?B?SW52b2ljZeKAiyBkdWU=?="));
    try testing.expectEqualStrings("plain\u{e9}", try displayValue(a, "plain\u{e9}\u{202E}"));

    var long: std.ArrayList(u8) = .empty;
    try long.appendNTimes(a, 'a', 5000);
    const capped = try displayValue(a, long.items);
    try testing.expect(std.mem.endsWith(u8, capped, "[truncated: 2952 bytes omitted]"));

    const hg = try headerGroups(a, try headers.parse(a, "Subject: =?UTF-8?Q?Hi?=\r\nTo: x@y.z\r\n\r\n"), null, 32 * 1024);
    try testing.expectEqual("subject".len + "Hi".len + "to".len + "x@y.z".len, hg.size);
}

test "review: one get_header item is capped" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var raw: std.ArrayList(u8) = .empty;
    for (0..2000) |i| {
        try raw.print(a, "X-H{d}: ", .{i});
        try raw.appendNTimes(a, 'v', 100);
        try raw.appendSlice(a, "\r\n");
    }
    try raw.appendSlice(a, "\r\n");
    const hg = try headerGroups(a, try headers.parse(a, raw.items), null, 32 * 1024);
    try testing.expect(hg.size <= 32 * 1024 + 4096);
    try testing.expect(hg.omitted > 0);
}

test "review: bodies are fetched only for UIDs whose headers were seen and passed" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const active = [_]*const filter.Filter{&filter.password_reset};
    // UID 42: an unsolicited flags-only FETCH arrives before its real headers.
    const fetched = [_]Fetched{
        .{ .uid = 42, .size = 0, .data = null, .flags = &.{"\\Seen"} },
        .{ .uid = 42, .size = 10, .data = "Subject: Reset your password\r\n\r\n", .flags = null },
        .{ .uid = 7, .size = 10, .data = "Subject: Lunch\r\n\r\n", .flags = null },
        .{ .uid = 9, .size = 0, .data = null, .flags = &.{"\\Seen"} }, // never got headers
    };
    var withheld: std.AutoHashMapUnmanaged(u32, []const u8) = .empty;
    const allowed = try classifyForBodies(a, &active, &.{ 42, 7, 9 }, &fetched, &withheld);
    try testing.expectEqualSlices(u32, &.{7}, allowed);
    try testing.expectEqualStrings("password_reset", withheld.get(42).?);
}

test "todo: create_message's append is never retried after a dropped connection" {
    try testing.expect(!accounts.retriesAfterConnectionLoss(AppendOp));
    try testing.expect(accounts.retriesAfterConnectionLoss(SearchOp));
}

test "todo: a cleaned mailbox name resolves back to its real wire name" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const boxes = [_]imap.Mailbox{
        .{ .name = "INBOX", .delimiter = '/', .flags = &.{} },
        .{ .name = "Fo&IAs-o", .delimiter = '/', .flags = &.{} }, // "Fo\u{200B}o"
    };
    try testing.expectEqualStrings("Fo&IAs-o", try resolveMailbox(a, &boxes, "Foo", "Foo"));
    try testing.expectEqualStrings("INBOX", try resolveMailbox(a, &boxes, "INBOX", "INBOX"));
    try testing.expectEqualStrings("Other", try resolveMailbox(a, &boxes, "Other", "Other"));
}

test "todo: cached hits for expunged UIDs are pruned" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const cached = [_]Fetched{
        .{ .uid = 5, .size = 1, .data = "A: b\r\n\r\n", .flags = null },
        .{ .uid = 6, .size = 1, .data = "A: c\r\n\r\n", .flags = null },
    };
    const r = try pruneCached(a, &cached, &.{6});
    try testing.expectEqual(1, r.kept.len);
    try testing.expectEqual(6, r.kept[0].uid);
    try testing.expectEqualSlices(u32, &.{5}, r.gone);
}

test "todo: message headers cannot spoof x-tp-imap-mcp markers" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const hs = try headers.parse(a, "Subject: hi\r\nX-TP-IMAP-MCP-Withheld: password_reset\r\n\r\n");
    const hg = try headerGroups(a, hs, null, 32 * 1024);
    try testing.expectEqual(1, hg.groups.count());
    try testing.expectEqual(0, (try headerFieldValues(a, hs, "x-tp-imap-mcp-withheld", null)).len);
}

test "todo: withheld entries bypass the response budget" {
    var b: limit.Budget = .init(10);
    try testing.expect(admitItem(&b, 50, null)); // first item always admitted
    try testing.expect(admitItem(&b, 50, "password_reset")); // withheld: kept regardless
    try testing.expect(!admitItem(&b, 50, null));
}

test "todo: list_attachments is offered with account, directory, uids" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    for (parsed.value.array.items) |t| {
        if (!std.mem.eql(u8, t.object.get("name").?.string, "list_attachments")) continue;
        const req = t.object.get("inputSchema").?.object.get("required").?.array.items;
        try testing.expectEqual(3, req.len);
        return;
    }
    return error.TestExpectedTool;
}

test "todo: attachment JSON shape" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const atts = [_]attachments.Attachment{.{ .filename = "a.pdf", .content_type = "application/pdf", .size = 3, .inline_ = false }};
    try testing.expectEqualStrings(
        "[{\"filename\":\"a.pdf\",\"content_type\":\"application/pdf\",\"size\":3,\"inline\":false}]",
        try attachmentsJson(a, &atts),
    );
}

test "organization tools: read-only accounts refuse changes but allow dry runs" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const ro = "account \"ro\" is read-only";
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "create_mailbox", "{\"account\":\"ro\",\"name\":\"X\"}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "rename_mailbox", "{\"account\":\"ro\",\"name\":\"X\",\"new_name\":\"Y\"}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "delete_mailbox", "{\"account\":\"ro\",\"name\":\"X\"}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "move_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"uids\":[\"1\"]}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "copy_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"uids\":[\"1\"]}")).?.tool_error);
    try testing.expectEqualStrings(ro, (try callJson(&reg, a, "move_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"criteria\":\"ALL\",\"dry_run\":false}")).?.tool_error);
    // Criteria default to a dry run, which read-only accounts may do: the
    // call gets as far as the (unreachable) server.
    try testing.expectEqualStrings(
        "account \"ro\": cannot connect to 127.0.0.1:1",
        (try callJson(&reg, a, "move_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"criteria\":\"ALL\"}")).?.tool_error,
    );
    try testing.expectEqualStrings(
        "account \"ro\": cannot connect to 127.0.0.1:1",
        (try callJson(&reg, a, "copy_messages", "{\"account\":\"ro\",\"directory\":\"INBOX\",\"destination\":\"X\",\"uids\":[\"1\"],\"dry_run\":true}")).?.tool_error,
    );
}

test "organization tools: argument errors never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("mailbox name must not be empty", (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"\"}")).?.invalid_params);
    try testing.expectEqualStrings("mailbox name must not contain * or %", (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"All*\"}")).?.invalid_params);
    try testing.expectEqualStrings(
        "mailbox name must be valid UTF-8 without control characters",
        (try callJson(&reg, a, "rename_mailbox", "{\"account\":\"rw\",\"name\":\"X\",\"new_name\":\"Y\\r\\nZ\"}")).?.invalid_params,
    );
    const move = "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"X\"";
    try testing.expectEqualStrings("pass either uids or criteria, not both", (try callJson(&reg, a, "move_messages", move ++ ",\"uids\":[\"1\"],\"criteria\":\"ALL\"}")).?.invalid_params);
    try testing.expectEqualStrings("pass uids (from search) or criteria", (try callJson(&reg, a, "copy_messages", move ++ "}")).?.invalid_params);
    try testing.expectEqualStrings("criteria must not contain CR, LF, or NUL", (try callJson(&reg, a, "move_messages", move ++ ",\"criteria\":\"ALL\\r\\nA1 DELETE INBOX\"}")).?.invalid_params);

    var many: std.ArrayList(u8) = .empty;
    try many.appendSlice(a, move ++ ",\"uids\":[");
    for (1..5002) |i| try many.print(a, "{s}\"{d}\"", .{ if (i > 1) "," else "", i });
    try many.appendSlice(a, "]}");
    try testing.expectEqualStrings("at most 5000 messages per call; got 5001 uids", (try callJson(&reg, a, "move_messages", many.items)).?.invalid_params);
}

test "organization tools: schema requires account, directory, destination" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, aw.written(), .{});
    defer parsed.deinit();
    for (parsed.value.array.items) |t| {
        if (!std.mem.eql(u8, t.object.get("name").?.string, "move_messages")) continue;
        const schema = t.object.get("inputSchema").?.object;
        const req = schema.get("required").?.array.items;
        try testing.expectEqual(3, req.len);
        try testing.expectEqualStrings("destination", req[2].string);
        try testing.expect(schema.get("properties").?.object.get("dry_run") != null);
        return;
    }
    return error.TestExpectedMoveMessages;
}

test "organization operations are never retried after a dropped connection" {
    try testing.expect(!accounts.retriesAfterConnectionLoss(CreateOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(RenameOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(DeleteOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(TransferOp));
}

test "bestEffort tolerates a server refusal only" {
    try testing.expect(try bestEffort({}));
    try testing.expect(!try bestEffort(error.ServerRejected));
    try testing.expectError(error.ConnectionLost, bestEffort(error.ConnectionLost));
}

test "keepPresent keeps existing UIDs in input order without duplicates" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    var present: std.AutoHashMapUnmanaged(u32, void) = .empty;
    for ([_]u32{ 3, 5, 9 }) |u| try present.put(a, u, {});
    try testing.expectEqualSlices(u32, &.{ 9, 3, 5 }, try keepPresent(a, &.{ 9, 4, 3, 9, 5 }, &present));
}

test "review: a failed fallback move says which messages were moved, copied, untouched" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings(
        "500 of 1200 messages were moved; the next 500 were copied to \"Dest\" but not removed from \"Src\" (they may be flagged \\Deleted); the remaining 200 were not touched: STORE failed",
        try partialMoveMessage(a, 500, 1200, 500, "Dest", "Src", "STORE failed"),
    );
    try testing.expectEqualStrings(
        "0 of 3 messages were moved; the next 3 were copied to \"Dest\" but not removed from \"Src\" (they may be flagged \\Deleted): EXPUNGE failed",
        try partialMoveMessage(a, 0, 3, 3, "Dest", "Src", "EXPUNGE failed"),
    );
}

test "review: a name matching several folders after cleaning is ambiguous" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const boxes = [_]imap.Mailbox{
        .{ .name = "INBOX", .delimiter = '/', .flags = &.{} },
        .{ .name = "Fo&IAs-o", .delimiter = '/', .flags = &.{} }, // "Fo\u{200B}o"
        .{ .name = "Fo&IA0-o", .delimiter = '/', .flags = &.{} }, // "Fo\u{200D}o"
        .{ .name = "Ba&IAs-r", .delimiter = '/', .flags = &.{} }, // "Ba\u{200B}r"
    };
    try testing.expect(try ambiguousMailbox(a, &boxes, "Foo", "Foo"));
    try testing.expect(!try ambiguousMailbox(a, &boxes, "Bar", "Bar"));
    try testing.expect(!try ambiguousMailbox(a, &boxes, "Other", "Other"));
    // An exact wire match wins; nothing to disambiguate.
    try testing.expect(!try ambiguousMailbox(a, &boxes, "Fo\u{200B}o", "Fo&IAs-o"));
}

test "review: new folder names with invisible characters never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const msg = "mailbox name must not contain invisible or control characters";
    try testing.expectEqualStrings(msg, (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"INBOX\\u200b\"}")).?.invalid_params);
    try testing.expectEqualStrings(msg, (try callJson(&reg, a, "create_mailbox", "{\"account\":\"rw\",\"name\":\"C1\\u0085\"}")).?.invalid_params);
    try testing.expectEqualStrings(msg, (try callJson(&reg, a, "rename_mailbox", "{\"account\":\"rw\",\"name\":\"X\",\"new_name\":\"Y\\u202e\"}")).?.invalid_params);
}

test "organize tools: argument errors never reach the server" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try testing.expectEqualStrings("argument \"limit\" must be between 1 and 200", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"limit\":0}")).?.invalid_params);
    try testing.expectEqualStrings("argument \"limit\" must be between 1 and 200", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"limit\":201}")).?.invalid_params);
    try testing.expectEqualStrings("argument \"limit\" must be an integer", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"limit\":\"5\"}")).?.invalid_params);
    try testing.expectEqualStrings("criteria must not contain CR, LF, or NUL", (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"rw\",\"criteria\":\"ALL\\r\\nA1 DELETE INBOX\"}")).?.invalid_params);

    const apply = "{\"account\":\"rw\",\"directory\":\"INBOX\",\"uidvalidity\":7";
    try testing.expectEqualStrings("missing required argument \"uidvalidity\"", (try callJson(&reg, a, "apply_organization", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"actions\":[]}")).?.invalid_params);
    try testing.expectEqualStrings("actions must not be empty", (try callJson(&reg, a, "apply_organization", apply ++ ",\"actions\":[]}")).?.invalid_params);
    try testing.expectEqualStrings(
        "execute=true needs the plan_hash from a dry run (execute=false)",
        (try callJson(&reg, a, "apply_organization", apply ++ ",\"actions\":[{\"uid\":\"1\",\"action\":\"keep\"}],\"execute\":true}")).?.invalid_params,
    );
}

test "organize tools: read-only accounts gather and dry-run but never execute" {
    var accts = testAccounts();
    var reg = try testRegistry(&accts);
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const unreachable_ro = "account \"ro\": cannot connect to 127.0.0.1:1";
    try testing.expectEqualStrings(unreachable_ro, (try callJson(&reg, a, "organize_mailbox", "{\"account\":\"ro\"}")).?.tool_error);
    const apply = "{\"account\":\"ro\",\"directory\":\"INBOX\",\"uidvalidity\":7,\"actions\":[{\"uid\":\"1\",\"action\":\"flag\"}]";
    try testing.expectEqualStrings(unreachable_ro, (try callJson(&reg, a, "apply_organization", apply ++ "}")).?.tool_error);
    try testing.expectEqualStrings("account \"ro\" is read-only", (try callJson(&reg, a, "apply_organization", apply ++ ",\"execute\":true,\"plan_hash\":\"0123456789abcdef\"}")).?.tool_error);
}

test "apply_organization runs flag, then moves, then delete, then keep" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const groups = [_]triage.Group{
        .{ .kind = .move, .destination = "A", .uids = &.{1} },
        .{ .kind = .move, .destination = "B", .uids = &.{2} },
        .{ .kind = .delete, .uids = &.{3} },
        .{ .kind = .flag, .uids = &.{4} },
        .{ .kind = .keep, .uids = &.{5} },
    };
    try testing.expectEqualSlices(usize, &.{ 3, 0, 1, 2, 4 }, try executionOrder(a, &groups));
}

test "applyFailureMessage says what was done, where it stopped, and what was not attempted" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const groups = [_]triage.Group{
        .{ .kind = .move, .destination = "Receipts", .uids = &.{ 1, 2, 3 } },
        .{ .kind = .delete, .uids = &.{4} },
        .{ .kind = .flag, .uids = &.{5} },
    };
    var op: ApplyOp = .{
        .arena = a,
        .headers = undefined,
        .active = &.{},
        .expected_uidvalidity = 7,
        .execute = true,
        .groups = &groups,
        .dests = &.{ "Receipts", "Trash", "" },
        .steps = try executionOrder(a, &groups),
        .account = "rw",
        .actions = &.{},
        .given_hash = "",
    };
    for ([_]u32{ 1, 2, 3, 4, 5 }) |u| try op.present.put(a, u, {});
    op.completed = 1; // flag done; stopped in the move
    op.current = .{ .done = 1, .pending = 0 };
    const dests_shown = [_][]const u8{ "Receipts", "Trash", "" };
    try testing.expectEqualStrings(
        "the plan stopped at move 3 to \"Receipts\": 1 of 3 were moved before the error: boom. Completed: flag 1. Not attempted: delete 1 (to \"Trash\").",
        try applyFailureMessage(a, &op, &dests_shown, "INBOX", "boom"),
    );
    op.current = .{ .done = 0, .pending = 2 };
    try testing.expect(std.mem.find(u8, try applyFailureMessage(a, &op, &dests_shown, "INBOX", "boom"), "were copied to \"Receipts\" but not removed from \"INBOX\"") != null);
    op.completed = 3;
    try testing.expectEqualStrings(
        "the plan stopped at marking reviewed messages: boom. Completed: flag 1; move 3 to \"Receipts\"; delete 1 (to \"Trash\"). Not attempted: nothing.",
        try applyFailureMessage(a, &op, &dests_shown, "INBOX", "boom"),
    );
}

test "review: a dry run larger than max_response_bytes is refused, not cut off" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const subject: [2000]u8 = @splat('x');
    var msgs: [100]PlanMessage = undefined;
    for (&msgs, 0..) |*m, i| m.* = .{ .uid = try a.print("{d}", .{i + 1}), .from = "a@example.org", .subject = &subject };
    const groups = [_]PlanGroup{
        .{ .action = "delete", .destination = "Trash", .count = msgs.len, .messages = &msgs },
        .{ .action = "keep", .count = 3 },
    };
    const hash = "0123456789abcdef".*;
    try testing.expect(try dryRunJson(a, hash, &groups, &.{}, 64 * 1024) == null);
    const small = [_]PlanGroup{.{ .action = "delete", .destination = "Trash", .count = 1, .messages = msgs[0..1] }};
    const json = (try dryRunJson(a, hash, &small, &.{"9"}, 64 * 1024)).?;
    try testing.expect(json.len <= 64 * 1024);
    try testing.expect(std.mem.find(u8, json, "\"plan_hash\":\"0123456789abcdef\"") != null);
    try testing.expect(std.mem.find(u8, json, "\"missing\":[\"9\"]") != null);
}

test "apply_organization is never retried (gathering may be); its schema lists the actions" {
    try testing.expect(accounts.retriesAfterConnectionLoss(GatherOp));
    try testing.expect(!accounts.retriesAfterConnectionLoss(ApplyOp));
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    var jw: Stringify = .{ .writer = &aw.writer };
    try writeList(&jw);
    try testing.expect(std.mem.find(u8, aw.written(), "\"enum\":[\"move\",\"delete\",\"flag\",\"keep\"]") != null);
    try testing.expect(std.mem.find(u8, aw.written(), "\"limit\":{\"type\":\"integer\"") != null);
}

// ---- handlers against the in-memory IMAP server (src/imap/fake.zig) -------

const FakeHarness = struct {
    fake: imap.Fake,
    accts: [2]config.Account,
    reg: Registry,
    arena_state: std.heap.ArenaAllocator,

    /// Call `init` on a harness at its final address (the registry points
    /// into it), then add folders to `h.fake`.
    fn init(h: *FakeHarness) !void {
        return h.initCache(null);
    }

    /// Like `init`, with the on-disk cache in `cache_dir` (null: none).
    fn initCache(h: *FakeHarness, cache_dir: ?[]const u8) !void {
        h.fake = .init(testing.allocator);
        h.accts = testAccounts();
        const none = [_][]const *const filter.Filter{ &.{}, &.{} };
        h.reg = try Registry.init(testing.allocator, testing.io, &h.accts, .{ .cache_dir = cache_dir, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file }, &none);
        h.reg.fake = &h.fake;
        h.arena_state = .init(testing.allocator);
        try h.fake.addBox("INBOX", &.{});
    }

    fn deinit(h: *FakeHarness) void {
        h.arena_state.deinit();
        h.reg.deinit();
        h.fake.deinit();
    }

    fn call(h: *FakeHarness, name: []const u8, json_args: []const u8) !Outcome {
        return (try callJson(&h.reg, h.arena_state.allocator(), name, json_args)).?;
    }

    fn obj(h: *FakeHarness, out: Outcome) !std.json.ObjectMap {
        return (try std.json.parseFromSliceLeaky(std.json.Value, h.arena_state.allocator(), out.content, .{})).object;
    }
};

test "fake: move uses COPY + STORE \\Deleted + UID EXPUNGE when MOVE is missing" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    h.fake.caps = .{ .uidplus = true };
    try h.fake.addBox("Archive", &.{});
    try h.fake.addMessages("INBOX", 3);
    const o = try h.obj(try h.call("move_messages", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"Archive\",\"uids\":[\"1\",\"3\"]}"));
    try testing.expectEqual(2, o.get("moved").?.integer);
    try testing.expectEqualSlices(u32, &.{2}, try h.fake.uidsOf("INBOX"));
    try testing.expectEqualSlices(u32, &.{ 1, 2 }, try h.fake.uidsOf("Archive"));
    try testing.expect(h.fake.sawCommand("UID COPY 1,3 Archive"));
    try testing.expect(h.fake.sawCommand("UID STORE 1,3 +FLAGS.SILENT"));
    try testing.expect(h.fake.sawCommand("UID EXPUNGE 1,3"));
    try testing.expect(!h.fake.sawCommand("UID MOVE"));
    try testing.expectEqual(2, o.get("uid_map").?.array.items.len);
}

test "fake: without MOVE or UIDPLUS a move is refused, its dry run too" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    h.fake.caps = .{};
    try h.fake.addBox("Archive", &.{});
    try h.fake.addMessages("INBOX", 2);
    try testing.expectEqualStrings(unsupported_move, (try h.call("move_messages", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"Archive\",\"criteria\":\"ALL\"}")).tool_error);
    try testing.expectEqualStrings(unsupported_move, (try h.call("move_messages", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"Archive\",\"uids\":[\"1\"]}")).tool_error);
    // Copying needs neither.
    const c = try h.obj(try h.call("copy_messages", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"Archive\",\"uids\":[\"1\"]}"));
    try testing.expectEqual(1, c.get("copied").?.integer);
}

test "fake: create_missing creates the destination only when something matches" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    try h.fake.addMessages("INBOX", 1);
    const none = try h.obj(try h.call("move_messages", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"New\",\"uids\":[\"99\"],\"create_missing\":true}"));
    try testing.expectEqual(0, none.get("moved").?.integer);
    try testing.expectEqualStrings("nothing matched, so the destination was not created", none.get("note").?.string);
    try testing.expect(h.fake.box("New") == null);
    try testing.expect(!h.fake.sawCommand("CREATE"));

    const one = try h.obj(try h.call("move_messages", "{\"account\":\"rw\",\"directory\":\"INBOX\",\"destination\":\"New\",\"uids\":[\"1\"],\"create_missing\":true}"));
    try testing.expectEqual(1, one.get("moved").?.integer);
    try testing.expect(h.fake.sawCommand("CREATE New"));
    try testing.expect(h.fake.sawCommand("SUBSCRIBE New"));
    try testing.expectEqualSlices(u32, &.{1}, try h.fake.uidsOf("New"));
}

test "fake: rename carries subfolders and their subscriptions" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    try h.fake.addBox("Projects", &.{});
    try h.fake.addBox("Projects/X", &.{});
    try h.fake.addBox("Projects/X/Y", &.{});
    try h.fake.addBox("Projectsish", &.{});
    const o = try h.obj(try h.call("rename_mailbox", "{\"account\":\"rw\",\"name\":\"Projects\",\"new_name\":\"Archive/Projects\"}"));
    try testing.expectEqualStrings("Archive/Projects", o.get("to").?.string);
    try testing.expect(h.fake.box("Archive/Projects/X/Y") != null);
    try testing.expect(h.fake.box("Projectsish") != null); // a name prefix, not a child
    try testing.expect(h.fake.sawCommand("UNSUBSCRIBE Projects/X/Y"));
    try testing.expect(h.fake.sawCommand("SUBSCRIBE Archive/Projects/X/Y"));
    try testing.expect(!h.fake.sawCommand("SUBSCRIBE Archive/Projectsish"));
}

test "fake: delete unsubscribes before DELETE, so Gmail (which drops the label's subscription) gets no note" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    h.fake.unsubscribe_needs_box = true;
    try h.fake.addBox("Empty", &.{});
    const o = try h.obj(try h.call("delete_mailbox", "{\"account\":\"rw\",\"name\":\"Empty\"}"));
    try testing.expectEqualStrings("Empty", o.get("deleted").?.string);
    try testing.expect(o.get("note").? == .null);
    try testing.expect(commandIndex(&h.fake, "UNSUBSCRIBE Empty").? < commandIndex(&h.fake, "DELETE Empty").?);
}

fn commandIndex(fake: *imap.Fake, line: []const u8) ?usize {
    for (fake.commands.items, 0..) |c, i| if (std.mem.eql(u8, c, line)) return i;
    return null;
}

test "fake: a refused DELETE re-subscribes the folder it unsubscribed" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    try h.fake.addBox("Empty", &.{});
    h.fake.fail = .{ .command = "DELETE", .err = error.ServerRejected, .response = "NO [fake] in use" };
    _ = (try h.call("delete_mailbox", "{\"account\":\"rw\",\"name\":\"Empty\"}")).tool_error;
    try testing.expect(h.fake.box("Empty") != null);
    try testing.expect(commandIndex(&h.fake, "DELETE Empty").? < commandIndex(&h.fake, "SUBSCRIBE Empty").?);
}

test "fake: delete refuses folders with messages or subfolders and deletes empty ones" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    try h.fake.addBox("Full", &.{});
    try h.fake.addMessages("Full", 2);
    try h.fake.addBox("Parent", &.{});
    try h.fake.addBox("Parent/Child", &.{});
    try h.fake.addBox("Empty", &.{});
    try testing.expectEqualStrings("\"Full\" is not empty (2 messages, 0 subfolders); move or delete its contents first", (try h.call("delete_mailbox", "{\"account\":\"rw\",\"name\":\"Full\"}")).tool_error);
    try testing.expectEqualStrings("\"Parent\" is not empty (0 messages, 1 subfolders); move or delete its contents first", (try h.call("delete_mailbox", "{\"account\":\"rw\",\"name\":\"Parent\"}")).tool_error);
    try testing.expect(!h.fake.sawCommand("DELETE"));
    const o = try h.obj(try h.call("delete_mailbox", "{\"account\":\"rw\",\"name\":\"Empty\"}"));
    try testing.expectEqualStrings("Empty", o.get("deleted").?.string);
    try testing.expect(h.fake.box("Empty") == null);
    try testing.expect(h.fake.sawCommand("UNSUBSCRIBE Empty"));
}

test "fake: mailboxes_status with a pattern reports each folder, a rejected one with its error" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    try h.fake.addBox("Reading", &.{"\\Noselect"});
    try h.fake.addBox("Reading/Tech", &.{});
    try h.fake.addBox("Reading/Food", &.{});
    try h.fake.addMessages("Reading/Tech", 3);
    h.fake.fail = .{ .command = "STATUS Reading/Food", .err = error.ServerRejected, .response = "NO Mailbox doesn't exist" };
    const o = try h.obj(try h.call("mailboxes_status", "{\"account\":\"rw\",\"directory\":\"Reading\",\"pattern\":\"*\"}"));
    const folders = o.get("folders").?.array.items;
    try testing.expectEqual(3, folders.len);
    try testing.expectEqualStrings("Reading", folders[0].object.get("PATH").?.string);
    try testing.expect(folders[0].object.get("noselect").?.bool);
    try testing.expectEqualStrings("NO Mailbox doesn't exist", folders[1].object.get("error").?.string);
    try testing.expectEqual(3, folders[2].object.get("MESSAGES").?.integer);
    try testing.expectEqual(3, folders[2].object.get("UNSEEN").?.integer);
    try testing.expectEqual(0, o.get("omitted").?.integer);
}

test "fake: the cached folder list follows a rename, and goes stale when the connection drops mid-change" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(testing.io, &dir_buf)];
    var h: FakeHarness = undefined;
    try h.initCache(dir);
    defer h.deinit();
    try h.fake.addBox("Projects", &.{});
    try h.fake.addBox("Old", &.{});
    const a = h.arena_state.allocator();

    // Success: the list is refreshed with the new name (mailboxesChanged).
    _ = try h.call("list_mailboxes", "{\"account\":\"rw\",\"directory\":\"\",\"pattern\":\"*\"}");
    _ = (try h.call("rename_mailbox", "{\"account\":\"rw\",\"name\":\"Projects\",\"new_name\":\"Done\"}")).content;
    const after = h.reg.freshMailboxes(0, a).?;
    try testing.expect(organize.find(after, "Done") != null);
    try testing.expect(organize.find(after, "Projects") == null);

    // A dropped connection: the folder may or may not have been renamed, so
    // the cached list must not be trusted.
    h.fake.fail = .{ .command = "RENAME Old", .err = error.ConnectionLost };
    const lost = (try h.call("rename_mailbox", "{\"account\":\"rw\",\"name\":\"Old\",\"new_name\":\"Older\"}")).tool_error;
    try testing.expect(std.mem.find(u8, lost, "connection lost while renaming") != null);
    try testing.expect(h.reg.freshMailboxes(0, a) == null);

    // Same for create and delete.
    _ = try h.call("list_mailboxes", "{\"account\":\"rw\",\"directory\":\"\",\"pattern\":\"*\",\"refresh\":true}");
    try testing.expect(h.reg.freshMailboxes(0, a) != null);
    h.fake.fail = .{ .command = "CREATE", .err = error.ConnectionLost };
    _ = (try h.call("create_mailbox", "{\"account\":\"rw\",\"name\":\"New\"}")).tool_error;
    try testing.expect(h.reg.freshMailboxes(0, a) == null);

    _ = try h.call("list_mailboxes", "{\"account\":\"rw\",\"directory\":\"\",\"pattern\":\"*\",\"refresh\":true}");
    h.fake.fail = .{ .command = "DELETE", .err = error.ConnectionLost };
    _ = (try h.call("delete_mailbox", "{\"account\":\"rw\",\"name\":\"Done\"}")).tool_error;
    try testing.expect(h.reg.freshMailboxes(0, a) == null);
}

test "fake: malformed folder arguments are refused before any LIST" {
    var h: FakeHarness = undefined;
    try h.init();
    defer h.deinit();
    const calls = [_][2][]const u8{
        .{ "rename_mailbox", "{\"account\":\"rw\",\"name\":\"Pro\\u0000jects\",\"new_name\":\"X\"}" },
        .{ "delete_mailbox", "{\"account\":\"rw\",\"name\":\"Old\\u0000\"}" },
        .{ "move_messages", "{\"account\":\"rw\",\"directory\":\"IN\\u0000BOX\",\"destination\":\"X\",\"uids\":[\"1\"]}" },
        .{ "copy_messages", "{\"account\":\"rw\",\"directory\":\"IN\\u0000BOX\",\"destination\":\"X\",\"uids\":[\"1\"]}" },
        .{ "organize_mailbox", "{\"account\":\"rw\",\"directory\":\"IN\\u0000BOX\"}" },
        .{ "apply_organization", "{\"account\":\"rw\",\"directory\":\"IN\\u0000BOX\",\"uidvalidity\":7,\"actions\":[{\"uid\":\"1\",\"action\":\"keep\"}]}" },
    };
    for (calls) |c| {
        const out = try h.call(c[0], c[1]);
        if (out != .invalid_params) {
            std.debug.print("{s} was not refused as invalid params\n", .{c[0]});
            return error.TestUnexpectedResult;
        }
    }
    try testing.expectEqual(0, h.fake.commands.items.len);
}
