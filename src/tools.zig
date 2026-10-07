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
const unicode = @import("sanitize/unicode.zig");
const limit = @import("sanitize/limit.zig");
const mutf7 = @import("imap/mutf7.zig");
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
        if (ctx.registry.find(name)) |idx| return idx;
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
        const wire = mutf7.encode(ctx.arena, utf8) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidUtf8 => return ctx.invalid("argument \"{s}\" is not valid UTF-8", .{key}),
        };
        return ctx.arena.dupeSentinel(u8, wire, 0);
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

const ParamKind = enum { string, string_array, boolean };

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

pub const tools = [_]Tool{
    .{ .name = "list_accounts", .description = desc.list_accounts, .params = &.{}, .handler = listAccounts },
    .{ .name = "whoami", .description = desc.whoami, .params = &.{p_account}, .handler = whoami },
    .{ .name = "list_mailboxes", .description = desc.list_mailboxes, .params = &.{
        p_account,
        .{ .name = "directory", .kind = .string, .description = "Base folder; \"\" for the root" },
        .{ .name = "pattern", .kind = .string, .description = "LIST pattern, e.g. \"*\" or \"Archives%\"" },
        .{ .name = "refresh", .kind = .boolean, .description = "true to bypass the cached mailbox list", .required = false },
    }, .handler = listMailboxes },
    .{ .name = "mailboxes_status", .description = desc.mailboxes_status, .params = &.{ p_account, p_directory }, .handler = mailboxesStatus },
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

    const Entry = struct { PATH: []const u8, DELIMITER: ?[]const u8, FLAGS: []const []const u8 };
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
            .FLAGS = m.flags,
        });
    }
    return ctx.json(out.items);
}

fn mailboxesStatus(ctx: *Ctx) Failure![]const u8 {
    const idx = try ctx.account();
    var op: StatusOp = .{ .mailbox = try ctx.mailbox("directory", null) };
    try ctx.imapRun(idx, &op);
    return ctx.json(.{ .MESSAGES = op.result.messages, .RECENT = op.result.recent, .UNSEEN = op.result.unseen });
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
        if (out.size >= max_bytes) {
            out.omitted += 1;
            continue;
        }
        const g = try out.groups.getOrPut(arena, h.name);
        if (!g.found_existing) {
            g.value_ptr.* = .empty;
            out.size += h.name.len;
        }
        const v = try displayValue(arena, h.value);
        try g.value_ptr.append(arena, v);
        out.size += v.len;
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
        if (budget.admit(hg.size)) {
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
        const values = try headerFieldValues(ctx.arena, try headers.parse(ctx.arena, raw), field, try withheldBy(ctx.arena, active, raw));
        var size: usize = 0;
        for (values) |v| size += v.len;
        o.* = if (budget.admit(size)) values else &.{limit.omitted_text};
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
    return if (budget.admit(rendered.len)) rendered else limit.omitted_text;
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

        var missing: std.ArrayList(u32) = .empty;
        for (self.uids) |u| {
            for (cached) |c| {
                if (c.uid == u) break;
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

    pub fn run(self: *AppendOp, s: *Session) accounts.Error!void {
        try s.append(self.mailbox, self.data);
        self.response = s.lastResponse();
    }
};

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
    return Registry.init(testing.allocator, accts, .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = config.default_ca_file });
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
