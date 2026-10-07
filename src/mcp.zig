//! MCP over stdio: newline-delimited JSON-RPC 2.0 (spec §3, §8).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Stringify = std.json.Stringify;

const Registry = @import("accounts.zig").Registry;
const prompts = @import("prompts.zig");
const text_util = @import("text.zig");
const tools = @import("tools.zig");

pub const server_name = "tp-imap-mcp";
pub const server_version = "0.1.0";

/// Newest first; the first entry is offered when the client asks for an
/// unknown version.
const protocol_versions = [_][]const u8{ "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05" };

const parse_error = -32700;
const invalid_request = -32600;
const method_not_found = -32601;
const invalid_params = -32602;

/// Serves requests until `in` reaches EOF. Each request gets a fresh arena.
pub fn serve(gpa: Allocator, registry: *Registry, in: *std.Io.Reader, out: *std.Io.Writer) !void {
    var line: std.Io.Writer.Allocating = .init(gpa);
    defer line.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();

    while (true) {
        line.clearRetainingCapacity();
        const at_eof = if (in.streamDelimiter(&line.writer, '\n')) |_| blk: {
            in.toss(1); // the '\n'
            break :blk false;
        } else |err| switch (err) {
            error.EndOfStream => true, // final line without '\n' is still handled
            else => return err,
        };

        const msg = std.mem.trim(u8, line.written(), " \t\r");
        if (msg.len > 0) {
            _ = arena_state.reset(.retain_capacity);
            if (try handle(arena_state.allocator(), registry, msg)) |response| {
                try out.writeAll(response);
                try out.writeByte('\n');
                try out.flush();
            }
        }
        if (at_eof) return;
    }
}

/// Returns the serialized response, or null for notifications.
pub fn handle(arena: Allocator, registry: *Registry, msg: []const u8) Allocator.Error!?[]const u8 {
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, msg, .{}) catch
        return try errorResponse(arena, .null, parse_error, "parse error");
    if (root != .object) return try errorResponse(arena, .null, invalid_request, "request must be a JSON object");
    const req = root.object;
    const id = req.get("id");
    const method_v = req.get("method") orelse
        return if (id) |i| try errorResponse(arena, i, invalid_request, "missing method") else null;
    if (method_v != .string)
        return if (id) |i| try errorResponse(arena, i, invalid_request, "method must be a string") else null;
    const method = method_v.string;
    const params: ?std.json.ObjectMap = if (req.get("params")) |p| (if (p == .object) p.object else null) else null;

    // Notifications (no id) never get a response.
    const rid = id orelse return null;

    var aw: std.Io.Writer.Allocating = .init(arena);
    var jw: Stringify = .{ .writer = &aw.writer };
    const W = Stringify.Error;
    const write = struct {
        fn begin(j: *Stringify, i: std.json.Value) W!void {
            try j.beginObject();
            try j.objectField("jsonrpc");
            try j.write("2.0");
            try j.objectField("id");
            try j.write(i);
            try j.objectField("result");
        }
    };

    if (std.mem.eql(u8, method, "initialize")) {
        const requested: ?[]const u8 = if (params) |p| (if (p.get("protocolVersion")) |v| (if (v == .string) v.string else null) else null) else null;
        var version = protocol_versions[0];
        if (requested) |r| for (protocol_versions) |pv| if (std.mem.eql(u8, pv, r)) {
            version = pv;
        };
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.write(.{
            .protocolVersion = version,
            .capabilities = .{ .tools = .{ .listChanged = false }, .prompts = .{ .listChanged = false } },
            .serverInfo = .{ .name = server_name, .version = server_version },
        }) catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "ping")) {
        write.begin(&jw, rid) catch return error.OutOfMemory;
        // `.{}` would serialize as `[]`; the result must be an empty object.
        jw.beginObject() catch return error.OutOfMemory;
        jw.endObject() catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "tools/list")) {
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.beginObject() catch return error.OutOfMemory;
        jw.objectField("tools") catch return error.OutOfMemory;
        tools.writeList(&jw) catch return error.OutOfMemory;
        jw.endObject() catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "tools/call")) {
        const p = params orelse return try errorResponse(arena, rid, invalid_params, "missing params");
        const name_v = p.get("name") orelse return try errorResponse(arena, rid, invalid_params, "missing tool name");
        if (name_v != .string) return try errorResponse(arena, rid, invalid_params, "tool name must be a string");
        const args: ?std.json.ObjectMap = if (p.get("arguments")) |a| switch (a) {
            .object => |o| o,
            .null => null,
            else => return try errorResponse(arena, rid, invalid_params, "arguments must be an object"),
        } else null;
        const outcome = (try tools.call(registry, arena, name_v.string, args)) orelse
            return try errorResponse(arena, rid, invalid_params, try arena.print("unknown tool \"{s}\"", .{name_v.string}));
        const raw_text, const is_error = switch (outcome) {
            .content => |t| .{ t, false },
            .tool_error => |t| .{ t, true },
            .invalid_params => |t| return try errorResponse(arena, rid, invalid_params, t),
        };
        // Backstop: std.json writes a non-UTF-8 []const u8 as an array of
        // integers, which breaks the MCP schema. Server text can be 8-bit.
        const text = try text_util.sanitizeUtf8(arena, raw_text);
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.write(.{
            .content = .{.{ .type = "text", .text = text }},
            .isError = is_error,
        }) catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "prompts/list")) {
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.beginObject() catch return error.OutOfMemory;
        jw.objectField("prompts") catch return error.OutOfMemory;
        prompts.writeList(&jw) catch return error.OutOfMemory;
        jw.endObject() catch return error.OutOfMemory;
    } else if (std.mem.eql(u8, method, "prompts/get")) {
        const p = params orelse return try errorResponse(arena, rid, invalid_params, "missing params");
        const name_v = p.get("name") orelse return try errorResponse(arena, rid, invalid_params, "missing prompt name");
        if (name_v != .string) return try errorResponse(arena, rid, invalid_params, "prompt name must be a string");
        const args: ?std.json.ObjectMap = if (p.get("arguments")) |a| (if (a == .object) a.object else null) else null;
        const text = prompts.render(arena, name_v.string, args) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnknownPrompt => return try errorResponse(arena, rid, invalid_params, "unknown prompt"),
            error.MissingArgument => return try errorResponse(arena, rid, invalid_params, "missing required argument"),
        };
        write.begin(&jw, rid) catch return error.OutOfMemory;
        jw.write(.{
            .messages = .{.{ .role = "user", .content = .{ .type = "text", .text = text } }},
        }) catch return error.OutOfMemory;
    } else {
        return try errorResponse(arena, rid, method_not_found, try arena.print("method not found: {s}", .{method}));
    }

    jw.endObject() catch return error.OutOfMemory;
    return aw.written();
}

fn errorResponse(arena: Allocator, id: std.json.Value, code: i32, message: []const u8) Allocator.Error![]const u8 {
    return Stringify.valueAlloc(arena, .{
        .jsonrpc = "2.0",
        .id = id,
        .@"error" = .{ .code = code, .message = try text_util.sanitizeUtf8(arena, message) },
    }, .{}) catch error.OutOfMemory;
}

const testing = std.testing;

fn roundTrip(input: []const u8) ![]u8 {
    var reg: Registry = try .init(testing.allocator, &.{}, .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = @import("config.zig").default_ca_file });
    defer reg.deinit();
    var in: std.Io.Reader = .fixed(input);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    try serve(testing.allocator, &reg, &in, &out.writer);
    return out.toOwnedSlice();
}

test "initialize negotiates version; notifications get no response" {
    const got = try roundTrip(
        \\{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}
        \\{"jsonrpc":"2.0","method":"notifications/initialized"}
        \\{"jsonrpc":"2.0","id":"p","method":"ping"}
        \\
    );
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{"tools":{"listChanged":false},"prompts":{"listChanged":false}},"serverInfo":{"name":"tp-imap-mcp","version":"0.1.0"}}}
        \\{"jsonrpc":"2.0","id":"p","result":{}}
        \\
    , got);
}

test "unknown protocol version falls back to newest" {
    const got = try roundTrip("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"1999-01-01\"}}");
    defer testing.allocator.free(got);
    try testing.expect(std.mem.find(u8, got, "\"protocolVersion\":\"2025-11-25\"") != null);
}

test "protocol errors" {
    const got = try roundTrip(
        \\not json
        \\[1,2]
        \\{"jsonrpc":"2.0","id":2,"method":"nope"}
        \\{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}
        \\{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"whoami","arguments":{}}}
        \\{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"whoami","arguments":{"account":"x"}}}
    );
    defer testing.allocator.free(got);
    var lines = std.mem.splitScalar(u8, got, '\n');
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse error"}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"request must be a JSON object"}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"method not found: nope"}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":3,"error":{"code":-32602,"message":"unknown tool \"nope\""}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":4,"error":{"code":-32602,"message":"missing required argument \"account\""}}
    , lines.next().?);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":5,"result":{"content":[{"type":"text","text":"unknown account \"x\"; configured accounts: "}],"isError":true}}
    , lines.next().?);
}

test "tools/list and prompts round-trip" {
    const got = try roundTrip(
        \\{"jsonrpc":"2.0","id":1,"method":"tools/list"}
        \\{"jsonrpc":"2.0","id":2,"method":"prompts/list"}
        \\{"jsonrpc":"2.0","id":3,"method":"prompts/get","params":{"name":"review_a_patch_series"}}
        \\
    );
    defer testing.allocator.free(got);
    var lines = std.mem.splitScalar(u8, got, '\n');
    const list = try std.json.parseFromSlice(std.json.Value, testing.allocator, lines.next().?, .{});
    defer list.deinit();
    try testing.expectEqual(14, list.value.object.get("result").?.object.get("tools").?.array.items.len);
    try testing.expect(std.mem.find(u8, lines.next().?, "list_patches_of_a_series") != null);
    try testing.expect(std.mem.find(u8, lines.next().?, "\"role\":\"user\"") != null);
}

test "very long line is read whole" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try buf.appendSlice(testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":{\"pad\":\"");
    try buf.appendNTimes(testing.allocator, 'a', 200_000);
    try buf.appendSlice(testing.allocator, "\"}}\n");
    const got = try roundTrip(buf.items);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n", got);
}

test "id 0 is echoed and arguments may be omitted" {
    const got = try roundTrip(
        \\{"jsonrpc":"2.0","id":0,"method":"tools/call","params":{"name":"list_accounts"}}
        \\
    );
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(
        \\{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"[]"}],"isError":false}}
        \\
    , got);
}

test "tool text with invalid UTF-8 is still a JSON string" {
    var accounts = [_]@import("config.zig").Account{.{
        .name = "a", .host = "h", .port = 993, .login = "caf\xe9", .password = @constCast(&[_:0]u8{}),
        .readonly = false, .drafts = null,
    }};
    var reg: Registry = try .init(testing.allocator, &accounts, .{ .cache_dir = null, .cache_dir_unavailable = false, .mailbox_ttl = 3600, .ca_file = @import("config.zig").default_ca_file });
    defer reg.deinit();
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const got = (try handle(arena_state.allocator(), &reg,
        \\{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{"account":"a"}}}
    )).?;
    try testing.expectEqualStrings(
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"caf\u{FFFD}\"}],\"isError\":false}}",
        got,
    );
}
