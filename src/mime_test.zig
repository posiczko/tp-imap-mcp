//! Body rendering tests against .eml fixtures (exercises src/c/mime.c).

const std = @import("std");
const body = @import("body.zig");

const testing = std.testing;

fn expectBody(comptime fixture: []const u8, kind: body.Kind, expected: []const u8) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const got = try body.render(arena_state.allocator(), @embedFile("testdata/" ++ fixture), kind);
    try testing.expectEqualStrings(expected, got);
}

test "multipart/alternative picks the requested subtype" {
    try expectBody("alternative.eml", .plain, "hello plain");
    try expectBody("alternative.eml", .html, "<p>hello html</p>");
}

test "text attachment is skipped" {
    try expectBody("attachment.eml", .plain, "the body");
}

test "iso-8859-1 quoted-printable becomes utf-8" {
    try expectBody("latin1_qp.eml", .plain, "r\u{e9}sum\u{e9}\n");
}

test "base64 body is decoded" {
    try expectBody("base64.eml", .plain, "hello base64");
}

test "nested message/rfc822 parts are included in walk order" {
    try expectBody("nested.eml", .plain, "outerinner");
}

test "no matching part yields empty string" {
    try expectBody("base64.eml", .html, "");
}

test "missing Content-Type defaults to text/plain" {
    try expectBody("no_content_type.eml", .plain, "just text\n");
}

test "undeclared 8-bit bytes are replaced, not passed as invalid utf-8" {
    try expectBody("bad_utf8.eml", .plain, "caf\u{FFFD}\n");
}

test "multipart/encrypted yields the not-decrypted marker" {
    try expectBody(
        "encrypted.eml",
        .plain,
        "[encrypted message (multipart/encrypted; protocol=application/pgp-encrypted) — not decrypted]",
    );
}
