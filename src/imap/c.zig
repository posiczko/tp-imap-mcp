//! Hand-written externs for src/c/tpi.h. Keep in sync with that header.

pub const OK: c_int = 0;
pub const ERR_CONNECT: c_int = 1;
pub const ERR_STREAM: c_int = 2;
pub const ERR_SERVER: c_int = 3;
pub const ERR_PARSE: c_int = 4;
pub const ERR_MEMORY: c_int = 5;
pub const ERR_OTHER: c_int = 6;
pub const ERR_TLS: c_int = 7;

pub const FETCH_HEADER: c_int = 1;
pub const FETCH_BODY: c_int = 2;
pub const FETCH_SIZE: c_int = 4;
pub const FETCH_FLAGS: c_int = 8;

pub const Session = opaque {};

pub const Mailbox = extern struct {
    name: [*:0]u8,
    delimiter: u8,
    flags: [*:0]u8,
};

pub const Status = extern struct {
    messages: u32,
    recent: u32,
    unseen: u32,
};

pub const FetchItem = extern struct {
    uid: u32,
    size: u32,
    data: ?[*]u8,
    data_len: usize,
    flags: ?[*:0]u8,
};

pub extern fn tpi_new() ?*Session;
pub extern fn tpi_free(s: *Session) void;
pub extern fn tpi_connect(s: *Session, host: [*:0]const u8, port: u16, timeout_sec: c_long, ca_file: [*:0]const u8) c_int;
pub extern fn tpi_peer_certificate(s: *Session, der: *?[*]u8) c_long;
pub extern fn tpi_login(s: *Session, user: [*:0]const u8, password: [*:0]const u8) c_int;
pub extern fn tpi_oauth2_login(s: *Session, user: [*:0]const u8, access_token: [*:0]const u8) c_int;
pub extern fn tpi_noop(s: *Session) c_int;
pub extern fn tpi_logout(s: *Session) c_int;
pub extern fn tpi_examine(s: *Session, mailbox: [*:0]const u8, uidvalidity: *u32) c_int;
pub extern fn tpi_select(s: *Session, mailbox: [*:0]const u8, uidvalidity: *u32) c_int;
pub extern fn tpi_last_response(s: *Session) [*:0]const u8;

pub extern fn tpi_uid_search(s: *Session, criteria: [*:0]const u8, uids: *?[*]u32, count: *usize) c_int;
pub extern fn tpi_uids_free(uids: ?[*]u32) void;

pub extern fn tpi_list(s: *Session, reference: [*:0]const u8, pattern: [*:0]const u8, out: *?[*]Mailbox, count: *usize) c_int;
pub extern fn tpi_mailboxes_free(items: ?[*]Mailbox, count: usize) void;

pub extern fn tpi_status_get(s: *Session, mailbox: [*:0]const u8, out: *Status) c_int;

pub extern fn tpi_uid_fetch(s: *Session, uids: [*]const u32, uid_count: usize, what: c_int, out: *?[*]FetchItem, count: *usize) c_int;
pub extern fn tpi_fetch_free(items: ?[*]FetchItem, count: usize) void;

pub extern fn tpi_uid_store_flags(s: *Session, uids: [*]const u32, uid_count: usize, add: c_int, flags: [*]const [*:0]const u8, flag_count: usize) c_int;

pub extern fn tpi_append(s: *Session, mailbox: [*:0]const u8, data: [*]const u8, len: usize) c_int;

pub extern fn tpi_create(s: *Session, mailbox: [*:0]const u8) c_int;
pub extern fn tpi_rename(s: *Session, from: [*:0]const u8, to: [*:0]const u8) c_int;
pub extern fn tpi_delete(s: *Session, mailbox: [*:0]const u8) c_int;
pub extern fn tpi_subscribe(s: *Session, mailbox: [*:0]const u8) c_int;
pub extern fn tpi_unsubscribe(s: *Session, mailbox: [*:0]const u8) c_int;

pub const CAP_MOVE: c_int = 1;
pub const CAP_UIDPLUS: c_int = 2;
pub extern fn tpi_capabilities(s: *Session, caps: *c_int) c_int;

pub const CopyUid = extern struct {
    uidvalidity: u32,
    src: ?[*]u32,
    src_len: usize,
    dst: ?[*]u32,
    dst_len: usize,
};
pub extern fn tpi_uid_transfer(s: *Session, uids: [*]const u32, uid_count: usize, mailbox: [*:0]const u8, move: c_int, out: *CopyUid) c_int;
pub extern fn tpi_copyuid_free(c: *CopyUid) void;
pub extern fn tpi_uid_expunge(s: *Session, uids: [*]const u32, uid_count: usize) c_int;

pub extern fn tpi_extract_text(msg: [*]const u8, len: usize, subtype: [*:0]const u8, out: *?[*]u8, out_len: *usize, parts_found: *usize, encrypted_protocol: *?[*:0]u8) c_int;
pub extern fn tpi_buf_free(buf: ?[*]u8) void;

pub extern fn tpi_decode_header_value(raw: [*]const u8, len: usize, out: *?[*]u8, out_len: *usize) c_int;

pub const Part = extern struct {
    uid: u32,
    size: u32,
    base64: c_int,
    content_type: [*:0]u8,
    disposition: [*:0]u8,
    params: [*:0]u8,
    disp_params: [*:0]u8,
};
pub extern fn tpi_uid_bodystructure(s: *Session, uids: [*]const u32, uid_count: usize, out: *?[*]Part, count: *usize) c_int;
pub extern fn tpi_parts_free(items: ?[*]Part, count: usize) void;

pub const Regex = opaque {};
pub extern fn tpi_regex_compile(pattern: [*:0]const u8, err: [*]u8, errlen: usize) ?*Regex;
pub extern fn tpi_regex_match(r: *const Regex, text: [*:0]const u8) c_int;
pub extern fn tpi_regex_free(r: ?*Regex) void;
