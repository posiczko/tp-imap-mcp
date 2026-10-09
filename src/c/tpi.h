/* Flat C interface over libetpan, consumed from Zig via hand-written externs
 * in src/imap/c.zig. Keep the two in sync. All returned buffers are malloc'd
 * and released with the matching tpi_*_free function. */
#ifndef TPI_H
#define TPI_H

#include <stddef.h>
#include <stdint.h>

enum {
  TPI_OK = 0,
  TPI_ERR_CONNECT = 1,  /* TCP/TLS connect failed */
  TPI_ERR_STREAM = 2,   /* connection dropped mid-command */
  TPI_ERR_SERVER = 3,   /* server replied NO or BAD; see tpi_last_response */
  TPI_ERR_PARSE = 4,    /* unparseable server response */
  TPI_ERR_MEMORY = 5,
  TPI_ERR_OTHER = 6,
  TPI_ERR_TLS = 7,      /* TLS handshake failed, e.g. untrusted certificate */
};

typedef struct tpi_session tpi_session;

tpi_session *tpi_new(void);
void tpi_free(tpi_session *s);

/* Implicit TLS connect. The server certificate chain is verified against the
 * PEM bundle ca_file and SNI is set to host; a failure returns TPI_ERR_TLS.
 * The certificate's host name is NOT checked here: the caller must check it
 * (tpi_peer_certificate) before sending credentials. timeout_sec applies to
 * every network operation. */
int tpi_connect(tpi_session *s, const char *host, uint16_t port, long timeout_sec,
                const char *ca_file);

/* Tests only: runs the session over an already-connected plain socket fd
 * (taken over; closed by tpi_free) and reads the server greeting. */
int tpi_attach_fd(tpi_session *s, int fd);

/* DER encoding of the connected server's certificate. Returns its length, or
 * -1 if unavailable. Release *der with tpi_buf_free. */
long tpi_peer_certificate(tpi_session *s, char **der);
int tpi_login(tpi_session *s, const char *user, const char *password);
/* SASL XOAUTH2 with a bearer access token (ADR 0020). */
int tpi_oauth2_login(tpi_session *s, const char *user, const char *access_token);
int tpi_noop(tpi_session *s);
int tpi_logout(tpi_session *s);
/* On success *uidvalidity is the mailbox's UIDVALIDITY (0 if the server did
 * not report one). */
int tpi_examine(tpi_session *s, const char *mailbox, uint32_t *uidvalidity);
int tpi_select(tpi_session *s, const char *mailbox, uint32_t *uidvalidity);

/* Text of the last server response line (e.g. "Unknown argument BOGUSKEY"),
 * or "" if none. Valid until the next call on this session. */
const char *tpi_last_response(tpi_session *s);

/* Sends "UID SEARCH <criteria>" verbatim; caller has already validated it. */
int tpi_uid_search(tpi_session *s, const char *criteria, uint32_t **uids, size_t *count);
void tpi_uids_free(uint32_t *uids);

typedef struct {
  char *name;   /* raw (modified UTF-7) mailbox name */
  char delimiter; /* 0 when the server reports NIL */
  char *flags;  /* space-separated, each with leading backslash */
} tpi_mailbox;

int tpi_list(tpi_session *s, const char *reference, const char *pattern,
             tpi_mailbox **out, size_t *count);
void tpi_mailboxes_free(tpi_mailbox *items, size_t count);

typedef struct {
  uint32_t messages;
  uint32_t recent;
  uint32_t unseen;
} tpi_status;

int tpi_status_get(tpi_session *s, const char *mailbox, tpi_status *out);

enum {
  TPI_FETCH_HEADER = 1, /* BODY.PEEK[HEADER] */
  TPI_FETCH_BODY = 2,   /* BODY.PEEK[]       */
  TPI_FETCH_SIZE = 4,   /* RFC822.SIZE       */
  TPI_FETCH_FLAGS = 8,  /* FLAGS             */
  TPI_FETCH_PARTIAL = 16, /* with TPI_FETCH_BODY: only the first TPI_PARTIAL_BYTES */
};

enum { TPI_PARTIAL_BYTES = 16384 }; /* BODY.PEEK[]<0.16384> */

typedef struct {
  uint32_t uid;
  uint32_t size;  /* RFC822.SIZE, valid with TPI_FETCH_SIZE */
  char *data;     /* header or full message bytes; NULL if not fetched */
  size_t data_len;
  char *flags;    /* space-separated; NULL if not fetched */
} tpi_fetch_item;

/* Items come back in server order; the Zig layer aligns them to input. */
int tpi_uid_fetch(tpi_session *s, const uint32_t *uids, size_t uid_count, int what,
                  tpi_fetch_item **out, size_t *count);
void tpi_fetch_free(tpi_fetch_item *items, size_t count);

/* UID STORE <uids> +FLAGS.SILENT/-FLAGS.SILENT (<flags>). Flags are
 * "\\Seen"-style system flags or keyword atoms, already validated. */
int tpi_uid_store_flags(tpi_session *s, const uint32_t *uids, size_t uid_count, int add,
                        const char *const *flags, size_t flag_count);

int tpi_append(tpi_session *s, const char *mailbox, const char *data, size_t len);

/* Mailbox management (ADR 0021). Names are wire (modified UTF-7), validated. */
int tpi_create(tpi_session *s, const char *mailbox);
int tpi_rename(tpi_session *s, const char *from, const char *to);
int tpi_delete(tpi_session *s, const char *mailbox);
int tpi_subscribe(tpi_session *s, const char *mailbox);
int tpi_unsubscribe(tpi_session *s, const char *mailbox);

enum {
  TPI_CAP_MOVE = 1,    /* RFC 6851 */
  TPI_CAP_UIDPLUS = 2, /* RFC 4315 */
};

/* Bit mask of TPI_CAP_* from a CAPABILITY command, sent once per session. */
int tpi_capabilities(tpi_session *s, int *caps);

/* COPYUID response code (UIDPLUS). Ranges are (first, last) pairs, so each
 * length is twice the number of ranges; a last of 0 stands for "*".
 * uidvalidity is 0 and both arrays NULL when the server sent none. */
typedef struct {
  uint32_t uidvalidity;
  uint32_t *src;
  size_t src_len;
  uint32_t *dst;
  size_t dst_len;
} tpi_copyuid;

/* UID MOVE (move != 0) or UID COPY of uids from the selected mailbox to
 * mailbox. *out is filled on success; release it with tpi_copyuid_free. */
int tpi_uid_transfer(tpi_session *s, const uint32_t *uids, size_t uid_count,
                     const char *mailbox, int move, tpi_copyuid *out);
void tpi_copyuid_free(tpi_copyuid *c);

/* UID EXPUNGE (UIDPLUS): expunges only these UIDs, if flagged \Deleted. */
int tpi_uid_expunge(tpi_session *s, const uint32_t *uids, size_t uid_count);

/* MIME: concatenate every non-attachment text/<subtype> part of a full
 * RFC 822 message, transfer-decoded and converted to UTF-8 where possible.
 * *parts_found counts the matching parts (so "no part" and "empty part" can
 * be told apart).
 * If the top-level type is multipart/encrypted, *encrypted_protocol is set to
 * a malloc'd copy of its protocol parameter ("" if absent) and *out is NULL.
 * Release *out and *encrypted_protocol with tpi_buf_free. */
int tpi_extract_text(const char *msg, size_t len, const char *subtype,
                     char **out, size_t *out_len, size_t *parts_found,
                     char **encrypted_protocol);
void tpi_buf_free(char *buf);

/* RFC 2047: decode encoded-words in a header value to UTF-8 (unencoded text
 * is taken as UTF-8). Release *out with tpi_buf_free. */
int tpi_decode_header_value(const char *raw, size_t len, char **out, size_t *out_len);

/* BODYSTRUCTURE leaf parts for list_attachments. Strings are malloc'd;
 * params/disp_params are "name\x1fvalue" pairs joined by \x1e. */
typedef struct {
  uint32_t uid;
  uint32_t size;      /* encoded size in bytes */
  int base64;         /* 1 if Content-Transfer-Encoding is base64 */
  char *content_type; /* "type/subtype" as sent */
  char *disposition;  /* "" when absent */
  char *params;       /* content-type parameters */
  char *disp_params;  /* disposition parameters */
} tpi_part;

/* UID FETCH (UID BODYSTRUCTURE); forwarded messages are single leaves. */
int tpi_uid_bodystructure(tpi_session *s, const uint32_t *uids, size_t uid_count,
                          tpi_part **out, size_t *count);
void tpi_parts_free(tpi_part *items, size_t count);

/* POSIX extended regex, case-insensitive, match/no-match only (ADR 0017). */
typedef struct tpi_regex tpi_regex;

/* Returns NULL on failure with a message in err (always NUL-terminated when
 * errlen > 0). */
tpi_regex *tpi_regex_compile(const char *pattern, char *err, size_t errlen);
/* 1 if `text` (NUL-terminated) contains a match, else 0. */
int tpi_regex_match(const tpi_regex *r, const char *text);
void tpi_regex_free(tpi_regex *r);

#endif
