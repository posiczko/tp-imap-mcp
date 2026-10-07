/* MIME half of the tpi shim: text/<subtype> body extraction. */
#include "tpi.h"

#include <libetpan/libetpan.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

typedef struct {
  char *buf;
  size_t len;
  size_t cap;
  size_t parts; /* matching, non-attachment parts seen (even if empty) */
} growbuf;

static int grow_append(growbuf *g, const char *data, size_t n) {
  if (g->len + n + 1 > g->cap) {
    size_t cap = g->cap > 0 ? g->cap : 256;
    while (cap < g->len + n + 1)
      cap *= 2;
    char *p = realloc(g->buf, cap);
    if (p == NULL)
      return -1;
    g->buf = p;
    g->cap = cap;
  }
  memcpy(g->buf + g->len, data, n);
  g->len += n;
  g->buf[g->len] = '\0';
  return 0;
}

/* Content type of a part; RFC 2045 default is text/plain. */
static void content_type(struct mailmime_content *ct, const char **type, const char **subtype) {
  *type = "text";
  *subtype = "plain";
  if (ct == NULL || ct->ct_type == NULL)
    return;
  struct mailmime_type *t = ct->ct_type;
  if (t->tp_type == MAILMIME_TYPE_DISCRETE_TYPE && t->tp_data.tp_discrete_type != NULL) {
    struct mailmime_discrete_type *d = t->tp_data.tp_discrete_type;
    switch (d->dt_type) {
    case MAILMIME_DISCRETE_TYPE_TEXT: *type = "text"; break;
    case MAILMIME_DISCRETE_TYPE_IMAGE: *type = "image"; break;
    case MAILMIME_DISCRETE_TYPE_AUDIO: *type = "audio"; break;
    case MAILMIME_DISCRETE_TYPE_VIDEO: *type = "video"; break;
    case MAILMIME_DISCRETE_TYPE_APPLICATION: *type = "application"; break;
    default: *type = d->dt_extension != NULL ? d->dt_extension : "application"; break;
    }
  } else if (t->tp_type == MAILMIME_TYPE_COMPOSITE_TYPE && t->tp_data.tp_composite_type != NULL) {
    struct mailmime_composite_type *c = t->tp_data.tp_composite_type;
    *type = c->ct_type == MAILMIME_COMPOSITE_TYPE_MULTIPART ? "multipart" : "message";
  }
  *subtype = ct->ct_subtype != NULL ? ct->ct_subtype : "";
}

static const char *content_param(struct mailmime_content *ct, const char *name) {
  if (ct == NULL || ct->ct_parameters == NULL)
    return NULL;
  for (clistiter *it = clist_begin(ct->ct_parameters); it != NULL; it = clist_next(it)) {
    struct mailmime_parameter *p = clist_content(it);
    if (p->pa_name != NULL && strcasecmp(p->pa_name, name) == 0)
      return p->pa_value;
  }
  return NULL;
}

static int append_part(growbuf *g, struct mailmime *part) {
  struct mailmime_single_fields sf;
  mailmime_single_fields_init(&sf, part->mm_mime_fields, part->mm_content_type);
  /* Python's part.get_filename() skips these; so do we. */
  if (sf.fld_disposition_filename != NULL || sf.fld_content_name != NULL)
    return 0;

  struct mailmime_data *d = part->mm_data.mm_single;
  if (d == NULL || d->dt_type != MAILMIME_DATA_TEXT)
    return 0;
  g->parts++;

  int encoding = sf.fld_encoding != NULL ? sf.fld_encoding->enc_type : MAILMIME_MECHANISM_8BIT;
  size_t idx = 0;
  char *decoded = NULL;
  size_t decoded_len = 0;
  if (mailmime_part_parse(d->dt_data.dt_text.dt_data, d->dt_data.dt_text.dt_length, &idx,
                          encoding, &decoded, &decoded_len) != MAILIMF_NO_ERROR)
    return 0; /* undecodable part: skip, like a missing payload in Python */

  const char *charset = sf.fld_content_charset != NULL ? sf.fld_content_charset : "utf-8";
  int rc = 0;
  char *converted = NULL;
  size_t converted_len = 0;
  /* charconv_buffer reports the length, so an embedded NUL does not truncate. */
  if (strcasecmp(charset, "utf-8") != 0 && strcasecmp(charset, "us-ascii") != 0 &&
      charconv_buffer("utf-8", charset, decoded, decoded_len, &converted, &converted_len) ==
          MAIL_CHARCONV_NO_ERROR) {
    rc = grow_append(g, converted, converted_len);
    charconv_buffer_free(converted);
  } else {
    /* UTF-8, ASCII, or unknown charset: pass bytes through; the Zig layer
     * replaces invalid UTF-8 with U+FFFD. */
    rc = grow_append(g, decoded, decoded_len);
  }
  mmap_string_unref(decoded);
  return rc;
}

/* Depth-first walk matching Python's Message.walk(). */
static int walk(growbuf *g, struct mailmime *mime, const char *want_subtype) {
  switch (mime->mm_type) {
  case MAILMIME_SINGLE: {
    const char *type, *subtype;
    content_type(mime->mm_content_type, &type, &subtype);
    if (strcasecmp(type, "text") == 0 && strcasecmp(subtype, want_subtype) == 0)
      return append_part(g, mime);
    return 0;
  }
  case MAILMIME_MULTIPLE:
    if (mime->mm_data.mm_multipart.mm_mp_list == NULL)
      return 0;
    for (clistiter *it = clist_begin(mime->mm_data.mm_multipart.mm_mp_list); it != NULL;
         it = clist_next(it)) {
      if (walk(g, clist_content(it), want_subtype) != 0)
        return -1;
    }
    return 0;
  case MAILMIME_MESSAGE:
    if (mime->mm_data.mm_message.mm_msg_mime != NULL)
      return walk(g, mime->mm_data.mm_message.mm_msg_mime, want_subtype);
    return 0;
  default:
    return 0;
  }
}

int tpi_extract_text(const char *msg, size_t len, const char *subtype,
                     char **out, size_t *out_len, size_t *parts_found,
                     char **encrypted_protocol) {
  *out = NULL;
  *out_len = 0;
  *parts_found = 0;
  *encrypted_protocol = NULL;

  size_t idx = 0;
  struct mailmime *mime = NULL;
  if (mailmime_parse(msg, len, &idx, &mime) != MAILIMF_NO_ERROR)
    return TPI_ERR_PARSE;

  /* mailmime_parse wraps the message in a MAILMIME_MESSAGE node. */
  struct mailmime *top = mime;
  if (top->mm_type == MAILMIME_MESSAGE && top->mm_data.mm_message.mm_msg_mime != NULL)
    top = top->mm_data.mm_message.mm_msg_mime;

  const char *type, *sub;
  content_type(top->mm_content_type, &type, &sub);
  if (strcasecmp(type, "multipart") == 0 && strcasecmp(sub, "encrypted") == 0) {
    const char *proto = content_param(top->mm_content_type, "protocol");
    *encrypted_protocol = strdup(proto != NULL ? proto : "");
    mailmime_free(mime);
    return *encrypted_protocol != NULL ? TPI_OK : TPI_ERR_MEMORY;
  }

  growbuf g = {0};
  int rc = walk(&g, mime, subtype);
  mailmime_free(mime);
  if (rc != 0) {
    free(g.buf);
    return TPI_ERR_MEMORY;
  }
  if (g.buf == NULL) {
    g.buf = calloc(1, 1);
    if (g.buf == NULL)
      return TPI_ERR_MEMORY;
  }
  *out = g.buf;
  *out_len = g.len;
  *parts_found = g.parts;
  return TPI_OK;
}

void tpi_buf_free(char *buf) { free(buf); }

int tpi_decode_header_value(const char *raw, size_t len, char **out, size_t *out_len) {
  *out = NULL;
  *out_len = 0;
  size_t idx = 0;
  char *decoded = NULL;
  if (mailmime_encoded_phrase_parse("utf-8", raw, len, &idx, "utf-8", &decoded) != MAILIMF_NO_ERROR ||
      decoded == NULL)
    return TPI_ERR_PARSE;
  *out = decoded;
  *out_len = strlen(decoded);
  return TPI_OK;
}
