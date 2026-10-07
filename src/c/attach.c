/* BODYSTRUCTURE half of the tpi shim: flatten each message's MIME tree into
 * its leaf parts (raw facts only; src/attachments.zig decides). */
#include "tpi.h"

#include <libetpan/libetpan.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* Internal helpers from session.c. */
struct mailimap *tpi_imap(tpi_session *s);
int tpi_map_error(int r);

typedef struct {
  tpi_part *items;
  size_t len;
  size_t cap;
} partbuf;

/* Appends "name\x1fvalue" pairs joined by \x1e to a malloc'd string. */
static char *flatten_params(struct mailimap_body_fld_param *fp) {
  size_t need = 1;
  if (fp != NULL && fp->pa_list != NULL)
    for (clistiter *it = clist_begin(fp->pa_list); it != NULL; it = clist_next(it)) {
      struct mailimap_single_body_fld_param *p = clist_content(it);
      need += strlen(p->pa_name) + strlen(p->pa_value) + 2;
    }
  char *out = calloc(1, need);
  if (out == NULL)
    return NULL;
  if (fp == NULL || fp->pa_list == NULL)
    return out;
  size_t n = 0;
  for (clistiter *it = clist_begin(fp->pa_list); it != NULL; it = clist_next(it)) {
    struct mailimap_single_body_fld_param *p = clist_content(it);
    if (n > 0)
      out[n++] = '\x1e';
    size_t a = strlen(p->pa_name), b = strlen(p->pa_value);
    memcpy(out + n, p->pa_name, a);
    n += a;
    out[n++] = '\x1f';
    memcpy(out + n, p->pa_value, b);
    n += b;
  }
  out[n] = '\0';
  return out;
}

static char *join_type(const char *type, const char *subtype) {
  size_t a = strlen(type), b = strlen(subtype);
  char *out = malloc(a + b + 2);
  if (out == NULL)
    return NULL;
  memcpy(out, type, a);
  out[a] = '/';
  memcpy(out + a + 1, subtype, b);
  out[a + b + 1] = '\0';
  return out;
}

static const char *basic_type_name(struct mailimap_media_basic *m) {
  switch (m->med_type) {
  case MAILIMAP_MEDIA_BASIC_APPLICATION: return "application";
  case MAILIMAP_MEDIA_BASIC_AUDIO: return "audio";
  case MAILIMAP_MEDIA_BASIC_IMAGE: return "image";
  case MAILIMAP_MEDIA_BASIC_MESSAGE: return "message";
  case MAILIMAP_MEDIA_BASIC_VIDEO: return "video";
  default: return m->med_basic_type != NULL ? m->med_basic_type : "application";
  }
}

static int push_leaf(partbuf *pb, uint32_t uid, char *ct, struct mailimap_body_fields *f,
                     struct mailimap_body_ext_1part *ext) {
  if (ct == NULL)
    return -1;
  if (pb->len == pb->cap) {
    size_t cap = pb->cap > 0 ? pb->cap * 2 : 16;
    tpi_part *items = realloc(pb->items, cap * sizeof(tpi_part));
    if (items == NULL) {
      free(ct);
      return -1;
    }
    pb->items = items;
    pb->cap = cap;
  }
  tpi_part *p = &pb->items[pb->len];
  memset(p, 0, sizeof(*p));
  p->uid = uid;
  p->content_type = ct;
  p->size = f != NULL ? f->bd_size : 0;
  p->base64 = f != NULL && f->bd_encoding != NULL && f->bd_encoding->enc_type == MAILIMAP_BODY_FLD_ENC_BASE64;
  p->params = flatten_params(f != NULL ? f->bd_parameter : NULL);
  struct mailimap_body_fld_dsp *dsp = ext != NULL ? ext->bd_disposition : NULL;
  p->disposition = strdup(dsp != NULL && dsp->dsp_type != NULL ? dsp->dsp_type : "");
  p->disp_params = flatten_params(dsp != NULL ? dsp->dsp_attributes : NULL);
  pb->len++; /* counted even on partial failure so tpi_parts_free releases it */
  return (p->params == NULL || p->disposition == NULL || p->disp_params == NULL) ? -1 : 0;
}

static int walk(partbuf *pb, uint32_t uid, struct mailimap_body *b, int depth) {
  if (b == NULL || depth > 64)
    return 0;
  if (b->bd_type == MAILIMAP_BODY_MPART) {
    struct mailimap_body_type_mpart *mp = b->bd_data.bd_body_mpart;
    if (mp == NULL || mp->bd_list == NULL)
      return 0;
    for (clistiter *it = clist_begin(mp->bd_list); it != NULL; it = clist_next(it))
      if (walk(pb, uid, clist_content(it), depth + 1) != 0)
        return -1;
    return 0;
  }
  struct mailimap_body_type_1part *one = b->bd_data.bd_body_1part;
  if (one == NULL)
    return 0;
  switch (one->bd_type) {
  case MAILIMAP_BODY_TYPE_1PART_BASIC: {
    struct mailimap_body_type_basic *t = one->bd_data.bd_type_basic;
    if (t == NULL)
      return 0;
    return push_leaf(pb, uid, join_type(basic_type_name(t->bd_media_basic), t->bd_media_basic->med_subtype),
                     t->bd_fields, one->bd_ext_1part);
  }
  case MAILIMAP_BODY_TYPE_1PART_TEXT: {
    struct mailimap_body_type_text *t = one->bd_data.bd_type_text;
    if (t == NULL)
      return 0;
    return push_leaf(pb, uid, join_type("text", t->bd_media_text), t->bd_fields, one->bd_ext_1part);
  }
  case MAILIMAP_BODY_TYPE_1PART_MSG: {
    /* A forwarded message is one attachment; do not descend into it. */
    struct mailimap_body_type_msg *t = one->bd_data.bd_type_msg;
    if (t == NULL)
      return 0;
    return push_leaf(pb, uid, join_type("message", "rfc822"), t->bd_fields, one->bd_ext_1part);
  }
  default:
    return 0;
  }
}

int tpi_uid_bodystructure(tpi_session *s, const uint32_t *uids, size_t uid_count,
                          tpi_part **out, size_t *count) {
  *out = NULL;
  *count = 0;
  struct mailimap_set *set = mailimap_set_new_empty();
  if (set == NULL)
    return TPI_ERR_MEMORY;
  for (size_t i = 0; i < uid_count; i++) {
    if (mailimap_set_add_single(set, uids[i]) != MAILIMAP_NO_ERROR) {
      mailimap_set_free(set);
      return TPI_ERR_MEMORY;
    }
  }
  struct mailimap_fetch_type *ft = mailimap_fetch_type_new_fetch_att_list_empty();
  struct mailimap_fetch_att *a_uid = mailimap_fetch_att_new_uid();
  struct mailimap_fetch_att *a_bs = mailimap_fetch_att_new_bodystructure();
  if (ft == NULL || a_uid == NULL || a_bs == NULL ||
      mailimap_fetch_type_new_fetch_att_list_add(ft, a_uid) != MAILIMAP_NO_ERROR) {
    if (a_uid) mailimap_fetch_att_free(a_uid);
    if (a_bs) mailimap_fetch_att_free(a_bs);
    if (ft) mailimap_fetch_type_free(ft);
    mailimap_set_free(set);
    return TPI_ERR_MEMORY;
  }
  if (mailimap_fetch_type_new_fetch_att_list_add(ft, a_bs) != MAILIMAP_NO_ERROR) {
    mailimap_fetch_att_free(a_bs);
    mailimap_fetch_type_free(ft);
    mailimap_set_free(set);
    return TPI_ERR_MEMORY;
  }

  clist *result = NULL;
  int r = mailimap_uid_fetch(tpi_imap(s), set, ft, &result);
  mailimap_fetch_type_free(ft);
  mailimap_set_free(set);
  if (r != MAILIMAP_NO_ERROR)
    return tpi_map_error(r);

  partbuf pb = {0};
  int rc = TPI_OK;
  for (clistiter *it = clist_begin(result); it != NULL && rc == TPI_OK; it = clist_next(it)) {
    struct mailimap_msg_att *ma = clist_content(it);
    uint32_t uid = 0;
    struct mailimap_body *body = NULL;
    for (clistiter *jt = clist_begin(ma->att_list); jt != NULL; jt = clist_next(jt)) {
      struct mailimap_msg_att_item *ai = clist_content(jt);
      if (ai->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC || ai->att_data.att_static == NULL)
        continue;
      struct mailimap_msg_att_static *st = ai->att_data.att_static;
      if (st->att_type == MAILIMAP_MSG_ATT_UID)
        uid = st->att_data.att_uid;
      else if (st->att_type == MAILIMAP_MSG_ATT_BODYSTRUCTURE)
        body = st->att_data.att_bodystructure;
    }
    /* Unsolicited FETCH responses carry no UID or no structure: skip. */
    if (uid != 0 && body != NULL && walk(&pb, uid, body, 0) != 0)
      rc = TPI_ERR_MEMORY;
  }
  mailimap_fetch_list_free(result);
  if (rc != TPI_OK) {
    tpi_parts_free(pb.items, pb.len);
    return rc;
  }
  *out = pb.items;
  *count = pb.len;
  return TPI_OK;
}

void tpi_parts_free(tpi_part *items, size_t count) {
  if (items == NULL)
    return;
  for (size_t i = 0; i < count; i++) {
    free(items[i].content_type);
    free(items[i].disposition);
    free(items[i].params);
    free(items[i].disp_params);
  }
  free(items);
}
