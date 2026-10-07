/* IMAP session half of the tpi shim. See tpi.h for the contract. */
#include "tpi.h"

#include <libetpan/libetpan.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct tpi_session {
  mailimap *imap;
};

int tpi_map_error(int r);
static int map_error(int r) { return tpi_map_error(r); }

/* Internal: shared with attach.c. */
struct mailimap *tpi_imap(tpi_session *s) { return s->imap; }

int tpi_map_error(int r) {
  switch (r) {
  case MAILIMAP_NO_ERROR:
  case MAILIMAP_NO_ERROR_AUTHENTICATED:
  case MAILIMAP_NO_ERROR_NON_AUTHENTICATED:
    return TPI_OK;
  case MAILIMAP_ERROR_STREAM:
    return TPI_ERR_STREAM;
  case MAILIMAP_ERROR_PARSE:
    return TPI_ERR_PARSE;
  case MAILIMAP_ERROR_MEMORY:
    return TPI_ERR_MEMORY;
  case MAILIMAP_ERROR_CONNECTION_REFUSED:
  case MAILIMAP_ERROR_SSL:
    return TPI_ERR_CONNECT;
  default:
    return TPI_ERR_SERVER;
  }
}

tpi_session *tpi_new(void) {
  tpi_session *s = calloc(1, sizeof(*s));
  if (s == NULL)
    return NULL;
  s->imap = mailimap_new(0, NULL);
  if (s->imap == NULL) {
    free(s);
    return NULL;
  }
  return s;
}

void tpi_free(tpi_session *s) {
  if (s == NULL)
    return;
  mailimap_free(s->imap);
  free(s);
}

struct tls_options {
  const char *host;
  const char *ca_file;
  int ca_failed;
};

/* Runs before the handshake: SNI plus chain verification (SSL_VERIFY_PEER). */
static void tls_setup(struct mailstream_ssl_context *ctx, void *data) {
  struct tls_options *o = data;
  mailstream_ssl_set_server_name(ctx, (char *)o->host);
  if (mailstream_ssl_set_server_certicate(ctx, (char *)o->ca_file, NULL) < 0)
    o->ca_failed = 1;
}

int tpi_connect(tpi_session *s, const char *host, uint16_t port, long timeout_sec,
                const char *ca_file) {
  mailimap_set_timeout(s->imap, (time_t)timeout_sec);
  struct tls_options opts = {host, ca_file, 0};
  int r = mailimap_ssl_connect_with_callback(s->imap, host, port, tls_setup, &opts);
  if (opts.ca_failed)
    return TPI_ERR_TLS;
  if (r == MAILIMAP_NO_ERROR_AUTHENTICATED || r == MAILIMAP_NO_ERROR_NON_AUTHENTICATED)
    return TPI_OK;
  switch (r) {
  case MAILIMAP_ERROR_MEMORY: return TPI_ERR_MEMORY;
  case MAILIMAP_ERROR_SSL: return TPI_ERR_TLS;
  default: return TPI_ERR_CONNECT;
  }
}

/* Uses the certificate-chain API: mailstream_ssl_get_certificate (libetpan
 * 1.10.1) returns a pointer advanced past the end of its buffer by i2d_X509,
 * so it can be neither read nor freed. Element 0 is the server's own cert. */
long tpi_peer_certificate(tpi_session *s, char **der) {
  *der = NULL;
  carray *chain = mailstream_get_certificate_chain(s->imap->imap_stream);
  if (chain == NULL)
    return -1;
  long n = -1;
  if (carray_count(chain) > 0) {
    MMAPString *leaf = carray_get(chain, 0);
    char *copy = malloc(leaf->len > 0 ? leaf->len : 1);
    if (copy != NULL) {
      memcpy(copy, leaf->str, leaf->len);
      *der = copy;
      n = (long)leaf->len;
    }
  }
  mailstream_certificate_chain_free(chain);
  return n;
}

int tpi_login(tpi_session *s, const char *user, const char *password) {
  return map_error(mailimap_login(s->imap, user, password));
}

int tpi_noop(tpi_session *s) { return map_error(mailimap_noop(s->imap)); }

int tpi_logout(tpi_session *s) { return map_error(mailimap_logout(s->imap)); }

static uint32_t selected_uidvalidity(tpi_session *s) {
  return s->imap->imap_selection_info != NULL ? s->imap->imap_selection_info->sel_uidvalidity : 0;
}

int tpi_examine(tpi_session *s, const char *mailbox, uint32_t *uidvalidity) {
  *uidvalidity = 0;
  int rc = map_error(mailimap_examine(s->imap, mailbox));
  if (rc == TPI_OK)
    *uidvalidity = selected_uidvalidity(s);
  return rc;
}

int tpi_select(tpi_session *s, const char *mailbox, uint32_t *uidvalidity) {
  *uidvalidity = 0;
  int rc = map_error(mailimap_select(s->imap, mailbox));
  if (rc == TPI_OK)
    *uidvalidity = selected_uidvalidity(s);
  return rc;
}

const char *tpi_last_response(tpi_session *s) {
  return s->imap->imap_response != NULL ? s->imap->imap_response : "";
}

int tpi_uid_search(tpi_session *s, const char *criteria, uint32_t **uids, size_t *count) {
  *uids = NULL;
  *count = 0;

  size_t cmd_len = strlen("UID SEARCH ") + strlen(criteria) + 1;
  char *cmd = malloc(cmd_len);
  if (cmd == NULL)
    return TPI_ERR_MEMORY;
  strcpy(cmd, "UID SEARCH ");
  strcat(cmd, criteria);

  /* mailimap_custom_command runs the normal response parser, which leaves
   * untagged SEARCH results in imap_response_info->rsp_search_result. */
  int r = mailimap_custom_command(s->imap, cmd);
  free(cmd);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);

  clist *res = s->imap->imap_response_info != NULL
                   ? s->imap->imap_response_info->rsp_search_result
                   : NULL;
  if (res == NULL || clist_count(res) == 0)
    return TPI_OK;

  uint32_t *out = malloc(sizeof(uint32_t) * (size_t)clist_count(res));
  if (out == NULL)
    return TPI_ERR_MEMORY;
  size_t n = 0;
  for (clistiter *it = clist_begin(res); it != NULL; it = clist_next(it))
    out[n++] = *(uint32_t *)clist_content(it);
  *uids = out;
  *count = n;
  return TPI_OK;
}

void tpi_uids_free(uint32_t *uids) { free(uids); }

/* Appends "\<flag>" to a growing space-separated buffer. */
static int flags_append(char **buf, size_t *len, const char *prefix, const char *flag) {
  size_t add = (*len > 0 ? 1 : 0) + strlen(prefix) + strlen(flag);
  char *grown = realloc(*buf, *len + add + 1);
  if (grown == NULL)
    return -1;
  char *p = grown + *len;
  if (*len > 0)
    *p++ = ' ';
  strcpy(p, prefix);
  strcat(p, flag);
  *buf = grown;
  *len += add;
  return 0;
}

static char *empty_string(void) { return calloc(1, 1); }

static int mailbox_flags(struct mailimap_mbx_list_flags *mf, char **out) {
  char *buf = NULL;
  size_t len = 0;
  if (mf != NULL) {
    if (mf->mbf_type == MAILIMAP_MBX_LIST_FLAGS_SFLAG) {
      const char *sflag = NULL;
      switch (mf->mbf_sflag) {
      case MAILIMAP_MBX_LIST_SFLAG_MARKED: sflag = "Marked"; break;
      case MAILIMAP_MBX_LIST_SFLAG_NOSELECT: sflag = "Noselect"; break;
      case MAILIMAP_MBX_LIST_SFLAG_UNMARKED: sflag = "Unmarked"; break;
      default: break;
      }
      if (sflag != NULL && flags_append(&buf, &len, "\\", sflag) != 0)
        goto oom;
    }
    for (clistiter *it = clist_begin(mf->mbf_oflags); it != NULL; it = clist_next(it)) {
      struct mailimap_mbx_list_oflag *of = clist_content(it);
      const char *name = of->of_type == MAILIMAP_MBX_LIST_OFLAG_NOINFERIORS ? "Noinferiors"
                                                                            : of->of_flag_ext;
      if (name != NULL && flags_append(&buf, &len, "\\", name) != 0)
        goto oom;
    }
  }
  *out = buf != NULL ? buf : empty_string();
  return *out != NULL ? TPI_OK : TPI_ERR_MEMORY;
oom:
  free(buf);
  return TPI_ERR_MEMORY;
}

int tpi_list(tpi_session *s, const char *reference, const char *pattern,
             tpi_mailbox **out, size_t *count) {
  *out = NULL;
  *count = 0;
  clist *result = NULL;
  int r = mailimap_list(s->imap, reference, pattern, &result);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);

  int rc = TPI_OK;
  size_t total = (size_t)clist_count(result);
  tpi_mailbox *items = calloc(total > 0 ? total : 1, sizeof(tpi_mailbox));
  if (items == NULL) {
    rc = TPI_ERR_MEMORY;
    goto done;
  }
  size_t n = 0;
  for (clistiter *it = clist_begin(result); it != NULL; it = clist_next(it)) {
    struct mailimap_mailbox_list *mb = clist_content(it);
    items[n].name = strdup(mb->mb_name);
    items[n].delimiter = mb->mb_delimiter;
    if (items[n].name == NULL || mailbox_flags(mb->mb_flag, &items[n].flags) != TPI_OK) {
      n++;
      tpi_mailboxes_free(items, n);
      rc = TPI_ERR_MEMORY;
      goto done;
    }
    n++;
  }
  *out = items;
  *count = n;
done:
  mailimap_list_result_free(result);
  return rc;
}

void tpi_mailboxes_free(tpi_mailbox *items, size_t count) {
  if (items == NULL)
    return;
  for (size_t i = 0; i < count; i++) {
    free(items[i].name);
    free(items[i].flags);
  }
  free(items);
}

int tpi_status_get(tpi_session *s, const char *mailbox, tpi_status *out) {
  memset(out, 0, sizeof(*out));
  struct mailimap_status_att_list *atts = mailimap_status_att_list_new_empty();
  if (atts == NULL)
    return TPI_ERR_MEMORY;
  if (mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_MESSAGES) != MAILIMAP_NO_ERROR ||
      mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_RECENT) != MAILIMAP_NO_ERROR ||
      mailimap_status_att_list_add(atts, MAILIMAP_STATUS_ATT_UNSEEN) != MAILIMAP_NO_ERROR) {
    mailimap_status_att_list_free(atts);
    return TPI_ERR_MEMORY;
  }
  struct mailimap_mailbox_data_status *st = NULL;
  int r = mailimap_status(s->imap, mailbox, atts, &st);
  mailimap_status_att_list_free(atts);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);
  /* libetpan returns OK with st == NULL when the server's tagged OK carried
   * no untagged STATUS data. */
  if (st == NULL)
    return TPI_ERR_PARSE;
  if (st->st_info_list != NULL) {
    for (clistiter *it = clist_begin(st->st_info_list); it != NULL; it = clist_next(it)) {
      struct mailimap_status_info *info = clist_content(it);
      switch (info->st_att) {
      case MAILIMAP_STATUS_ATT_MESSAGES: out->messages = info->st_value; break;
      case MAILIMAP_STATUS_ATT_RECENT: out->recent = info->st_value; break;
      case MAILIMAP_STATUS_ATT_UNSEEN: out->unseen = info->st_value; break;
      default: break;
      }
    }
  }
  mailimap_mailbox_data_status_free(st);
  return TPI_OK;
}

static struct mailimap_set *uid_set(const uint32_t *uids, size_t count) {
  struct mailimap_set *set = mailimap_set_new_empty();
  if (set == NULL)
    return NULL;
  for (size_t i = 0; i < count; i++) {
    if (mailimap_set_add_single(set, uids[i]) != MAILIMAP_NO_ERROR) {
      mailimap_set_free(set);
      return NULL;
    }
  }
  return set;
}

static int add_att(struct mailimap_fetch_type *ft, struct mailimap_fetch_att *att) {
  if (att == NULL)
    return -1;
  if (mailimap_fetch_type_new_fetch_att_list_add(ft, att) != MAILIMAP_NO_ERROR) {
    mailimap_fetch_att_free(att);
    return -1;
  }
  return 0;
}

static struct mailimap_fetch_type *fetch_type(int what) {
  struct mailimap_fetch_type *ft = mailimap_fetch_type_new_fetch_att_list_empty();
  if (ft == NULL)
    return NULL;
  if (add_att(ft, mailimap_fetch_att_new_uid()) != 0)
    goto fail;
  if ((what & TPI_FETCH_SIZE) && add_att(ft, mailimap_fetch_att_new_rfc822_size()) != 0)
    goto fail;
  if ((what & TPI_FETCH_FLAGS) && add_att(ft, mailimap_fetch_att_new_flags()) != 0)
    goto fail;
  if (what & (TPI_FETCH_HEADER | TPI_FETCH_BODY)) {
    struct mailimap_section *sec =
        (what & TPI_FETCH_BODY) ? mailimap_section_new(NULL) : mailimap_section_new_header();
    if (sec == NULL)
      goto fail;
    struct mailimap_fetch_att *att = mailimap_fetch_att_new_body_peek_section(sec);
    if (att == NULL) {
      mailimap_section_free(sec);
      goto fail;
    }
    if (add_att(ft, att) != 0)
      goto fail;
  }
  return ft;
fail:
  mailimap_fetch_type_free(ft);
  return NULL;
}

static int fetch_flags(struct mailimap_msg_att_dynamic *dyn, char **out) {
  char *buf = NULL;
  size_t len = 0;
  if (dyn != NULL && dyn->att_list != NULL) {
    for (clistiter *it = clist_begin(dyn->att_list); it != NULL; it = clist_next(it)) {
      struct mailimap_flag_fetch *ff = clist_content(it);
      int rc = 0;
      if (ff->fl_type == MAILIMAP_FLAG_FETCH_RECENT) {
        rc = flags_append(&buf, &len, "\\", "Recent");
      } else if (ff->fl_flag != NULL) {
        struct mailimap_flag *f = ff->fl_flag;
        switch (f->fl_type) {
        case MAILIMAP_FLAG_ANSWERED: rc = flags_append(&buf, &len, "\\", "Answered"); break;
        case MAILIMAP_FLAG_FLAGGED: rc = flags_append(&buf, &len, "\\", "Flagged"); break;
        case MAILIMAP_FLAG_DELETED: rc = flags_append(&buf, &len, "\\", "Deleted"); break;
        case MAILIMAP_FLAG_SEEN: rc = flags_append(&buf, &len, "\\", "Seen"); break;
        case MAILIMAP_FLAG_DRAFT: rc = flags_append(&buf, &len, "\\", "Draft"); break;
        case MAILIMAP_FLAG_KEYWORD:
          if (f->fl_data.fl_keyword != NULL)
            rc = flags_append(&buf, &len, "", f->fl_data.fl_keyword);
          break;
        case MAILIMAP_FLAG_EXTENSION:
          if (f->fl_data.fl_extension != NULL)
            rc = flags_append(&buf, &len, "\\", f->fl_data.fl_extension);
          break;
        default: break;
        }
      }
      if (rc != 0) {
        free(buf);
        return TPI_ERR_MEMORY;
      }
    }
  }
  *out = buf != NULL ? buf : empty_string();
  return *out != NULL ? TPI_OK : TPI_ERR_MEMORY;
}

static int fill_item(struct mailimap_msg_att *ma, int what, tpi_fetch_item *item) {
  for (clistiter *it = clist_begin(ma->att_list); it != NULL; it = clist_next(it)) {
    struct mailimap_msg_att_item *ai = clist_content(it);
    if (ai->att_type == MAILIMAP_MSG_ATT_ITEM_DYNAMIC) {
      if ((what & TPI_FETCH_FLAGS) && item->flags == NULL &&
          fetch_flags(ai->att_data.att_dyn, &item->flags) != TPI_OK)
        return TPI_ERR_MEMORY;
      continue;
    }
    if (ai->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC)
      continue;
    struct mailimap_msg_att_static *st = ai->att_data.att_static;
    switch (st->att_type) {
    case MAILIMAP_MSG_ATT_UID: item->uid = st->att_data.att_uid; break;
    case MAILIMAP_MSG_ATT_RFC822_SIZE: item->size = st->att_data.att_rfc822_size; break;
    case MAILIMAP_MSG_ATT_BODY_SECTION: {
      struct mailimap_msg_att_body_section *bs = st->att_data.att_body_section;
      if (bs == NULL || item->data != NULL)
        break;
      size_t n = bs->sec_body_part != NULL ? bs->sec_length : 0;
      item->data = malloc(n + 1);
      if (item->data == NULL)
        return TPI_ERR_MEMORY;
      if (n > 0)
        memcpy(item->data, bs->sec_body_part, n);
      item->data[n] = '\0';
      item->data_len = n;
      break;
    }
    default: break;
    }
  }
  /* FLAGS requested but server sent an empty list: report "" not NULL. */
  if ((what & TPI_FETCH_FLAGS) && item->flags == NULL) {
    item->flags = empty_string();
    if (item->flags == NULL)
      return TPI_ERR_MEMORY;
  }
  return TPI_OK;
}

int tpi_uid_fetch(tpi_session *s, const uint32_t *uids, size_t uid_count, int what,
                  tpi_fetch_item **out, size_t *count) {
  *out = NULL;
  *count = 0;
  struct mailimap_set *set = uid_set(uids, uid_count);
  if (set == NULL)
    return TPI_ERR_MEMORY;
  struct mailimap_fetch_type *ft = fetch_type(what);
  if (ft == NULL) {
    mailimap_set_free(set);
    return TPI_ERR_MEMORY;
  }
  clist *result = NULL;
  int r = mailimap_uid_fetch(s->imap, set, ft, &result);
  mailimap_fetch_type_free(ft);
  mailimap_set_free(set);
  if (r != MAILIMAP_NO_ERROR)
    return map_error(r);

  int rc = TPI_OK;
  size_t total = (size_t)clist_count(result);
  tpi_fetch_item *items = calloc(total > 0 ? total : 1, sizeof(tpi_fetch_item));
  if (items == NULL) {
    rc = TPI_ERR_MEMORY;
    goto done;
  }
  size_t n = 0;
  for (clistiter *it = clist_begin(result); it != NULL; it = clist_next(it)) {
    if (fill_item(clist_content(it), what, &items[n]) != TPI_OK) {
      tpi_fetch_free(items, n + 1);
      rc = TPI_ERR_MEMORY;
      goto done;
    }
    /* Servers may send unsolicited FETCH (e.g. flag updates) without UID. */
    if (items[n].uid != 0)
      n++;
    else {
      free(items[n].data);
      free(items[n].flags);
      memset(&items[n], 0, sizeof(items[n]));
    }
  }
  *out = items;
  *count = n;
done:
  mailimap_fetch_list_free(result);
  return rc;
}

void tpi_fetch_free(tpi_fetch_item *items, size_t count) {
  if (items == NULL)
    return;
  for (size_t i = 0; i < count; i++) {
    free(items[i].data);
    free(items[i].flags);
  }
  free(items);
}

static struct mailimap_flag *flag_from_string(const char *s) {
  if (s[0] != '\\') {
    char *kw = strdup(s);
    if (kw == NULL)
      return NULL;
    struct mailimap_flag *f = mailimap_flag_new_flag_keyword(kw);
    if (f == NULL)
      free(kw);
    return f;
  }
  const char *name = s + 1;
  if (strcasecmp(name, "Seen") == 0) return mailimap_flag_new_seen();
  if (strcasecmp(name, "Answered") == 0) return mailimap_flag_new_answered();
  if (strcasecmp(name, "Flagged") == 0) return mailimap_flag_new_flagged();
  if (strcasecmp(name, "Deleted") == 0) return mailimap_flag_new_deleted();
  if (strcasecmp(name, "Draft") == 0) return mailimap_flag_new_draft();
  char *ext = strdup(name);
  if (ext == NULL)
    return NULL;
  struct mailimap_flag *f = mailimap_flag_new_flag_extension(ext);
  if (f == NULL)
    free(ext);
  return f;
}

int tpi_uid_store_flags(tpi_session *s, const uint32_t *uids, size_t uid_count, int add,
                        const char *const *flags, size_t flag_count) {
  struct mailimap_flag_list *fl = mailimap_flag_list_new_empty();
  if (fl == NULL)
    return TPI_ERR_MEMORY;
  for (size_t i = 0; i < flag_count; i++) {
    struct mailimap_flag *f = flag_from_string(flags[i]);
    if (f == NULL || mailimap_flag_list_add(fl, f) != MAILIMAP_NO_ERROR) {
      if (f != NULL)
        mailimap_flag_free(f);
      mailimap_flag_list_free(fl);
      return TPI_ERR_MEMORY;
    }
  }
  struct mailimap_store_att_flags *sa = add ? mailimap_store_att_flags_new_add_flags(fl)
                                            : mailimap_store_att_flags_new_remove_flags(fl);
  if (sa == NULL) {
    mailimap_flag_list_free(fl);
    return TPI_ERR_MEMORY;
  }
  struct mailimap_set *set = uid_set(uids, uid_count);
  if (set == NULL) {
    mailimap_store_att_flags_free(sa);
    return TPI_ERR_MEMORY;
  }
  int r = mailimap_uid_store(s->imap, set, sa);
  mailimap_set_free(set);
  mailimap_store_att_flags_free(sa);
  return map_error(r);
}

int tpi_append(tpi_session *s, const char *mailbox, const char *data, size_t len) {
  return map_error(mailimap_append(s->imap, mailbox, NULL, NULL, data, len));
}
