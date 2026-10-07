/* POSIX regex half of the tpi shim (ADR 0017): libc regcomp/regexec. */
#include "tpi.h"

#include <regex.h>
#include <stdlib.h>
#include <string.h>

struct tpi_regex {
  regex_t re;
};

tpi_regex *tpi_regex_compile(const char *pattern, char *err, size_t errlen) {
  tpi_regex *r = calloc(1, sizeof(*r));
  if (r == NULL) {
    if (errlen > 0)
      strncpy(err, "out of memory", errlen - 1);
    return NULL;
  }
  int rc = regcomp(&r->re, pattern, REG_EXTENDED | REG_ICASE | REG_NOSUB);
  if (rc != 0) {
    if (errlen > 0)
      regerror(rc, &r->re, err, errlen);
    free(r);
    return NULL;
  }
  return r;
}

int tpi_regex_match(const tpi_regex *r, const char *text) {
  return regexec(&r->re, text, 0, NULL, 0) == 0;
}

void tpi_regex_free(tpi_regex *r) {
  if (r == NULL)
    return;
  regfree(&r->re);
  free(r);
}
