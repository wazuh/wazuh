#include "bulk.h"

int bulk_reserve(bulk_t *b, size_t add) {
    size_t need = b->len + add;
    if (need <= b->cap) return 0;
    size_t ncap = b->cap ? b->cap : 4096;
    while (ncap < need) ncap *= 2;
    char *nb;
    os_realloc(b->buf, ncap, nb);
    if (!nb) return -1;
    b->buf = nb; b->cap = ncap;
    return 0;
}

void bulk_init(bulk_t *b, size_t cap_hint) {
    b->buf = NULL; b->len = 0; b->cap = 0; if (cap_hint) bulk_reserve(b, cap_hint);
}

void bulk_free(bulk_t *b) {
    os_free(b->buf); b->buf = NULL; b->len = b->cap = 0;
}

int bulk_append(bulk_t *b, const void *p, size_t n) {
    if (bulk_reserve(b, n) < 0) return -1; memcpy(b->buf + b->len, p, n); b->len += n; return 0;
}

int bulk_append_fmt(bulk_t *b, const char *fmt, ...) {
    char tmp[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return -1;
    if ((size_t)n < sizeof(tmp)) return bulk_append(b, tmp, (size_t)n);
    // chain larger than tmp: book exactly
    char *big;
    os_malloc((size_t)n + 1, big);
    if (!big) return -1;
    va_start(ap, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, ap);
    va_end(ap);
    int rc = bulk_append(b, big, (size_t)n);
    os_free(big);
    return rc;
}
