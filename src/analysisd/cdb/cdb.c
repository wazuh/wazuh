/* Public domain */
/* Adapted from DJB's original cdb-0.75 package */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "cdb.h"

#ifndef EPROTO
#define EPROTO -15  /* cdb 0.75's default for PROTOless systems */
#endif


void cdb_free(struct cdb *c)
{
    if (c->map) {
        munmap(c->map, c->size);
        c->map = 0;
    }
}

void cdb_findstart(struct cdb *c)
{
    c->loop = 0;
}

void cdb_init(struct cdb *c, int fd)
{
    struct stat st;
    char *x;

    cdb_free(c);
    cdb_findstart(c);
    c->fd = fd;

    if (fstat(fd, &st) == 0)
        if ((size_t) st.st_size <= 0xffffffff) {
            x = (char *) mmap(0, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
            if (x + 1) {
                c->size = st.st_size;
                c->map = x;
            }
        }
}

int cdb_read(struct cdb *c, char *buf, unsigned int len, uint32 pos)
{
    if (c->map) {
        if ((pos > c->size) || (c->size - pos < len)) {
            goto FORMAT;
        }
        memcpy(buf, c->map + pos, len);
    } else {
        if (lseek(c->fd, pos, SEEK_SET) == -1) {
            return -1;
        }
        /* if (seek_set(c->fd,pos) == -1) return -1; */
        while (len > 0) {
            int r;
            do {
                r = read(c->fd, buf, len);
            } while ((r == -1) && (errno == EINTR));
            if (r == -1) {
                return -1;
            }
            if (r == 0) {
                goto FORMAT;
            }
            buf += r;
            len -= r;
        }
    }
    return 0;

FORMAT:
    errno = EPROTO;
    return -1;
}

static int match(struct cdb *c, char *key, unsigned int len, uint32 pos)
{
    char buf[32];
    unsigned int n;

    while (len > 0) {
        n = sizeof buf;
        if (n > len) {
            n = len;
        }
        if (cdb_read(c, buf, n, pos) == -1) {
            return -1;
        }
        if (memcmp(buf, key, n)) {
            return 0;
        }
        pos += n;
        key += n;
        len -= n;
    }
    return 1;
}

int cdb_findnext(struct cdb *c, char *key, unsigned int len)
{
    char buf[8];
    uint32 pos;
    uint32 u;

    if (!c->loop) {
        u = cdb_hash(key, len);
        if (cdb_read(c, buf, 8, (u << 3) & 2047) == -1) {
            return -1;
        }
        uint32_unpack(buf + 4, &c->hslots);
        if (!c->hslots) {
            return 0;
        }
        uint32_unpack(buf, &c->hpos);
        c->khash = u;
        u >>= 8;
        u %= c->hslots;
        u <<= 3;
        c->kpos = c->hpos + u;
    }

    while (c->loop < c->hslots) {
        if (cdb_read(c, buf, 8, c->kpos) == -1) {
            return -1;
        }
        uint32_unpack(buf + 4, &pos);
        if (!pos) {
            return 0;
        }
        c->loop += 1;
        c->kpos += 8;
        if (c->kpos == c->hpos + (c->hslots << 3)) {
            c->kpos = c->hpos;
        }
        uint32_unpack(buf, &u);
        if (u == c->khash) {
            if (cdb_read(c, buf, 8, pos) == -1) {
                return -1;
            }
            uint32_unpack(buf, &u);
            if (u == len)
                switch (match(c, key, len, pos + 8)) {
                    case -1:
                        return -1;
                    case 1:
                        uint32_unpack(buf + 4, &c->dlen);
                        c->dpos = pos + 8 + len;
                        return 1;
                }
        }
    }

    return 0;
}

int cdb_find(struct cdb *c, char *key, unsigned int len)
{
    cdb_findstart(c);
    return cdb_findnext(c, key, len);
}
