/** \ingroup rpmbuild
 * \file build/misc.c
 */
#include "system.h"

#include <ctype.h>
#include <stdlib.h>
#include <rpm/rpmstring.h>
#include "rpmbuild_misc.h"
#include "debug.h"

#define BUF_CHUNK 1024

struct StringBufRec {
    char *buf;
    char *tail;     /* Points to first "free" char */
    int allocated;
    int free;
};

StringBuf newStringBuf(void)
{
    StringBuf sb = (StringBuf)xmalloc(sizeof(*sb));

    sb->free = sb->allocated = BUF_CHUNK;
    sb->buf = (char *)xcalloc(sb->allocated, sizeof(*sb->buf));
    sb->buf[0] = '\0';
    sb->tail = sb->buf;
    
    return sb;
}

StringBuf freeStringBuf(StringBuf sb)
{
    if (sb) {
	sb->buf = _free(sb->buf);
	sb = _free(sb);
    }
    return sb;
}

void stripTrailingBlanksStringBuf(StringBuf sb)
{
    while (sb->free != sb->allocated) {
	if (! risspace(*(sb->tail - 1)))
	    break;
	sb->free++;
	sb->tail--;
    }
    sb->tail[0] = '\0';
}

const char * getStringBuf(StringBuf sb)
{
    return (sb != NULL) ? sb->buf : NULL;
}

void appendStringBufAux(StringBuf sb, const char *s, int nl)
{
    int l;

    l = strlen(s);
    /* If free == l there is no room for NULL terminator! */
    while ((l + nl + 1) > sb->free) {
        sb->allocated += BUF_CHUNK;
	sb->free += BUF_CHUNK;
        sb->buf = xrealloc(sb->buf, sb->allocated);
	sb->tail = sb->buf + (sb->allocated - sb->free);
    }
    
    /* FIX: shrug */
    strcpy(sb->tail, s);
    sb->tail += l;
    sb->free -= l;
    if (nl) {
        sb->tail[0] = '\n';
        sb->tail[1] = '\0';
	sb->tail++;
	sb->free--;
    }
}

int parseUnsignedNum(const char * line, uint32_t * res)
{
    char * s1 = NULL;
    unsigned long rc;
    uint32_t result;

    if (line == NULL) return -1;

    while (isspace(*line)) line++;
    if (!isdigit(*line)) return -1;

    rc = strtoul(line, &s1, 10);

    if (*s1 || s1 == line || rc == ULONG_MAX || rc > UINT_MAX)
        return -1;

    result = (uint32_t)rc;
    if (res) *res = result;

    return 0;
}
