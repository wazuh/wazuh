/* Included and modified strings.c from the OpenBSD project */

/*
 * Copyright (C) 2015, Wazuh Inc.
 * Copyright (c) 1980, 1987, 1993
 * The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef WIN32
#include <sys/types.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include "file_op.h"
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <unistd.h>
#include <netinet/in.h>

#if defined Darwin || defined ALPINE

/* For some reason darwin does not have that */
struct exec {
    unsigned long a_info;         /* Use macros N_MAGIC, etc for access */
    unsigned char   a_machtype;   /* machine type */
    unsigned short  a_magic;      /* magic number */
    unsigned a_text;              /* length of text, in bytes */
    unsigned a_data;              /* length of data, in bytes */
    unsigned a_bss;               /* length of uninitialized data area for file, in bytes */
    unsigned a_syms;              /* length of symbol table data in file, in bytes */
    unsigned a_entry;             /* start address */
    unsigned a_trsize;            /* length of relocation info for text, in bytes */
    unsigned a_drsize;            /* length of relocation info for data, in bytes */
};

#define OMAGIC      0407     /* Object file or impure executable */
#define NMAGIC      0410     /* Code indicating pure executable */
#define ZMAGIC      0413     /* Code indicating demand-paged executable */
#define BMAGIC      0415     /* Used by a b.out object */
#define M_OLDSUN2      0

#else

#include <a.out.h>

#endif

#ifndef PAGSIZ
#define       PAGSIZ          0x02000
#endif

#ifndef OLD_PAGSIZ
#define       OLD_PAGSIZ      0x00800
#endif

#ifndef N_BADMAG
#define       N_BADMAG(x) \
    (((x).a_magic)!=OMAGIC && ((x).a_magic)!=NMAGIC && ((x).a_magic)!=ZMAGIC)
#endif  /* N_BADMAG */

#ifndef N_PAGSIZ
#define       N_PAGSIZ(x) \
        ((x).a_machtype == M_OLDSUN2? OLD_PAGSIZ : PAGSIZ)
#endif

#ifndef N_TXTOFF
#define       N_TXTOFF(x) \
        /* text segment */ \
    ((x).a_machtype == M_OLDSUN2 \
           ? ((x).a_magic==ZMAGIC ? N_PAGSIZ(x) : sizeof (struct exec)) \
           : ((x).a_magic==ZMAGIC ? 0 : sizeof (struct exec)) )
#endif /* N_TXTOFF */

#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/regex_op.h"

#include "error_messages/error_messages.h"
#include "error_messages/debug_messages.h"

#define STR_MINLEN  4       /* Minimum length for a string */

#define ISSTR(ch)   (isascii(ch) && (isprint(ch) || ch == '\t'))

typedef struct exec EXEC;

typedef struct _os_strings {
    int head_len;
    int read_len;
    int hcnt;
    long foff;
    unsigned char hbfr[sizeof(EXEC)];
    FILE *fp;
} os_strings;

/* Read each character from a binary file */
int os_getch(os_strings *oss);


/* List the strings of a binary and check if the regex given is there */
int os_string(char *file, char *regex)
{
    int ch, cnt;
    unsigned char *C;
    unsigned char *bfr;
    char line[OS_SIZE_1024 + 1];
    char *buf;
    EXEC *head = NULL;
    os_strings oss;

    /* Return didn't match */
    if (!file || !regex) {
        return (0);
    }

    /* Allocate the buffer */
    bfr = (unsigned char *) calloc(STR_MINLEN + 2, sizeof(unsigned char));
    if (!bfr) {
        mterror(ARGV0, MEM_ERROR, errno, strerror(errno));
        return (0);
    }

    /* Open the file */
    oss.fp = wfopen(file, "r");
    if (!oss.fp) {
        free(bfr);
        return (0);
    }

    /* Clean the line */
    memset(line, '\0', OS_SIZE_1024 + 1);

    /* Start (from old strings.c) */
    oss.foff = 0;
    oss.head_len = 0;
    oss.read_len = -1;
    head = (EXEC *)oss.hbfr;

    if ((oss.head_len = read(fileno(oss.fp), head, sizeof(EXEC))) == -1) {
        oss.head_len = 0;
        oss.read_len = -1;
    } else if (oss.head_len == sizeof(EXEC) && !N_BADMAG(*head)) {
        oss.foff = N_TXTOFF(*head);
        if (fseek(stdin, oss.foff, SEEK_SET) == -1) {
            oss.read_len = -1;
        } else {
            oss.read_len = head->a_text + head->a_data;
        }

        oss.head_len = 0;
    } else {
        oss.hcnt = 0;
    }

    /* Read the file and perform the regex comparison */
    for (cnt = 0, C = bfr; (ch = os_getch(&oss)) != EOF;) {
        if (ISSTR(ch)) {
            if (!cnt) {
                C = bfr;
            }
            *C++ = ch;
            if (++cnt < STR_MINLEN) {
                continue;
            }

            strncpy(line, (char *)bfr, STR_MINLEN + 1);
            buf = line;
            buf += strlen(line);

            while ((ch = os_getch(&oss)) != EOF && ISSTR(ch)) {
                if (cnt < OS_SIZE_1024) {
                    *buf = (char)ch;
                    buf++;
                } else {
                    *buf = '\0';
                    break;
                }
                cnt++;
            }

            *buf = '\0';

            if (OS_PRegex(line, regex)) {
                if (oss.fp) {
                    fclose(oss.fp);
                }
                free(bfr);
                return (1);
            }
        }

        cnt = 0;
    }

    if (oss.fp) {
        fclose(oss.fp);
    }
    free(bfr);
    return (0);
}

/* Get next character from wherever */
int os_getch(os_strings *oss)
{
    ++oss->foff;
    if (oss->head_len) {
        if (oss->hcnt < oss->head_len) {
            return ((int)oss->hbfr[oss->hcnt++]);
        }
        oss->head_len = 0;
    }
    if (oss->read_len == -1 || oss->read_len-- > 0) {
        return (fgetc(oss->fp));
    }
    return (EOF);
}

#else
int os_string(__attribute__((unused)) char *file, __attribute__((unused)) char *regex)
{
    return (0);
}
#endif
