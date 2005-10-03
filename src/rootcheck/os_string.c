/*   $OSSEC, os_strings.c, v0.1, 2005/10/02, Daniel B. Cid$   */

/* Included and modified strings.c from the OpenBSD project.
 * Copyright bellow.
 */
 
/*
 * Copyright (c) 1980, 1987, 1993
 *	The Regents of the University of California.  All rights reserved.
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


#include <sys/types.h>

#include <a.out.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <unistd.h>
#include <err.h>

#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/regex_op.h"

#include "error_messages/error_messages.h"

#define STR_MINLEN  4       /* Minumum length for a string */

#define ISSTR(ch)	(isascii(ch) && (isprint(ch) || ch == '\t'))

int dbg_flag;
int chroot_flag;

typedef struct exec EXEC;    

typedef struct _os_strings
{
    int head_len;
    int read_len;
    int hcnt;
    long foff;
    unsigned char hbfr[sizeof(EXEC)];
    FILE *fp;
}os_strings;


/* os_getch: Read each character from a binary file */
int os_getch(os_strings *oss);


/* os_strings: List the strings of a binary and
 * check if the regex given is there.
 */
int os_string(char *file, char *regex)
{
    int ch, cnt;
    
    unsigned char *C;
    unsigned char *bfr;
 
    char line[OS_MAXSTR +1];
    char *buf;
    
    EXEC *head;

    os_strings oss;
   
    /* Return didn't match */
    if(!file || !regex)
    {
        return(0);
    }
    
    
    /* Allocating for the buffer */ 
    bfr = calloc(STR_MINLEN + 1, sizeof(char *));
    if (!bfr)
    {
        merror(MEM_ERROR, ARGV0);
        return(0);
    }

    /* Opening the file */
    oss.fp = fopen(file, "r");
    if(!oss.fp)
    {
        merror(MEM_ERROR, ARGV0);
        return(0);
    }

    /* cleaning the line */
    memset(line, '\0', OS_MAXSTR +1);
    
    /* starting .. (from old strings.c) */
    oss.foff = 0;
    oss.head_len = 0;
    
    oss.read_len = -1;
    head = (EXEC *)oss.hbfr;

    
    if ((oss.head_len = read(fileno(oss.fp), head, sizeof(EXEC))) == -1)
    {
        oss.head_len = 0;
        oss.read_len = -1;
    }
    else if (oss.head_len == sizeof(EXEC) && !N_BADMAG(*head)) 
    {
        oss.foff = N_TXTOFF(*head);
        if (fseek(stdin, oss.foff, SEEK_SET) == -1)
        {
            oss.read_len = -1;
        }
        else
        {
            oss.read_len = head->a_text + head->a_data;
        }

        oss.head_len = 0;
    }
    else
    {
        oss.hcnt = 0;
    }


    /* Read the file and perform the regex comparison */
    for (cnt = 0; (ch = os_getch(&oss)) != EOF;) 
    {
        if (ISSTR(ch)) 
        {
            if (!cnt)
                C = bfr;
            *C++ = ch;
            if (++cnt < STR_MINLEN)
                continue;
            
            strncpy(line, bfr, STR_MINLEN +1);    
            buf = line;
            buf+=strlen(line);
            

            while ((ch = os_getch(&oss)) != EOF && ISSTR(ch))
            {
                if(cnt < OS_MAXSTR)
                {
                    *buf = (char)ch;
                    buf++;
                }
                else
                {
                    *buf = '\0';
                    break;
                }
            }

            *buf = '\0';

            if(OS_PRegex(line, regex))
            {
                return(1);
            }
        }
        cnt = 0;
    }

    return(0);
}


/*
 * getch (os_getch, modified)--
 *	get next character from wherever
 */
int os_getch(os_strings *oss)
{
	++oss->foff;
	if (oss->head_len) 
    {
		if (oss->hcnt < oss->head_len)
			return((int)oss->hbfr[oss->hcnt++]);
		oss->head_len = 0;
	}
	if (oss->read_len == -1 || oss->read_len-- > 0)
    {
		return(fgetc(oss->fp));
    }
	return(EOF);
}

/* EOF */
