/*   $OSSEC, os_regex_match.c, v0.3, 2005/06/09, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "os_regex.h"
#include "os_regex_internal.h"

/* Algorithm:
 *       Go as faster as you can :)
 *
 * Supports:
 *      '|' to separate multiple OR patterns
 *      '^' to match the begining of a string
 */


/** Prototypes **/
static int _InternalMatch(const char *pattern, const char *str,size_t count) __attribute__((nonnull));


/* OS_WordMatch v0.3:
 * Searches for  pattern in the string
 */
int OS_WordMatch(const char *pattern, const char *str)
{
    size_t count = 0;

    if(*pattern == '\0')
        return(FALSE);

    do
    {
        if(pattern[count] == '|')
        {
            /* If we match '|' , search with
             * we have so far.
             */
            if(_InternalMatch(pattern, str, count))
            {
                return(TRUE);
            }
            else
            {
                pattern += count+1;
                count = 0;
                continue;
            }
        }

        count++;

    }while(pattern[count] != '\0');

    /* Last check until end of string */
    return(_InternalMatch(pattern, str,count));
}

/* Internal match function */
static int _InternalMatch(const char *pattern, const char *str, size_t pattern_size)
{
    const uchar *pt = (const uchar *)pattern;
    const uchar *st = (const uchar *)str;

    const uchar last_char = (const uchar) pattern[pattern_size];


    /* Return true for some odd expressions */
    if(*pattern == '\0')
        return(TRUE);


    /* If '^' specified, just do a strncasecmp */
    else if(*pattern == '^')
    {
        pattern++;
        pattern_size --;

        /* Compare two string */
        if(strncasecmp(pattern,str,pattern_size) == 0)
            return(TRUE);
        return(FALSE);
    }


    /* Null line */
    else if(*st == '\0')
        return(FALSE);


    /* Look to match the first pattern */
    do
    {
        /* Match */
        if(charmap[*st] == charmap[*pt])
        {
            str = (const char *)st++;
            pt++;

            while(*pt != last_char)
            {
                if(*st == '\0')
                    return(FALSE);

                else if(charmap[*pt] != charmap[*st])
                    goto error;

                st++;pt++;
            }

            /* Return here if pt == last_char */
            return(TRUE);

            error:
                st = (const uchar *)str;
                pt = (const uchar *)pattern;

        }

        st++;
    }while(*st != '\0');

    return(FALSE);
}
/* EOF */
