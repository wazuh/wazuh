/*   $OSSEC, os_match_execute.c, v0.1, 2006/04/18, Daniel B. Cid$   */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "os_regex.h"
#include "os_regex_internal.h"


/** Internal matching **/
int _OS_Match(const char *pattern, const char *str, size_t str_len, size_t size)
{
    size_t i = 0,j;
    const char *pt = pattern;

    if(str_len < size)
        return(FALSE);

    size = str_len - size;

    /* Look to match the first pattern */
    do
    {
        /* Match */
        if(charmap[(uchar)str[i]] == *pt)
        {
            pt++;
            j = i+1;

            while(*pt != '\0')
            {
                if(str[j] == '\0')
                    return(FALSE);

                else if(*pt != charmap[(uchar)str[j]])
                {
                    pt = pattern;
                    goto nnext;
                }
                j++;pt++;
            }
            return(TRUE);
            nnext:
            continue;
        }
    }while(++i <= size);

    return(FALSE);
}


/** Internal matching **/
int _os_strncmp(const char *pattern, const char *str, __attribute__((unused)) size_t str_len, size_t size)
{
    if(strncasecmp(pattern, str, size) == 0)
        return(TRUE);

    return(FALSE);
}

/** Internal matching **/
int _os_strcmp(const char *pattern, const char *str, __attribute__((unused)) size_t str_len, __attribute__((unused)) size_t size)
{
    if(strcasecmp(pattern, str) == 0)
        return(TRUE);

    return(FALSE);
}

int _os_strmatch(__attribute__((unused)) const char *pattern, __attribute__((unused)) const char *str,
        __attribute__((unused)) size_t str_len, __attribute__((unused)) size_t size)
{
    return(TRUE);
}

int _os_strstr(const char *pattern, const char *str, __attribute__((unused)) size_t str_len, __attribute__((unused)) size_t size)
{
    if(strstr(str, pattern) != NULL)
    {
        return(TRUE);
    }
    return(FALSE);
}


/** Internal matching **/
int _os_strcmp_last(const char *pattern, const char *str, size_t str_len, size_t size)
{
    /* Size of the string must be bigger */
    if(str_len < size)
        return(FALSE);

    if(strcasecmp(pattern, str + (str_len - size)) == 0)
        return(TRUE);

    return(FALSE);
}


/** int OSMatch_Execute(char *str, int str_len, OSMatch *reg) v0.1
 * Compare an already compiled pattern with
 * a not NULL string.
 * Returns 1 on success or 0 on error.
 * The error code is set on reg->error.
 */
int OSMatch_Execute(const char *str, size_t str_len, OSMatch *reg)
{
    short int i = 0;

    /* The string can't be NULL */
    if(str == NULL)
    {
        reg->error = OS_REGEX_STR_NULL;
        return(0);
    }


    /* Looping on all sub patterns */
    while(reg->patterns[i])
    {
        if(reg->match_fp[i](reg->patterns[i],
                            str,
                            str_len,
                            reg->size[i]) == TRUE)
        {
            return(1);
        }
        i++;
    }

    return(0);
}


/* EOF */
