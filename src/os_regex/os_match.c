/*   $OSSEC, os_regex.c, v0.4, 2006/01/02, Daniel B. Cid$   */

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



/** int OS_Match2(char *pattern, char *str) v0.4
 *
 *  This function is a wrapper around the compile/execute
 *  functions. It should only be used when the pattern is
 *  only going to be used once.
 *  Returns 1 on success or 0 on failure.
 */
int OS_Match2(char *pattern, char *str)
{
    int r_code = 0;
    OSMatch reg;

    /* If the compilation failed, we don't need to free anything */
    if(OSMatch_Compile(pattern, &reg, 0))
    {
        if(OSMatch_Execute(str,strlen(str), &reg))
        {
            r_code = 1;
        }

        OSMatch_FreePattern(&reg);
    }

    return(r_code);
}


#ifdef NOTHINGEMPTY
/** int OS_Match3(char *pattern, char *str) v2.6
 *
 *  This function is used
 *  to match any values from a delimited string
 *  e.g. match pattern "abc" from string "123,abc,xyz"
 */
int OS_Match3(char *pattern, char *str, char *delimiter)
{
    int r_code = 0;
    char *token = NULL;
    char *dupstr = NULL;
    char *saveptr = NULL;

    /* debug2("1. str [%s], dupstr [%s], token[%s], delim [%s]", str, dupstr, token, delimiter); */

    os_strdup(str, dupstr);
    /* debug2("2. str [%s], dupstr [%s], token[%s], delim [%s]", str, dupstr, token, delimiter); */

    token = strtok_r(dupstr, delimiter, &saveptr);
    /* debug2("3. str [%s], dupstr [%s], token[%s], delim [%s]", str, dupstr, token, delimiter); */

    while (token != NULL)
    {
        debug2("Matching [%s] with [%s]", pattern, token);
        if (!strcmp(pattern, token))
        {
            r_code = 1;
            break;
        }

        token = strtok_r(NULL, delimiter, &saveptr);
    }

    /* debug2("4. str [%s], dupstr [%s], token[%s], delim [%s]", str, dupstr, token, delimiter); */
    free(dupstr);
    return(r_code);
}
#endif


/* EOF */
