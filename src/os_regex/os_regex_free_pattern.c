/*   $OSSEC, os_regex_free_pattern.c, v0.1, 2006/01/02, Daniel B. Cid$   */

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


/** int OSRegex_FreePattern(SRegex *reg) v0.1
 * Release all the memory created by the compilation/executation
 * phases.
 * Returns void.
 */
void OSRegex_FreePattern(OSRegex *reg)
{
    int i = 0;

    /* Freeing the patterns */
    if(reg->patterns)
    {
        char **pattern = reg->patterns;
        while(*pattern)
        {
            if(*pattern)
                free(*pattern);
            pattern++;
        }

        free(reg->patterns);
        reg->patterns = NULL;
    }

    /* Freeing the flags */
    free(reg->flags);
    reg->flags = NULL;

    /* Freeing the closure */
    if(reg->prts_closure)
    {
        i = 0;
        while(reg->prts_closure[i])
        {
            free(reg->prts_closure[i]);
            i++;
        }
        free(reg->prts_closure);
        reg->prts_closure = NULL;
    }

    /* Freeing the str */
    if(reg->prts_str)
    {
        i = 0;
        while(reg->prts_str[i])
        {
            free(reg->prts_str[i]);
            i++;
        }
        free(reg->prts_str);
        reg->prts_str = NULL;
    }

    /* Freeing the sub strings */
    if(reg->sub_strings)
    {
        OSRegex_FreeSubStrings(reg);
        free(reg->sub_strings);
        reg->sub_strings = NULL;
    }

    return;
}


/* EOF */
