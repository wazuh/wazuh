/* $OSSEC, os_regex_free_substrings.c, v0.1, 2006/01/02, Daniel B. Cid$ */

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


/** int OSRegex_FreeSubStrings(OSRegex *reg) v0.1
 * Release all the memory created to store the sub strings.
 * Returns void.
 */
void OSRegex_FreeSubStrings(OSRegex *reg)
{
    /* Freeing the sub strings */
    if(reg->sub_strings)
    {
        int i = 0;
        while(reg->sub_strings[i])
        {
            free(reg->sub_strings[i]);
            reg->sub_strings[i] = NULL;
            i++;
        }
    }
    return;
}


/* EOF */
