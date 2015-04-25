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


/* Release all the memory created by the compilation/executation phases */
void OSRegex_FreePattern(OSRegex *reg)
{
    int i = 0;

    /* Free the patterns */
    if (reg->patterns) {
        char **pattern = reg->patterns;
        while (*pattern) {
            if (*pattern) {
                free(*pattern);
            }
            pattern++;
        }

        free(reg->patterns);
        reg->patterns = NULL;
    }

    /* Free the flags */
    free(reg->flags);
    reg->flags = NULL;

    /* Free the closure */
    if (reg->prts_closure) {
        i = 0;
        while (reg->prts_closure[i]) {
            free(reg->prts_closure[i]);
            i++;
        }
        free(reg->prts_closure);
        reg->prts_closure = NULL;
    }

    /* Free the str */
    if (reg->prts_str) {
        i = 0;
        while (reg->prts_str[i]) {
            free(reg->prts_str[i]);
            i++;
        }
        free(reg->prts_str);
        reg->prts_str = NULL;
    }

    /* Free the sub strings */
    if (reg->sub_strings) {
        OSRegex_FreeSubStrings(reg);
        free(reg->sub_strings);
        reg->sub_strings = NULL;
    }

    return;
}

