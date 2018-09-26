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
#include "shared.h"

/* Release all the memory created by the compilation/execution phases */
void OSRegex_FreePattern(OSRegex *reg)
{
    int i = 0, j;

    w_mutex_lock((pthread_mutex_t *)&reg->mutex);
    /* Free the patterns */
    if (reg->patterns) {
        char **pattern = reg->patterns;
        while (*pattern) {
            if (*pattern) {
                free(*pattern);
            }
            pattern++;
        }

        os_free(reg->patterns);
    }

    /* Free the flags */
    os_free(reg->flags);

    if (reg->raw) {
        os_free(reg->raw);
    }

    /* Free the closure */
    if (reg->prts_closure) {
        i = 0;
        while (reg->prts_closure[i]) {
            free(reg->prts_closure[i]);
            i++;
        }
        os_free(reg->prts_closure);
    }

    /* Free the matching array*/
    for (j = 0; j < reg->instances; j++) {
        /* Free the str */
        i = 0;
        if (reg->matching[j]->prts_str) {
            while (reg->matching[j]->prts_str[i]) {
                free(reg->matching[j]->prts_str[i]);
                i++;
            }
            os_free(reg->matching[j]->prts_str);
        }

        /* Free the sub strings */
        if (reg->matching[j]->sub_strings) {
            OSRegex_FreeSubStrings(reg, j);
            os_free(reg->matching[j]->sub_strings);
        }
        free(reg->matching[j]);
    }
    free(reg->matching);

    w_mutex_unlock((pthread_mutex_t *)&reg->mutex);
    return;
}
