/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
    int i = 0;

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

    /* Free the str */
    if (reg->d_prts_str) {
        i = 0;
        while (reg->d_prts_str[i]) {
            free(reg->d_prts_str[i]);
            i++;
        }
        free(reg->d_prts_str);
        reg->d_prts_str = NULL;
    }

    /* Free the sub strings */
    if (reg->d_sub_strings) {
        w_FreeArray(reg->d_sub_strings);
        free(reg->d_sub_strings);
        reg->d_sub_strings = NULL;
    }

    free(reg->d_size.prts_str_size);

    w_mutex_unlock((pthread_mutex_t *)&reg->mutex);
    return;
}
