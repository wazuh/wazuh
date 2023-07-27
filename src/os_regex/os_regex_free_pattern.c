/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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
    if(reg == NULL)
        return;

    /* Free the patterns */
    if (reg->patterns) {
        char **pattern = reg->patterns;
        while (*pattern) {
            os_free(*pattern);
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
            os_free(reg->prts_closure[i]);
            i++;
        }
        os_free(reg->prts_closure);
    }

    /* Free the str */
    if (reg->d_prts_str) {
        i = 0;
        while (reg->d_prts_str[i]) {
            os_free(reg->d_prts_str[i]);
            i++;
        }
        os_free(reg->d_prts_str);
    }

    /* Free the sub strings */
    if (reg->d_sub_strings) {
        w_FreeArray(reg->d_sub_strings);
        os_free(reg->d_sub_strings);
    }

    os_free(reg->d_size.prts_str_size);
    if (reg->mutex_initialised)
        w_mutex_destroy(&reg->mutex);

    return;
}
