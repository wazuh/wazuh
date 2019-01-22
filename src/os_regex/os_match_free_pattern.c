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

#include "os_regex.h"
#include "os_regex_internal.h"


/* Release all the memory created by the compilation/execution phases */
void OSMatch_FreePattern(OSMatch *reg)
{
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

    free(reg->size);
    free(reg->match_fp);
    free(reg->raw);

    reg->size = NULL;
    reg->match_fp = NULL;

    return;
}
