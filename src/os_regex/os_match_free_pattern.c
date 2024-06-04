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

#include "os_regex.h"
#include "os_regex_internal.h"
#include "shared.h"


/* Release all the memory created by the compilation/execution phases */
void OSMatch_FreePattern(OSMatch *reg)
{
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

    os_free(reg->size);
    os_free(reg->match_fp);
    os_free(reg->raw);

    return;
}
