/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "manage_agents.h"

/* Global variables */
static char __user_buffer[USER_SIZE + 1];
static char *__user_buffer_pt;


char *read_from_user()
{
    memset(__user_buffer, '\0', USER_SIZE + 1);

    if ((fgets(__user_buffer, USER_SIZE - 1, stdin) == NULL) ||
            (strlen(__user_buffer) >= (USER_SIZE - 2))) {
        printf(INPUT_LARGE);
        exit(1);
    }

    __user_buffer_pt = chomp(__user_buffer);

    return (__user_buffer_pt);
}

