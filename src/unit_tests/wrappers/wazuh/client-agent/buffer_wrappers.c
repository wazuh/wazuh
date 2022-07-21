/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "buffer_wrappers.h"
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_w_agentd_get_buffer_lenght() {
    return mock();
}
