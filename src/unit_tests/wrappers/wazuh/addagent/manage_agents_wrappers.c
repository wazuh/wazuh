/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "manage_agents_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_OS_AddNewAgent(__attribute__((unused)) void *keys, const char *id, 
                    const char *name, const char *ip, const char *key) {
    check_expected(id);
    check_expected(name);
    check_expected(ip);
    check_expected(key);
    return mock();
}

void __wrap_OS_RemoveAgentGroup(__attribute__((unused)) const char *id) {
    // Empty wrapper
}
