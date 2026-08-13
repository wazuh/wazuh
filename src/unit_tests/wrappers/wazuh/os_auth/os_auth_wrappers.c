/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_auth_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

void __wrap_add_remove(__attribute__((unused)) const keyentry *entry) {
    // Empty wrapper
}

