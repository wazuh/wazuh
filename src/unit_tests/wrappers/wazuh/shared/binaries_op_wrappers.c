/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "binaries_op_wrappers.h"
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_get_binary_path(const char *command, char **path) {
    check_expected(command);
    *path = (char*)mock_ptr_type(char*);

    return mock_type(int);
}
