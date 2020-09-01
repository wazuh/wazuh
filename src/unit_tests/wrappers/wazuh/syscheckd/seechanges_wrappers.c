/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "seechanges_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

char *__wrap_seechanges_addfile(const char *filename) {
    check_expected(filename);

    return mock_type(char*);
}

char *__wrap_seechanges_get_diff_path(char *path) {
    check_expected(path);

    return mock_type(char*);
}
