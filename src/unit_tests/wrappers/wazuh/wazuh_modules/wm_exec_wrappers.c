/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "headers/shared.h"
#include "wm_exec_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path) {
    check_expected(command);
    check_expected(secs);
    check_expected(add_path);

    if (output) {
        char *out = mock_type(char *);
        if (out) {
            os_strdup(out, *output);
        }
    }

    *exitcode = mock_type(int);

    return mock();
}
