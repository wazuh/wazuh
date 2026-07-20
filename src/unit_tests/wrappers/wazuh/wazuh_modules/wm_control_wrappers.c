/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "wm_control_wrappers.h"

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

size_t __wrap_wm_control_execute_action(const char *action, const char *service, char **output) {
    check_expected(action);
    check_expected(service);
    *output = mock_type(char *);
    return strlen(*output);
}

bool __wrap_wm_control_check_systemd(void) {
    return mock_type(bool);
}

pid_t __wrap_fork(void) {
    return mock_type(pid_t);
}
