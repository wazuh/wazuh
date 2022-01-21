/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "time_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

size_t __wrap_strftime(char * s, size_t max, __attribute__((unused)) const char * format,
                       __attribute__((unused)) const struct tm * tm) {
    strncpy(s, mock_type(char *), max);
    return mock();
}
