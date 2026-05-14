/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "string_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


char *__wrap_strerror(__attribute__((unused)) int __errnum) {
    return mock_type(char*);
}

size_t __wrap_strlen(const char *s) {
    check_expected(s);
    return mock();
}
