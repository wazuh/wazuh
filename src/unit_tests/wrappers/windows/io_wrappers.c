/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "io_wrappers.h"

char * wrap_mktemp_s(__attribute__((unused)) const char *path, __attribute__((unused)) ssize_t length) {
    return mock_type(char*);
}
