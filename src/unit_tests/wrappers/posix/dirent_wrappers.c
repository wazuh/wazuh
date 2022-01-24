/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "dirent_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


int __wrap_closedir(__attribute__((unused)) DIR *dirp) {
    return 1;
}

int __wrap_opendir() {
    return mock();
}

struct dirent * __wrap_readdir() {
    return mock_type(struct dirent *);
}
