/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dirent_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"

int wrap_closedir(__attribute__((unused)) DIR *dirp) {
    if (test_mode) {
        check_expected(dirp);
        return mock_type(int);
    }
    return closedir(dirp);
}

DIR * wrap_opendir(const char *filename) {
    if(test_mode) {
        check_expected_ptr(filename);
        return mock_ptr_type(DIR*);
    } else {
        return opendir(filename);
    }
}

struct dirent * wrap_readdir(DIR *dirp) {
    if (test_mode) {
        return mock_type(struct dirent *);
    }
    return readdir(dirp);
}
