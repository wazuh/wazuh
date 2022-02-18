/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sym_load_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include "../../common.h"

void* __wrap_so_get_module_handle_on_path(const char *path, const char *so) {
    if (test_mode) {
        check_expected(path);
        check_expected(so);
        void *ret = mock_type(void*);

        return ret;

    }
    return so_get_module_handle_on_path(path, so);
}

void* __wrap_so_get_module_handle(const char *so) {
    if (test_mode) {
        check_expected(so);
        void *ret = mock_type(void*);

        return ret;

    }
    return so_get_module_handle(so);
}

void* __wrap_so_get_function_sym(void *handle, const char *function_name) {
    if (test_mode) {
        check_expected(handle);
        check_expected(function_name);
        void *ret = mock_type(void*);

        return ret;

    }
    return so_get_function_sym(handle, function_name);
}

int __wrap_so_free_library(void *handle) {
    if (test_mode) {
        check_expected(handle);
        return mock();
    }
    return so_free_library(handle);
}
