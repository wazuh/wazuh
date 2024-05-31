/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dlfcn_wrappers.h"

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>


extern int test_mode;

extern void * __real_dlsym(void * handle, const char * symbol);
void * __wrap_dlsym(void * handle, const char * symbol) {
    if (test_mode) {
        check_expected_ptr(handle);
        check_expected_ptr(symbol);
        return mock_ptr_type(void *);
    } else {
        return __real_dlsym(handle, symbol);
    }
}

// Mock dlerror function
extern char * __real_dlerror(void);
char * __wrap_dlerror(void) {
    if (test_mode) {
        return mock_ptr_type(char *);
    } else {
        return __real_dlerror();
    }
}

// Mock dlopen function
extern void * __real_dlopen(const char * filename, int flags);
void * __wrap_dlopen(const char * filename, int flags) {
    if (test_mode) {
        check_expected_ptr(filename);
        check_expected(flags);
        return mock_ptr_type(void *);
    } else {
        return __real_dlopen(filename, flags);
    }
}

// Mock dlclose function
extern int __real_dlclose(void * handle);
int __wrap_dlclose(void * handle) {
    if (test_mode) {
        check_expected_ptr(handle);
        return mock();
    } else {
        return __real_dlclose(handle);
    }
}
