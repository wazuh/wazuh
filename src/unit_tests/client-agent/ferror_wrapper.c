/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>

#include "../wrappers/common.h"
#include "ferror_wrapper.h"

/* Kept out of stdio_wrappers.c on purpose: that file is linked into virtually every unit
 * test binary via libwazuh_test.a, and only test_https_client_bridge needs ferror()
 * mocked. Compiled and -Wl,--wrap,ferror'd only for that target (see its CMakeLists.txt),
 * so __real_ferror only needs to resolve there and can stay a plain (non-weak) extern. */
extern int __real_ferror(FILE *_File);

int __wrap_ferror(FILE *_File) {
    if (test_mode) {
        check_expected(_File);
        return mock();
    } else {
        return __real_ferror(_File);
    }
}

void expect_ferror(FILE *_File, int ret) {
    expect_value(__wrap_ferror, _File, _File);
    will_return(__wrap_ferror, ret);
}
