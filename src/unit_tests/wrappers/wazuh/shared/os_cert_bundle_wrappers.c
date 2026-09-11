/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>

#include "os_cert_bundle_wrappers.h"

const char* __wrap_os_find_ca_bundle(const char* const* candidates) {
    check_expected_ptr(candidates);
    return mock_type(const char*);
}

void expect_os_find_ca_bundle(const char *path) {
    expect_any(__wrap_os_find_ca_bundle, candidates);
    will_return(__wrap_os_find_ca_bundle, path);
}
