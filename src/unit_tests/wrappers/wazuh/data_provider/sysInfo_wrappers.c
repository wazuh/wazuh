/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "sysInfo_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_sysinfo_hardware(cJSON ** js_result) {
    *js_result = mock_ptr_type(cJSON *);
    int ret = mock_type(int);
    return ret;
}

int __wrap_sysinfo_packages(cJSON ** js_result) {

    *js_result = mock_ptr_type(cJSON *);
    return mock_type(int);
}

int __wrap_sysinfo_os(cJSON ** js_result) {

    *js_result = mock_ptr_type(cJSON *);
    return mock_type(int);
}

int __wrap_sysinfo_processes(cJSON ** js_result) {

    *js_result = mock_ptr_type(cJSON *);
    return mock_type(int);
}

int __wrap_sysinfo_networks(cJSON ** js_result) {

    *js_result = mock_ptr_type(cJSON *);
    return mock_type(int);
}

int __wrap_sysinfo_ports(cJSON ** js_result) {

    *js_result = mock_ptr_type(cJSON *);
    return mock_type(int);
}

void __wrap_sysinfo_free_result( __attribute__((unused)) cJSON ** js_data) {

    js_data = mock_ptr_type(cJSON **);
}
