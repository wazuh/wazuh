/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "run_check_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_fim_send_scan_info(__attribute__ ((__unused__)) fim_scan_event event) {
    return;
}

void __wrap_fim_send_sync_msg(const char * msg) {
    check_expected(msg);
}

int __wrap_send_log_msg(const char * msg) {
    check_expected(msg);
    return mock();
}

void __wrap_send_syscheck_msg(__attribute__((unused)) char *msg) {
    return;
}
