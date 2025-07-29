/* Copyright (C) 2015, Wazuh Inc.
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
#include <cJSON.h>

int __wrap_send_log_msg(const char * msg) {
    check_expected(msg);
    return mock();
}

void __wrap_send_syscheck_msg(__attribute__((unused)) char *msg) {
    function_called();
    return;
}

void __wrap_persist_syscheck_msg(__attribute__((unused)) char *msg) {
    function_called();
    return;
}

void __wrap_fim_sync_check_eps() {
    function_called();
}

// Send a state synchronization message
void __wrap_fim_send_sync_state(const char* location, const char* msg) {
    check_expected(location);
    check_expected(msg);
}

void expect_fim_send_sync_state_call(const char* location, const char* msg) {
    expect_value(__wrap_fim_send_sync_state, location, location);
    expect_value(__wrap_fim_send_sync_state, msg, msg);
}
