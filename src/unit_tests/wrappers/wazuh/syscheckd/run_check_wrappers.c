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
void __wrap_fim_send_scan_info(__attribute__ ((__unused__)) fim_scan_event event) {
    return;
}

int __wrap_send_log_msg(const char * msg) {
    check_expected(msg);
    return mock();
}

void __wrap_send_syscheck_msg(__attribute__((unused)) char *msg) {
    return;
}

void __wrap_fim_sync_check_eps() {
    function_called();
}

// Send a state synchronization message
void __wrap_fim_send_sync_state(const char *location, cJSON * msg) {
    check_expected(location);
    check_expected(msg);

    cJSON_Delete(msg);
}

// Send a data synchronization control message
void __wrap_fim_send_sync_control(const char *component,
                                  dbsync_msg msg,
                                  long id,
                                  const char *start,
                                  const char *top,
                                  const char *tail,
                                  const char *checksum) {
    check_expected(component);
    check_expected(msg);
    check_expected(id);
    check_expected(start);
    check_expected(top);
    check_expected(tail);
    check_expected(checksum);
}

void expect_fim_send_sync_state_call(const char *location, cJSON *msg) {
    expect_value(__wrap_fim_send_sync_state, location, location);
    expect_value(__wrap_fim_send_sync_state, msg, msg);
}
