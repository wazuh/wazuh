/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "integrity_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

char * __wrap_dbsync_check_msg(const char * component, dbsync_msg msg, long id, const char * start, const char * top,
                                const char * tail, __attribute__((unused)) const char * checksum) {
    check_expected(component);
    check_expected(msg);
    check_expected(id);
    check_expected(start);
    check_expected(top);
    check_expected(tail);

    return mock_type(char*);
}

char * __wrap_dbsync_state_msg(const char * component, cJSON * data) {
    check_expected(component);
    check_expected_ptr(data);

    return mock_type(char*);
}

void expect_fim_send_sync_control_call(const char *component,
                                         dbsync_msg msg,
                                         int id,
                                         const char *start,
                                         const char *top,
                                         const char *tail,
                                         const char *checksum) {

    expect_string(__wrap_fim_send_sync_control, component, component);
    expect_value(__wrap_fim_send_sync_control, msg, msg);
    expect_value(__wrap_fim_send_sync_control, id, id);

    if (start == NULL) {
        expect_value(__wrap_fim_send_sync_control, start, 0);
    } else {
        expect_string(__wrap_fim_send_sync_control, start, start);
    }
    if (top == NULL) {
        expect_value(__wrap_fim_send_sync_control, top, 0);
    } else {
        expect_string(__wrap_fim_send_sync_control, top, top);
    }
    if (tail == NULL) {
        expect_value(__wrap_fim_send_sync_control, tail, 0);
    } else {
        expect_string(__wrap_fim_send_sync_control, tail, tail);
    }

    if (checksum == NULL) {
        expect_value(__wrap_fim_send_sync_control, checksum, checksum);
    } else {
        expect_string(__wrap_fim_send_sync_control, checksum, checksum);
    }
}
