/* Copyright (C) 2015-2020, Wazuh Inc.
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

void expect_dbsync_check_msg_call(const char *component,
                                         dbsync_msg msg,
                                         int id,
                                         const char *start,
                                         const char *top,
                                         const char *tail,
                                         char *ret) {

    expect_string(__wrap_dbsync_check_msg, component, component);
    expect_value(__wrap_dbsync_check_msg, msg, msg);
    expect_value(__wrap_dbsync_check_msg, id, id);

    if (start == NULL) {
        expect_value(__wrap_dbsync_check_msg, start, 0);
    } else {
        expect_string(__wrap_dbsync_check_msg, start, start);

    }
    if (top == NULL) {
        expect_value(__wrap_dbsync_check_msg, top, 0);
    } else {
        expect_string(__wrap_dbsync_check_msg, top, top);
    }
    if (tail == NULL) {
        expect_value(__wrap_dbsync_check_msg, tail, 0);
    } else {
        expect_string(__wrap_dbsync_check_msg, tail, tail);
    }
    will_return(__wrap_dbsync_check_msg, ret);
}
