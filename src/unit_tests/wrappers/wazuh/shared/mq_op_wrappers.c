/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "mq_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

int __wrap_SendMSG(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc) {
    check_expected(message);
    check_expected(locmsg);
    check_expected(loc);
    return mock();
}

int __wrap_StartMQ(const char *path, short int type,__attribute__((unused)) short int n_attempts) {
    check_expected(path);
    check_expected(type);
    return mock();
}

void expect_StartMQ_call(const char *qpath, int type, int ret) {
    expect_string(__wrap_StartMQ, path, qpath);
    expect_value(__wrap_StartMQ, type, type);
    will_return(__wrap_StartMQ, ret);
}

void expect_SendMSG_call(const char *message, const char *locmsg, char loc, int ret) {
    expect_string(__wrap_SendMSG, message, message);
    expect_string(__wrap_SendMSG, locmsg, locmsg);
    expect_value(__wrap_SendMSG, loc, loc);
    will_return(__wrap_SendMSG, ret);
}
