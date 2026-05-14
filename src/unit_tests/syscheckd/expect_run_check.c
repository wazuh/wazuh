/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "test_fim.h"

void expect_fim_send_msg(char mq, const char *location, const char *msg, int retval) {
    if (msg == NULL) {
        expect_any(__wrap_SendMSG, message);
    } else {
        expect_string(__wrap_SendMSG, message, msg);
    }
    expect_string(__wrap_SendMSG, locmsg, location);
    expect_value(__wrap_SendMSG, loc, mq);
    will_return(__wrap_SendMSG, retval);
}

void expect_send_syscheck_msg(const char *msg) {
    expect_any(__wrap__mdebug2, formatted_msg);

    expect_fim_send_msg(SYSCHECK_MQ, SYSCHECK, msg, 0);
}
