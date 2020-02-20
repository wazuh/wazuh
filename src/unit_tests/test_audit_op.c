/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
#include <stdio.h>
#include <stdlib.h>

#include "../headers/audit_op.h"
#include "../headers/defs.h"

int audit_get_rule_list(int fd);

/* redefinitons/wrapping */

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_audit_send(int fd, int type, const void *data, unsigned int size) {
    check_expected(fd);
    check_expected(type);

    return mock();
}

/* setups/teardowns */


/* tests */

static void test_audit_get_rule_list(void **state) {
    (void) state;

    expect_value(__wrap_audit_send, fd, 0);
    expect_value(__wrap_audit_send, type, 1013);
    will_return(__wrap_audit_send, -1);

    expect_string(__wrap__merror, formatted_msg, "Error sending rule list data request (Operation not permitted)");

    audit_get_rule_list(0);
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_audit_get_rule_list),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
