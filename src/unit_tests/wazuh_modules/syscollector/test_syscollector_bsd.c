/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Test corresponding to the syscollector capacities
 * for BSD and MAC
 * */


#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <time.h>
#include <sys/proc_info.h>

#include "shared.h"
#include "headers/defs.h"
#include "../../wrappers/common.h"
#include "../../wrappers/macos/libc/stdio_wrappers.h"
#include "../../../wazuh_modules/syscollector/syscollector.h"
#include "../../wazuh_modules/wmodules.h"

int extern test_mode;

char *get_port_state();

static int setup_wrappers(void **state) {
    test_mode = 1;
    return 0;
}

static int teardown_wrappers(void **state) {
    test_mode = 0;
    return 0;
}

void test_get_port_state() {
    expect_string(wrap_snprintf, s, "close");
    will_return(wrap_snprintf, 5);
    char * ret = get_port_state(TSI_S_CLOSED);
    assert_string_equal(ret, "close");
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_port_state, setup_wrappers, teardown_wrappers)
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}