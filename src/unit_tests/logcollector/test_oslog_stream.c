/*
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include <time.h>

#include "../../logcollector/logcollector.h"
#include "../../headers/shared.h"
#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

bool w_logcollector_validate_oslog_stream_predicate(char * predicate);
char ** w_create_oslog_stream_array(char * predicate, char * level, int type);
wfd_t * w_logcollector_exec_oslog_stream(char ** oslog_array, u_int32_t flags);
void w_logcollector_create_oslog_env(logreader * current);

/* setup/teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

/* wraps */


/* tests */

/* w_logcollector_validate_oslog_stream_predicate */
void test_w_logcollector_validate_oslog_stream_predicate_empty(void ** state) {
    char predicate[] = "";

    bool ret = w_logcollector_validate_oslog_stream_predicate(predicate);
    assert_false(ret);
}

void test_w_logcollector_validate_oslog_stream_predicate_existing(void ** state) {
    char predicate[] = "test";

    bool ret = w_logcollector_validate_oslog_stream_predicate(predicate);
    assert_true(ret);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_logcollector_validate_oslog_stream_predicate
        cmocka_unit_test(test_w_logcollector_validate_oslog_stream_predicate_empty),
        cmocka_unit_test(test_w_logcollector_validate_oslog_stream_predicate_existing),    
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
