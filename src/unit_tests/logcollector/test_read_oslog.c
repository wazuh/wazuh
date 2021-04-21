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
#include "../wrappers/linux/socket_wrappers.h"

bool oslog_ctxt_restore(char * buffer, w_oslog_ctxt_t * ctxt);
void oslog_ctxt_backup(char * buffer, w_oslog_ctxt_t * ctxt);
void oslog_ctxt_clean(w_oslog_ctxt_t * ctxt);
bool oslog_ctxt_is_expired(time_t timeout, w_oslog_ctxt_t * ctxt);
char * oslog_get_lastline(char * str);

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

/* oslog_ctxt_restore */

void test_oslog_ctxt_restore_false(void ** state) {

    w_oslog_ctxt_t ctxt;
    ctxt.buffer[0] = '\0';

    char * buffer = NULL;

    bool ret = oslog_ctxt_restore(buffer, &ctxt);
    assert_false(ret);

}

void test_oslog_ctxt_restore_true(void ** state) {

    w_oslog_ctxt_t ctxt;
    strncpy(ctxt.buffer,"test",OS_MAXSTR);

    char buffer[OS_MAXSTR + 1];
    buffer[OS_MAXSTR] = '\0';

    bool ret = oslog_ctxt_restore(buffer, &ctxt);
    assert_true(ret);

}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Test w_logcollector_validate_oslog_stream_predicate
        cmocka_unit_test(test_oslog_ctxt_restore_false),
        cmocka_unit_test(test_oslog_ctxt_restore_true),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
