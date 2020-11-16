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

#include "../../config/global-config.h"
#include "../../analysisd/eventinfo.h"
#include "../../wazuh_db/wdb.h"
#include "../wrappers/wazuh/shared/rootcheck_op_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

#define TEST_AGENT_ID "005"
#define TEST_TIME     10005
#define TEST_LOG_STRING "Test log string File 'file_name'"

extern int DecodeRootcheck(Eventinfo *lf);
extern void w_free_event_info(Eventinfo *lf);
extern _Config Config;
/* setup / teardown */
int test_setup_global(void **state) {
    expect_string(__wrap__mdebug1, formatted_msg, "RootcheckInit completed.");
    Config.decoder_order_size = 32;
    RootcheckInit();
    return 0;
}

int test_setup(void **state) {
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
    Zero_Eventinfo(lf);
    os_strdup(TEST_AGENT_ID, lf->agent_id);
    os_strdup(TEST_LOG_STRING, lf->log);
    lf->time.tv_sec = (time_t) TEST_TIME;
    *state = lf;
    return 0;
}

int test_cleanup(void **state) {
    Eventinfo *lf = *state;
    os_free(lf->log);
    w_free_event_info(lf);
    return 0;
}

/* tests */

void test_rootcheck_db_failure(void **state) {
    Eventinfo *lf = *state;
    expect_string(__wrap_send_rootcheck_log, agent_id, TEST_AGENT_ID);
    expect_value(__wrap_send_rootcheck_log, date, TEST_TIME);
    expect_string(__wrap_send_rootcheck_log, log, TEST_LOG_STRING);
    will_return(__wrap_send_rootcheck_log, "ERROR String");
    will_return(__wrap_send_rootcheck_log, -2);

    expect_string(__wrap__merror, formatted_msg, "Rootcheck decoder unexpected result: 'ERROR String'");

    int ret = DecodeRootcheck(lf);
    assert_int_equal(ret, 0);
}

void test_rootcheck_success(void **state) {
    Eventinfo *lf = *state;
    expect_string(__wrap_send_rootcheck_log, agent_id, TEST_AGENT_ID);
    expect_value(__wrap_send_rootcheck_log, date, TEST_TIME);
    expect_string(__wrap_send_rootcheck_log, log, TEST_LOG_STRING);
    will_return(__wrap_send_rootcheck_log, "ok 2");
    will_return(__wrap_send_rootcheck_log, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Rootcheck decoder response: 'ok 2'");

    int ret = DecodeRootcheck(lf);
    assert_int_equal(ret, 1);
    assert_string_equal(lf->fields[RK_FILE].value, "file_name");
    assert_string_equal(lf->fields[RK_TITLE].value, TEST_LOG_STRING);
    assert_int_equal(lf->rootcheck_fts, FTS_DONE);
}


int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rootcheck_db_failure, test_setup, test_cleanup),
        cmocka_unit_test_setup_teardown(test_rootcheck_success, test_setup, test_cleanup),
    };
    return cmocka_run_group_tests(tests, test_setup_global, NULL);
}
