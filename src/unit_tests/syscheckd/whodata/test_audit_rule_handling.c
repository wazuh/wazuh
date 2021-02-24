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

#include "../../wrappers/common.h"
#include "syscheckd/syscheck.h"

#include "wrappers/externals/audit/libaudit_wrappers.h"
#include "wrappers/externals/procpc/readproc_wrappers.h"
#include "wrappers/libc/stdio_wrappers.h"
#include "wrappers/libc/stdlib_wrappers.h"
#include "wrappers/posix/unistd_wrappers.h"
#include "wrappers/wazuh/shared/audit_op_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"
#include "wrappers/wazuh/shared/file_op_wrappers.h"
#include "wrappers/wazuh/syscheckd/audit_parse_wrappers.h"


#define PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)

/* setup/teardown */
static int setup_group(void **state) {
    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifndef TEST_SERVER
    will_return_always(__wrap_getDefine_Int, 0);
#endif

    Read_Syscheck_Config("../test_syscheck2.conf");

    syscheck.database_store = 0; // disk
    w_mutex_init(&syscheck.fim_entry_mutex, NULL);
    test_mode = 1;

#ifdef TEST_WINAGENT
    time_mock_value = 192837465;
#endif
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    return 0;
}

void test_rules_initial_load_new_rules(void **state) {
    int i;
    int total_rules;
    will_return(__wrap_audit_open, 1);
    will_return(__wrap_audit_get_rule_list, 1);

    expect_function_call(__wrap_pthread_mutex_lock);
    for (i = 0; syscheck.dir[i]; i++) {
        if (syscheck.opts[i] & WHODATA_ACTIVE) {
            continue;
        }

        will_return(__wrap_search_audit_rule, 0);
        will_return(__wrap_audit_add_rule, 1);
    }
    // Inside fim_get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    expect_function_call(__wrap_pthread_mutex_unlock);

    total_rules = fim_rules_initial_load();

}
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_rules_initial_load_new_rules),
        };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
