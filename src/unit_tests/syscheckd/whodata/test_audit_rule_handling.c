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
#include "syscheckd/whodata/syscheck_audit.h"


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

extern OSList *whodata_directories;
extern pthread_mutex_t rules_mutex;

extern int audit_rule_manipulation;

/* setup/teardown */
static int setup_group(void **state) {
    expect_any_always(__wrap__mdebug1, formatted_msg);

#ifndef TEST_SERVER
    will_return_always(__wrap_getDefine_Int, 0);
#endif

    Read_Syscheck_Config("../test_syscheck2.conf");
    fim_audit_rules_init();

    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    return 0;
}

static int setup_max_entries(void **state) {
    syscheck.max_audit_entries = 10;
    return 0;
}

static int teardown_max_entries(void **state) {
    syscheck.max_audit_entries = 0;
    return 0;
}

void test_rules_initial_load_new_rules(void **state) {
    int total_dirs;
    int total_rules;
    int i;

    will_return(__wrap_audit_open, 1);
    will_return(__wrap_audit_get_rule_list, 1);

    expect_function_call(__wrap_pthread_mutex_lock);
    for (total_dirs = 0; syscheck.dir[total_dirs]; total_dirs++) {
        if ((syscheck.opts[total_dirs] & WHODATA_ACTIVE) == 0) {
            continue;
        }
        will_return(__wrap_search_audit_rule, 0);
        will_return(__wrap_audit_add_rule, 1);
    }
    // Inside fim_get_real_path
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    // Inside _add_whodata_directory
    expect_function_call(__wrap_pthread_mutex_lock);
    expect_function_call(__wrap_pthread_mutex_unlock);

    char buffers [total_dirs][OS_SIZE_1024];
    for (i = total_dirs; i >= 0; i--) {
        if ((syscheck.opts[i] & WHODATA_ACTIVE) == 0) {
            continue;
        }
        snprintf (buffers[i], OS_SIZE_1024, FIM_AUDIT_NEWRULE, syscheck.dir[i]);
        expect_string(__wrap__mdebug1, formatted_msg, buffers[i]);
    }

    expect_function_call(__wrap_pthread_mutex_unlock);

    total_rules = fim_rules_initial_load();

}
int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rules_initial_load_new_rules, setup_max_entries, teardown_max_entries),
        };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
