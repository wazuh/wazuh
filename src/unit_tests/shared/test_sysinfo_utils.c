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

#include "../../data_provider/include/sysInfo.h"
#include "../../headers/shared.h"
#include "../../headers/sysinfo_utils.h"
#include "../wrappers/common.h"

cJSON * w_sysinfo_get_processes(w_sysinfo_helpers_t * sysinfo);
cJSON * w_get_os(w_sysinfo_helpers_t * sysinfo);
bool w_sysinfo_init(w_sysinfo_helpers_t * sysinfo);
bool w_sysinfo_deinit(w_sysinfo_helpers_t * sysinfo);
pid_t * w_get_process_childs(w_sysinfo_helpers_t * sysinfo, pid_t parent_pid, unsigned int max_count);
char * w_get_os_codename(w_sysinfo_helpers_t * sysinfo);

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

/* w_sysinfo_get_processes */

void test_w_sysinfo_get_processes_sysinfo_NULL(void ** state) {

    w_sysinfo_helpers_t * sysinfo = NULL;

    cJSON * ret = w_sysinfo_get_processes(sysinfo);

    assert_null(ret);
}

void test_w_sysinfo_get_processes_processes_NULL(void ** state) {

    w_sysinfo_helpers_t * sysinfo = NULL;

    os_calloc(1, sizeof(w_sysinfo_helpers_t), sysinfo);
    sysinfo->processes = NULL;

    cJSON * ret = w_sysinfo_get_processes(sysinfo);

    assert_null(ret);

    os_free(sysinfo->processes);
    os_free(sysinfo);
}

int main(void) {

    const struct CMUnitTest tests[] = {
        // Test w_sysinfo_get_processes
        cmocka_unit_test(test_w_sysinfo_get_processes_sysinfo_NULL),
        cmocka_unit_test(test_w_sysinfo_get_processes_processes_NULL),

    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
