/*
 * Copyright (C) 2025, Wazuh Inc.  *
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

#include "../../../syscheckd/include/syscheck.h"
#include "../../../syscheckd/src/ebpf/include/ebpf_whodata.h"
#include "wrappers/linux/ebpf_wrappers.h"
#include "wrappers/wazuh/shared/debug_op_wrappers.h"

/* setup/teardown */
static int setup_group(void **state) {
    (void) state;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    (void) state;
    memset(&syscheck, 0, sizeof(syscheck_config));
    Free_Syscheck(&syscheck);
    test_mode = 0;
    return 0;
}


static int setup_syscheck_dir_links(void **state) {

    directory_t *directory0 = fim_create_directory("/test0", WHODATA_ACTIVE, NULL, 512,
                                                NULL, -1, 0);
    directory_t *directory1 = fim_create_directory("/test1", WHODATA_ACTIVE, NULL, 512,
                                                NULL, -1, 0);

    syscheck.whodata_provider = EBPF_PROVIDER;
    syscheck.directories = OSList_Create();
    if (syscheck.directories == NULL) {
        return (1);
    }

    OSList_InsertData(syscheck.directories, NULL, directory0);
    OSList_InsertData(syscheck.directories, NULL, directory1);

    return 0;
}

static int teardown_syscheck_dir_links(void **state) {
    OSListNode *node_it;

    if (syscheck.directories) {
        OSList_foreach(node_it, syscheck.directories) {
            free_directory(node_it->data);
            node_it->data = NULL;
        }
        OSList_Destroy(syscheck.directories);
        syscheck.directories = NULL;
    }

    return 0;
}

static int teardown_rules_to_realtime(void **state) {
    free(syscheck.realtime);
    syscheck.realtime = NULL;
    teardown_syscheck_dir_links(state);
    return 0;
}

void test_check_ebpf_availability_true(void **state) {

    expect_string(__wrap__minfo, formatted_msg, FIM_EBPF_INIT);
    expect_string(__wrap__mwarn, formatted_msg, FIM_ERROR_EBPF_HEALTHCHECK);

    will_return(__wrap_ebpf_whodata_healthcheck, 1);


    check_ebpf_availability();

    // Verify that EBPF_PROVIDER was disable
    if (syscheck.whodata_provider == EBPF_PROVIDER){
        fail();
    }

    // Check that they have been switched to AUDIT_PROVIDER.
    if (syscheck.whodata_provider != AUDIT_PROVIDER){
        fail();
    }

}

void test_check_ebpf_availability_false(void **state) {

    expect_string(__wrap__minfo, formatted_msg, FIM_EBPF_INIT);
    will_return(__wrap_ebpf_whodata_healthcheck, 0);

    check_ebpf_availability();

    // Verify EBPF_PROVIDER
    if (syscheck.whodata_provider != EBPF_PROVIDER){
        fail();
    }

    // Check that they have not been switched to AUDIT_PROVIDER.
    if (syscheck.whodata_provider == AUDIT_PROVIDER){
        fail();
    }
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_check_ebpf_availability_true, setup_syscheck_dir_links, teardown_rules_to_realtime),
        cmocka_unit_test_setup_teardown(test_check_ebpf_availability_false, setup_syscheck_dir_links, teardown_rules_to_realtime),
        };

    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
