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
#include <stdio.h>
#include <stdlib.h>

#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"

#include "../analysisd/eventinfo.h"
#include "../headers/defs.h"

void DispatchUpgradeModule(Eventinfo * lf);

/* setup/teardown */

static int setup_upgrade_event(void **state) {
    Eventinfo *lf;

    os_calloc(1, sizeof(Eventinfo), lf);
    os_calloc(OS_SIZE_16, sizeof(char), lf->agent_id);
    snprintf(lf->agent_id, OS_SIZE_16, "001");

    *state = lf;

    return 0;
}

static int teardown_upgrade_event(void **state) {
    Eventinfo *lf = *state;

    os_free(lf->agent_id);
    os_free(lf->log);
    os_free(lf);

    return 0;
}

/* tests */

static void test_DispatchUpgradeModule_blocks_upgrade_custom_from_agent(void **state) {
    Eventinfo *lf = *state;

    os_strdup(
        "{\"command\":\"upgrade_custom\",\"parameters\":{\"file_path\":\"/etc/shadow\",\"installer\":\"upgrade.sh\"}}",
        lf->log);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Agent '001' is not allowed to request the upgrade command received on the agent channel");

    DispatchUpgradeModule(lf);
}

static void test_DispatchUpgradeModule_blocks_upgrade_from_agent(void **state) {
    Eventinfo *lf = *state;

    os_strdup(
        "{\"command\":\"upgrade\",\"parameters\":{\"wpk_repository\":\"http://x/\",\"wpk_file\":\"a.wpk\",\"wpk_sha1\":\"abc\"}}",
        lf->log);

    expect_string(__wrap__mdebug1, formatted_msg,
                  "Agent '001' is not allowed to request the upgrade command received on the agent channel");

    DispatchUpgradeModule(lf);
}

static void test_DispatchUpgradeModule_allows_status_update(void **state) {
    Eventinfo *lf = *state;

    os_strdup("{\"command\":\"upgrade_update_status\",\"parameters\":{\"status\":\"Done\"}}", lf->log);

    expect_string(__wrap_OS_ConnectUnixDomain, path, WM_UPGRADE_SOCK);
    expect_value(__wrap_OS_ConnectUnixDomain, type, SOCK_STREAM);
    expect_value(__wrap_OS_ConnectUnixDomain, max_msg_size, OS_MAXSTR);
    will_return(__wrap_OS_ConnectUnixDomain, 44);

    expect_value(__wrap_OS_SendSecureTCP, sock, 44);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    DispatchUpgradeModule(lf);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_DispatchUpgradeModule_blocks_upgrade_custom_from_agent,
                                         setup_upgrade_event, teardown_upgrade_event),
        cmocka_unit_test_setup_teardown(test_DispatchUpgradeModule_blocks_upgrade_from_agent,
                                         setup_upgrade_event, teardown_upgrade_event),
        cmocka_unit_test_setup_teardown(test_DispatchUpgradeModule_allows_status_update,
                                         setup_upgrade_event, teardown_upgrade_event),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
