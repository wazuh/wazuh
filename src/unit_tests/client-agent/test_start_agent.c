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
#include <string.h>

#include "../wrappers/common.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/validate_op_wrappers.h"
#include "../wrappers/wazuh/monitord/monitord_wrappers.h"

#ifdef TEST_WINAGENT
#include "../wrappers/wazuh/shared/randombytes_wrappers.h"
#endif

#include "agentd.h"
#include "module_limits.h"
#include "metadata_provider.h"
#include "version_op.h"

/* What is left of start_agent.c after the TCP path was retired (#38030): the
 * metadata publication and the agent-start event, now over /stateless. */

extern void send_msg_on_startup(void);

/* Wrappers for w_agentd_populate_metadata dependencies */
int __wrap_metadata_provider_update(const agent_metadata_t *metadata) {
    check_expected(metadata);
    return (int)mock();
}

os_info *__wrap_get_unix_version(void) {
    return (os_info *)mock_ptr_type(os_info *);
}

os_info *__wrap_get_win_version(void) {
    return (os_info *)mock_ptr_type(os_info *);
}

void __wrap_free_osinfo(os_info *osinfo) {
    return;
}

int __wrap_w_https_client_submit_event(const char *frame, size_t length) {
    check_expected(frame);
    check_expected(length);
    return (int)mock();
}

/* setup/teardown */
static int setup_test(void **state) {
    agt = (agent *)calloc(1, sizeof(agent));
    agt->server = NULL;
    agt->rip_id = 0;
    agt->execdq = 0;
    agt->profile = NULL;
    agt->flags.auto_restart = 1;

    /* No keystore: only the metadata's id/name copy reads it, guarded on
     * keys.keysize. */
    memset(&keys, 0, sizeof(keys));

    agent_cluster_name[0] = '\0';
    agent_agent_groups[0] = '\0';

    return 0;
}

static int teardown_test(void **state) {
    os_free(agt);
    return 0;
}

/* start_agent */

/* A non-startup call has nothing left to do: no connection to re-establish. */
static void test_start_agent_not_startup_is_a_noop(void **state) {
    (void)state;

    start_agent(0);
}

/* send_msg_on_startup: same event, submitted to the HTTPS accumulator. */
static void test_send_msg_on_startup_goes_to_https(void **state) {
    (void)state;

    expect_any(__wrap_w_https_client_submit_event, frame);
    expect_any(__wrap_w_https_client_submit_event, length);
    will_return(__wrap_w_https_client_submit_event, 0);

    send_msg_on_startup();
}

/* w_agentd_populate_metadata: publishes the local data plus the cluster/groups
 * the bridge writes from the manager's Startup response. */
static void test_populate_metadata_publishes_identity(void **state) {
    (void)state;

    snprintf(agent_cluster_name, sizeof(agent_cluster_name), "%s", "wazuh-cluster");
    snprintf(agent_agent_groups, sizeof(agent_agent_groups), "%s", "default,linux");

#ifdef TEST_WINAGENT
    will_return(__wrap_get_win_version, NULL);
#else
    will_return(__wrap_get_unix_version, NULL);
#endif
    expect_any(__wrap_metadata_provider_update, metadata);
    will_return(__wrap_metadata_provider_update, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Early metadata populated into shared memory");

    w_agentd_populate_metadata();
}

/* A failed publication is reported and swallowed: it must not abort the start. */
static void test_populate_metadata_update_failure(void **state) {
    (void)state;

#ifdef TEST_WINAGENT
    will_return(__wrap_get_win_version, NULL);
#else
    will_return(__wrap_get_unix_version, NULL);
#endif
    expect_any(__wrap_metadata_provider_update, metadata);
    will_return(__wrap_metadata_provider_update, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Failed to populate early metadata");

    w_agentd_populate_metadata();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_start_agent_not_startup_is_a_noop, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_send_msg_on_startup_goes_to_https, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_populate_metadata_publishes_identity, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_populate_metadata_update_failure, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
