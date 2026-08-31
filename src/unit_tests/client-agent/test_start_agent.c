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
#include "../wrappers/wazuh/shared/log_rotate_wrappers.h"

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
static agent_metadata_t last_published;

int __wrap_metadata_provider_update(const agent_metadata_t *metadata) {
    check_expected(metadata);

    if (metadata != NULL) {
        last_published = *metadata;
    }

    return (int)mock();
}

/* metadata_provider_get() is scripted through an array rather than cmocka's mock queue because
 * w_agentd_populate_metadata() retries the read: how many times it is called is part of what
 * these cases assert, and an unscripted default of -1 keeps the cases that do not care about the
 * carry-over from having to enumerate every attempt. Wrapped rather than left to the real
 * provider because that one reads a file at a path relative to the working directory, which
 * other test binaries in this tree also write. */
#define METADATA_GET_SCRIPT_MAX 8

static int metadata_get_script[METADATA_GET_SCRIPT_MAX];
static uint64_t metadata_get_offsets[METADATA_GET_SCRIPT_MAX];
static int metadata_get_script_len;
static int metadata_get_calls;

static void script_metadata_get(int result, uint64_t vd_feed_offset) {
    assert_true(metadata_get_script_len < METADATA_GET_SCRIPT_MAX);
    metadata_get_script[metadata_get_script_len] = result;
    metadata_get_offsets[metadata_get_script_len] = vd_feed_offset;
    metadata_get_script_len++;
}

int __wrap_metadata_provider_get(agent_metadata_t *out_metadata) {
    const int attempt = metadata_get_calls++;

    if (attempt >= metadata_get_script_len) {
        return -1;
    }

    if (metadata_get_script[attempt] == 0 && out_metadata != NULL) {
        out_metadata->vd_feed_offset = metadata_get_offsets[attempt];
    }

    return metadata_get_script[attempt];
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

    memset(&last_published, 0, sizeof(last_published));
    metadata_get_script_len = 0;
    metadata_get_calls = 0;

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
    expect_string(__wrap__mdebug1, formatted_msg, "No published agent metadata to carry the VD feed offset from.");
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
    expect_string(__wrap__mdebug1, formatted_msg, "No published agent metadata to carry the VD feed offset from.");
    expect_any(__wrap_metadata_provider_update, metadata);
    will_return(__wrap_metadata_provider_update, -1);
    expect_string(__wrap__mdebug1, formatted_msg, "Failed to populate early metadata");

    w_agentd_populate_metadata();
}

/* #38601: the VD feed offset is agent-info's field, and metadata_provider_get() reports a reader
 * that hit agent-info mid-write the same way it reports a record that does not exist yet. Losing
 * the offset publishes a zero, which aborts every VD synchronization with NO_VD_OFFSET_ERROR and
 * takes the identity resync down with it, so a busy read is retried instead of believed. */
static void test_populate_metadata_carries_offset_after_a_busy_read(void **state) {
    (void)state;

    script_metadata_get(-1, 0);      /* agent-info holds `updating` */
    script_metadata_get(-1, 0);      /* still */
    script_metadata_get(0, 4242);    /* cleared, and this is the offset it published */

#ifdef TEST_WINAGENT
    will_return(__wrap_get_win_version, NULL);
#else
    will_return(__wrap_get_unix_version, NULL);
#endif
    expect_any(__wrap_metadata_provider_update, metadata);
    will_return(__wrap_metadata_provider_update, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Early metadata populated into shared memory");

    w_agentd_populate_metadata();

    assert_int_equal(metadata_get_calls, 3);
    assert_int_equal(last_published.vd_feed_offset, 4242);
}

/* The first read already succeeds: no retry, no debug line about a missing record. */
static void test_populate_metadata_carries_offset_on_first_read(void **state) {
    (void)state;

    script_metadata_get(0, 99);

#ifdef TEST_WINAGENT
    will_return(__wrap_get_win_version, NULL);
#else
    will_return(__wrap_get_unix_version, NULL);
#endif
    expect_any(__wrap_metadata_provider_update, metadata);
    will_return(__wrap_metadata_provider_update, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Early metadata populated into shared memory");

    w_agentd_populate_metadata();

    assert_int_equal(metadata_get_calls, 1);
    assert_int_equal(last_published.vd_feed_offset, 99);
}

/* Every attempt fails -- first boot, or a window that never cleared. The publication still has
 * to happen, so the offset is zero, but it is reported rather than silent. */
static void test_populate_metadata_reports_an_unreadable_record(void **state) {
    (void)state;

#ifdef TEST_WINAGENT
    will_return(__wrap_get_win_version, NULL);
#else
    will_return(__wrap_get_unix_version, NULL);
#endif
    expect_string(__wrap__mdebug1, formatted_msg, "No published agent metadata to carry the VD feed offset from.");
    expect_any(__wrap_metadata_provider_update, metadata);
    will_return(__wrap_metadata_provider_update, 0);
    expect_string(__wrap__mdebug1, formatted_msg, "Early metadata populated into shared memory");

    w_agentd_populate_metadata();

    assert_int_equal(metadata_get_calls, 3);
    assert_int_equal(last_published.vd_feed_offset, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_start_agent_not_startup_is_a_noop, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_send_msg_on_startup_goes_to_https, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_populate_metadata_publishes_identity, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_populate_metadata_update_failure, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_populate_metadata_carries_offset_after_a_busy_read, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_populate_metadata_carries_offset_on_first_read, setup_test, teardown_test),
        cmocka_unit_test_setup_teardown(test_populate_metadata_reports_an_unreadable_record, setup_test, teardown_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
