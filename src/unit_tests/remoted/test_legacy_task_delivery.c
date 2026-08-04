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
#include <string.h>

#include "remoted.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/wazuhdb_queries_op_wrappers.h"
#include "../wrappers/wazuh/remoted/agent_metadata_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

/* Prototypes of the STATIC (test-exported under WAZUH_UNIT_TESTING) functions under test,
 * declared here rather than in a header -- same convention test_remcom.c already uses. */
bool legacy_task_agent_is_pre_v5(const char *agent_id, char **out_version);
bool legacy_task_deliver_remote_upgrade(const char *agent_id, const cJSON *payload_obj);
void legacy_upgrade_poll_cycle(void);

/* req_send_and_wait() is exercised entirely through this local mock -- it is the one function
 * this module uses to reach an agent, so every push-step assertion goes through it. */
int __wrap_req_send_and_wait(const char *agent_id, const char *payload, size_t length, char **response, int timeout_sec) {
    check_expected(agent_id);
    check_expected(payload);
    (void) length;
    (void) timeout_sec;

    const char *mocked_response = mock_ptr_type(const char *);
    *response = mocked_response ? strdup(mocked_response) : NULL;

    return mock_type(int);
}

/* Trivial no-op mocks for the keystore rwlock -- legacy_upgrade_poll_cycle() only needs the
 * (single-threaded, unlocked in tests) keys array contents, same pattern test_secure.c uses. */
void __wrap_key_lock_read(void) { }
void __wrap_key_unlock(void) { }

static int test_setup(void **state) {
    (void) state;
    test_mode = 1;
    return 0;
}

static int test_teardown(void **state) {
    (void) state;
    test_mode = 0;
    keys.keyentries = NULL;
    keys.keysize = 0;
    return 0;
}

/* Always mocked as a cache miss: the shared wrapper can't inject metadata content, so version
 * scenarios below go through the wazuh-db fallback instead -- the path after resolution is
 * identical either way. */
static void expect_cache_miss(const char *agent_id) {
    expect_string(__wrap_agent_meta_snapshot_str, agent_id_str, agent_id);
    expect_any(__wrap_agent_meta_snapshot_str, out);
    will_return(__wrap_agent_meta_snapshot_str, -1);
}

static void expect_wdb_version(int agent_id_int, const char *version) {
    cJSON *agent_info = NULL;

    if (version) {
        agent_info = cJSON_CreateObject();
        cJSON *child = cJSON_CreateObject();
        cJSON_AddStringToObject(child, "version", version);
        agent_info->child = child;
    }

    expect_value(__wrap_wdb_get_agent_info, id, agent_id_int);
    will_return(__wrap_wdb_get_agent_info, agent_info);
}

static void expect_req_step(const char *response, int retcode) {
    expect_any(__wrap_req_send_and_wait, agent_id);
    expect_any(__wrap_req_send_and_wait, payload);
    will_return(__wrap_req_send_and_wait, response);
    will_return(__wrap_req_send_and_wait, retcode);
}

static cJSON *build_payload(const char *wpk_file, const char *sha1, const char *installer) {
    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "wpk_file", wpk_file);
    cJSON_AddStringToObject(payload, "wpk_sha1", sha1);
    cJSON_AddStringToObject(payload, "installer", installer);
    return payload;
}

/* Queues a full lock_restart/open/write(single chunk)/close/sha1/upgrade success sequence. */
static void expect_full_successful_push(FILE *fake_file, const char *sha1) {
    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."
    expect_any(__wrap__minfo, formatted_msg); // "successfully delivered..."

    expect_req_step("ok ", 0);                                  // lock_restart
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);      // open

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, fake_file);

    expect_fread("hello", 5);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);      // write

    expect_fread("", 0);                                        // EOF

    expect_fclose(fake_file, 0);

    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);      // close

    /* static: the buffer must remain valid until legacy_task_deliver_remote_upgrade() actually
     * consumes it later, well after this helper has returned. */
    static char sha1_response[128];
    snprintf(sha1_response, sizeof(sha1_response), "{\"error\":0,\"message\":\"%s\"}", sha1);
    expect_req_step(sha1_response, 0);                           // sha1

    expect_req_step("{\"error\":0,\"message\":\"0\"}", 0);       // upgrade
}

/* ---------------------------------------------------------------------- */
/* Version gate                                                            */
/* ---------------------------------------------------------------------- */

static void test_version_gate_unknown_version_skips(void **state) {
    (void) state;

    expect_cache_miss("020");
    expect_wdb_version(20, NULL);
    expect_any(__wrap__mdebug1, formatted_msg); // "has no known version, skipping..."

    char *version = NULL;
    assert_false(legacy_task_agent_is_pre_v5("020", &version));
    assert_null(version);
}

static void test_version_gate_unparseable_version_skips(void **state) {
    (void) state;

    expect_cache_miss("021");
    expect_wdb_version(21, "1.2.3");  // no 'v' char: must hit the unparseable-skip branch
    expect_any(__wrap__mdebug1, formatted_msg); // "reported an unparseable version..."

    char *version = NULL;
    assert_false(legacy_task_agent_is_pre_v5("021", &version));
    assert_null(version);
}

static void test_version_gate_5x_agent_skips(void **state) {
    (void) state;

    expect_cache_miss("022");
    expect_wdb_version(22, "Wazuh v5.0.0");
    expect_any(__wrap__mdebug2, formatted_msg); // "is on ... >= v5.0.0, skipping"

    char *version = NULL;
    assert_false(legacy_task_agent_is_pre_v5("022", &version));
    assert_null(version);
}

static void test_version_gate_legacy_agent_is_eligible(void **state) {
    (void) state;

    expect_cache_miss("023");
    expect_wdb_version(23, "Wazuh v4.14.6");

    char *version = NULL;
    assert_true(legacy_task_agent_is_pre_v5("023", &version));
    assert_non_null(version);
    assert_string_equal(version, "Wazuh v4.14.6");
    free(version);
}

/* ---------------------------------------------------------------------- */
/* Six-step push                                                           */
/* ---------------------------------------------------------------------- */

static void test_deliver_success(void **state) {
    (void) state;

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);
    expect_full_successful_push(fake_file, "abc123");

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_true(legacy_task_deliver_remote_upgrade("030", payload));
    cJSON_Delete(payload);
}

static void test_deliver_write_step_chunks_large_file(void **state) {
    (void) state;

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."
    expect_any(__wrap__minfo, formatted_msg); // "successfully delivered..."

    expect_req_step("ok ", 0);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);

    expect_string(__wrap_wfopen, path, "var/upgrade/big.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, fake_file);

    // Two full 32768-byte chunks, then EOF: exactly two 'write' round trips.
    char *chunk1 = malloc(32768);
    char *chunk2 = malloc(32768);
    memset(chunk1, 'A', 32768);
    memset(chunk2, 'B', 32768);

    expect_fread(chunk1, 32768);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);

    expect_fread(chunk2, 32768);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);

    expect_fread("", 0);

    expect_fclose(fake_file, 0);

    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);           // close
    expect_req_step("{\"error\":0,\"message\":\"abc123\"}", 0);      // sha1
    expect_req_step("{\"error\":0,\"message\":\"0\"}", 0);           // upgrade

    cJSON *payload = build_payload("big.wpk", "abc123", "upgrade.sh");
    assert_true(legacy_task_deliver_remote_upgrade("031", payload));
    cJSON_Delete(payload);

    free(chunk1);
    free(chunk2);
}

static void test_deliver_fails_on_lock_restart_no_further_steps(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."
    expect_any(__wrap__mwarn, formatted_msg); // "no response for step targeting 'com'"
    expect_any(__wrap__merror, formatted_msg); // "'lock_restart' step failed, aborting push"

    // Only one step is queued: if the code attempted 'open' (or any later step) after this
    // failure, __wrap_req_send_and_wait would find an empty mock queue and abort the test.
    expect_req_step(NULL, -1);

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_false(legacy_task_deliver_remote_upgrade("032", payload));
    cJSON_Delete(payload);
}

static void test_deliver_fails_on_write_step_no_retry(void **state) {
    (void) state;

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."

    expect_req_step("ok ", 0);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, fake_file);

    expect_fread("hello", 5);
    expect_req_step(NULL, -1); // write fails: no ack, no retry
    expect_any(__wrap__mwarn, formatted_msg); // "no response for step targeting 'upgrade'"

    expect_fclose(fake_file, 0);
    expect_any(__wrap__merror, formatted_msg); // "'write' step failed, aborting push (no retry)"

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_false(legacy_task_deliver_remote_upgrade("033", payload));
    cJSON_Delete(payload);

    // Only one write attempt was queued above: a retry would exhaust the mock queue and fail
    // this test with an "unexpected call" error instead of getting here.
}

static void test_deliver_fails_on_sha1_mismatch_no_upgrade_step(void **state) {
    (void) state;

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."

    expect_req_step("ok ", 0);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, fake_file);

    expect_fread("hello", 5);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);
    expect_fread("", 0);
    expect_fclose(fake_file, 0);

    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);              // close
    expect_req_step("{\"error\":0,\"message\":\"deadbeef\"}", 0);       // sha1 mismatch
    expect_any(__wrap__merror, formatted_msg); // "sha1 mismatch after transfer..."

    // No 'upgrade' step is queued: if the code sent it anyway, the mock queue would be empty.

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_false(legacy_task_deliver_remote_upgrade("034", payload));
    cJSON_Delete(payload);
}

/* ---------------------------------------------------------------------- */
/* Poll cycle: version-gate ordering + task-type filtering + no-retry       */
/* ---------------------------------------------------------------------- */

static keyentry *make_key(const char *id, int sock) {
    keyentry *key;
    os_calloc(1, sizeof(keyentry), key);
    key->id = strdup(id);
    key->sock = sock;
    return key;
}

/* One cycle, three connected agents:
 *  - '040' is >= v5.0.0: get_pending_tasks must never be reached for it.
 *  - '041' is < v5.0.0: its remote_upgrade task delivers, its active_response task is dropped
 *    (only 6 req_send_and_wait calls, not 12).
 *  - '042' is < v5.0.0: its remote_upgrade task's first step fails, no retry that cycle. */
static void test_poll_cycle_gating_filtering_and_no_retry(void **state) {
    (void) state;

    keyentry **keyentries;
    os_calloc(3, sizeof(keyentry *), keyentries);
    keyentries[0] = make_key("040", 5);
    keyentries[1] = make_key("041", 6);
    keyentries[2] = make_key("042", 7);
    keys.keyentries = keyentries;
    keys.keysize = 3;

    expect_any(__wrap__mdebug2, formatted_msg); // "checking 3 connected agent(s)"

    // Agent 040: >= v5.0.0.
    expect_cache_miss("040");
    expect_wdb_version(40, "Wazuh v5.0.0");
    expect_any(__wrap__mdebug2, formatted_msg); // "is on ... >= v5.0.0, skipping"

    // Agent 041: eligible, mixed task batch.
    expect_cache_miss("041");
    expect_wdb_version(41, "Wazuh v4.14.6");
    expect_any(__wrap__mdebug2, formatted_msg); // "is eligible, retrieving pending tasks"

    // Build the payload as an embedded JSON *string* field (matches the real wire shape, where
    // "payload" in a task is the task's payload re-serialized to text, not a nested object).
    cJSON *task_ar = cJSON_CreateObject();
    cJSON_AddStringToObject(task_ar, "task_id", "t-ar");
    cJSON_AddStringToObject(task_ar, "task_type", "active_response");
    cJSON_AddStringToObject(task_ar, "payload", "{}");

    cJSON *up_payload_obj = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    char *up_payload_str = cJSON_PrintUnformatted(up_payload_obj);
    cJSON *task_up = cJSON_CreateObject();
    cJSON_AddStringToObject(task_up, "task_id", "t-up");
    cJSON_AddStringToObject(task_up, "task_type", "remote_upgrade");
    cJSON_AddStringToObject(task_up, "payload", up_payload_str);
    os_free(up_payload_str);
    cJSON_Delete(up_payload_obj);

    cJSON *tasks_array = cJSON_CreateArray();
    cJSON_AddItemToArray(tasks_array, task_ar);
    cJSON_AddItemToArray(tasks_array, task_up);

    cJSON *response_041_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(response_041_obj, "status", "ok");
    cJSON_AddItemToObject(response_041_obj, "tasks", tasks_array);
    char *response_041 = cJSON_PrintUnformatted(response_041_obj);
    cJSON_Delete(response_041_obj);

    expect_string(__wrap_OS_ConnectUnixDomain, path, "queue/tasks/task");
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, 50);

    expect_value(__wrap_OS_SendSecureTCP, sock, 50);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 50);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, response_041);
    will_return(__wrap_OS_RecvSecureTCP, strlen(response_041));

    // The unsupported task type is logged and dropped -- no push attempted for it.
    expect_any(__wrap__minfo, formatted_msg);

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);
    expect_full_successful_push(fake_file, "abc123");

    // Agent 042: eligible, one remote_upgrade task whose push fails at the first step.
    expect_cache_miss("042");
    expect_wdb_version(42, "Wazuh v4.10.0");
    expect_any(__wrap__mdebug2, formatted_msg); // "is eligible, retrieving pending tasks"

    cJSON *up_payload_obj_2 = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    char *up_payload_str_2 = cJSON_PrintUnformatted(up_payload_obj_2);
    cJSON *task_up_2 = cJSON_CreateObject();
    cJSON_AddStringToObject(task_up_2, "task_id", "t-up-2");
    cJSON_AddStringToObject(task_up_2, "task_type", "remote_upgrade");
    cJSON_AddStringToObject(task_up_2, "payload", up_payload_str_2);
    os_free(up_payload_str_2);
    cJSON_Delete(up_payload_obj_2);

    cJSON *tasks_array_2 = cJSON_CreateArray();
    cJSON_AddItemToArray(tasks_array_2, task_up_2);

    cJSON *response_042_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(response_042_obj, "status", "ok");
    cJSON_AddItemToObject(response_042_obj, "tasks", tasks_array_2);
    char *response_042 = cJSON_PrintUnformatted(response_042_obj);
    cJSON_Delete(response_042_obj);

    expect_string(__wrap_OS_ConnectUnixDomain, path, "queue/tasks/task");
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, 51);

    expect_value(__wrap_OS_SendSecureTCP, sock, 51);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 51);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, response_042);
    will_return(__wrap_OS_RecvSecureTCP, strlen(response_042));

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..." (fails before success)

    // Only one attempt is queued: a retry would exhaust the mock queue and fail the test.
    expect_req_step(NULL, -1);
    expect_any(__wrap__mwarn, formatted_msg); // "no response for step targeting 'com'"
    expect_any(__wrap__merror, formatted_msg); // "'lock_restart' step failed, aborting push"

    legacy_upgrade_poll_cycle();

    os_free(response_041);
    os_free(response_042);

    os_free(keyentries[0]->id);
    os_free(keyentries[0]);
    os_free(keyentries[1]->id);
    os_free(keyentries[1]);
    os_free(keyentries[2]->id);
    os_free(keyentries[2]);
    os_free(keyentries);
}

/* R15 (previously missing): an eligible (<v5.0.0) agent whose get_pending_tasks response has zero
 * pending tasks. Must not crash, must not log anything spurious, and the cycle must move on to
 * completion cleanly (nothing left in any mock queue at the end). */
static void test_poll_cycle_eligible_agent_zero_pending_tasks(void **state) {
    (void) state;

    keyentry **keyentries;
    os_calloc(1, sizeof(keyentry *), keyentries);
    keyentries[0] = make_key("050", 8);
    keys.keyentries = keyentries;
    keys.keysize = 1;

    expect_any(__wrap__mdebug2, formatted_msg); // "checking 1 connected agent(s)"

    expect_cache_miss("050");
    expect_wdb_version(50, "Wazuh v4.14.6");
    expect_any(__wrap__mdebug2, formatted_msg); // "is eligible, retrieving pending tasks"

    cJSON *response_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(response_obj, "status", "ok");
    cJSON_AddItemToObject(response_obj, "tasks", cJSON_CreateArray());
    char *response = cJSON_PrintUnformatted(response_obj);
    cJSON_Delete(response_obj);

    expect_string(__wrap_OS_ConnectUnixDomain, path, "queue/tasks/task");
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, 60);

    expect_value(__wrap_OS_SendSecureTCP, sock, 60);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 60);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, strlen(response));

    // No req_send_and_wait/minfo/merror/remoted_enqueue_manager_event calls are queued: an empty
    // task list must not attempt any push and must not log a failure -- any unexpected call here
    // fails the test.
    legacy_upgrade_poll_cycle();

    os_free(response);
    os_free(keyentries[0]->id);
    os_free(keyentries[0]);
    os_free(keyentries);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_version_gate_unknown_version_skips, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_version_gate_unparseable_version_skips, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_version_gate_5x_agent_skips, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_version_gate_legacy_agent_is_eligible, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_write_step_chunks_large_file, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_lock_restart_no_further_steps, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_write_step_no_retry, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_sha1_mismatch_no_upgrade_step, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_poll_cycle_gating_filtering_and_no_retry, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_poll_cycle_eligible_agent_zero_pending_tasks, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
