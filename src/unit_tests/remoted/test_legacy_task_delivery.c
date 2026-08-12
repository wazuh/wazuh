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
#include "legacy_task_delivery.h"

#include "../wrappers/common.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/wazuhdb_queries_op_wrappers.h"
#include "../wrappers/wazuh/remoted/agent_metadata_wrappers.h"
#include "../wrappers/libc/stdio_wrappers.h"

/* Prototypes of the STATIC (test-exported under WAZUH_UNIT_TESTING) functions under test,
 * declared here rather than in a header -- same convention test_remcom.c already uses.
 * legacy_task_push_result_t must be kept identical (same names/values) to the copy in
 * legacy_task_delivery.c -- it's file-local there, so there's no header to share it from. */
typedef enum {
    LEGACY_TASK_PUSH_SUCCESS,
    LEGACY_TASK_PUSH_RETRYABLE,
    LEGACY_TASK_PUSH_PERMANENT
} legacy_task_push_result_t;

bool legacy_task_agent_is_pre_v5(const char *agent_id, char **out_version);
agent_version_check_t agent_meta_check_version(const char *agent_id_str, const char *min_version, char **out_version);
legacy_task_push_result_t legacy_task_deliver_remote_upgrade(const char *agent_id, const cJSON *payload_obj);
void legacy_upgrade_poll_cycle(void);
void legacy_task_drain_clear_upgrade_replies(void);

/* Must match LEGACY_TASK_MAX_PUSH_ATTEMPTS in legacy_task_delivery.c. */
#define LEGACY_TASK_MAX_PUSH_ATTEMPTS 3

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
    // Fresh, empty pending-replies queue for every test: this is file-local static state in
    // legacy_task_delivery.c that would otherwise leak/persist across test invocations.
    legacy_task_delivery_teardown();
    legacy_task_delivery_init();
    return 0;
}

static int test_teardown(void **state) {
    (void) state;
    test_mode = 0;
    keys.keyentries = NULL;
    keys.keysize = 0;
    // Free anything a test left un-drained (checked under ASan/LeakSanitizer).
    legacy_task_delivery_teardown();
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

/* Covers agent_meta_check_version()'s real logic (used by legacy_task_agent_is_pre_v5() above)
 * through the real function, all four outcomes. */
static void test_agent_meta_check_version_classifications(void **state) {
    (void) state;
    char *version = NULL;

    // Unknown: no cache entry, no wazuh-db info either.
    expect_cache_miss("100");
    expect_wdb_version(100, NULL);
    assert_int_equal(agent_meta_check_version("100", "v5.0.0", &version), AGENT_VERSION_CHECK_UNKNOWN);
    assert_null(version);

    // Unparseable: a version string was found but has no 'v' token.
    expect_cache_miss("101");
    expect_wdb_version(101, "4.14.6");
    assert_int_equal(agent_meta_check_version("101", "v5.0.0", &version), AGENT_VERSION_CHECK_UNPARSEABLE);
    assert_non_null(version);
    free(version);

    // >= min_version.
    expect_cache_miss("102");
    expect_wdb_version(102, "Wazuh v5.0.0");
    assert_int_equal(agent_meta_check_version("102", "v5.0.0", &version), AGENT_VERSION_CHECK_GE_MIN);
    assert_non_null(version);
    free(version);

    // < min_version.
    expect_cache_miss("103");
    expect_wdb_version(103, "Wazuh v4.14.6");
    assert_int_equal(agent_meta_check_version("103", "v5.0.0", &version), AGENT_VERSION_CHECK_LT_MIN);
    assert_non_null(version);
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
    assert_int_equal(legacy_task_deliver_remote_upgrade("030", payload), LEGACY_TASK_PUSH_SUCCESS);
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
    assert_int_equal(legacy_task_deliver_remote_upgrade("031", payload), LEGACY_TASK_PUSH_SUCCESS);
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
    assert_int_equal(legacy_task_deliver_remote_upgrade("032", payload), LEGACY_TASK_PUSH_RETRYABLE);
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
    expect_req_step(NULL, -1); // write fails: no ack
    expect_any(__wrap__mwarn, formatted_msg); // "no response for step targeting 'upgrade'"

    expect_fclose(fake_file, 0);
    expect_any(__wrap__merror, formatted_msg); // "'write' step failed, aborting push"

    // This call is made directly, once -- it proves this single call to
    // legacy_task_deliver_remote_upgrade() doesn't retry internally. The caller-side retry loop
    // (proven separately at the poll-cycle level) is what retries a RETRYABLE result.
    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_int_equal(legacy_task_deliver_remote_upgrade("033", payload), LEGACY_TASK_PUSH_RETRYABLE);
    cJSON_Delete(payload);

    // Only one write attempt was queued above: a second internal attempt would exhaust the mock
    // queue and fail this test with an "unexpected call" error instead of getting here.
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
    assert_int_equal(legacy_task_deliver_remote_upgrade("034", payload), LEGACY_TASK_PUSH_RETRYABLE);
    cJSON_Delete(payload);
}

static void test_deliver_fails_on_open_step(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."

    expect_req_step("ok ", 0);                 // lock_restart succeeds
    expect_req_step(NULL, -1);                 // open fails: no ack
    expect_any(__wrap__mwarn, formatted_msg);   // "no response for step targeting 'open'"
    expect_any(__wrap__merror, formatted_msg);  // "'open' step failed, aborting push"

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_int_equal(legacy_task_deliver_remote_upgrade("035", payload), LEGACY_TASK_PUSH_RETRYABLE);
    cJSON_Delete(payload);

    // No wfopen/fread call is queued: if the code proceeded to 'write' after this failure,
    // the mock queue for that step would be empty and fail the test.
}

static void test_deliver_fails_on_close_step(void **state) {
    (void) state;

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."

    expect_req_step("ok ", 0);                                    // lock_restart
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);       // open

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, fake_file);

    expect_fread("hello", 5);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);       // write
    expect_fread("", 0);
    expect_fclose(fake_file, 0);

    expect_req_step(NULL, -1);                  // close fails: no ack
    expect_any(__wrap__mwarn, formatted_msg);    // "no response for step targeting 'close'"
    expect_any(__wrap__merror, formatted_msg);   // "'close' step failed, aborting push"

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_int_equal(legacy_task_deliver_remote_upgrade("036", payload), LEGACY_TASK_PUSH_RETRYABLE);
    cJSON_Delete(payload);

    // No 'sha1'/'upgrade' step is queued: a further attempt would exhaust the mock queue.
}

static void test_deliver_fails_on_upgrade_exit_nonzero(void **state) {
    (void) state;

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."

    expect_req_step("ok ", 0);                                    // lock_restart
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);       // open

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, fake_file);

    expect_fread("hello", 5);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);       // write
    expect_fread("", 0);
    expect_fclose(fake_file, 0);

    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);            // close
    expect_req_step("{\"error\":0,\"message\":\"abc123\"}", 0);       // sha1, matches
    expect_req_step("{\"error\":0,\"message\":\"1\"}", 0);            // upgrade: non-zero exit status

    expect_any(__wrap__merror, formatted_msg); // "installer script failed (exit status: 1)"

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_int_equal(legacy_task_deliver_remote_upgrade("037", payload), LEGACY_TASK_PUSH_PERMANENT);
    cJSON_Delete(payload);
}

/* An invalid/incomplete payload (missing a required string field) is a permanent failure: the
 * payload's content won't change on a retry. Built directly via cJSON rather than build_payload()
 * so a field can be omitted. */
static void test_deliver_fails_on_invalid_payload_is_permanent(void **state) {
    (void) state;

    expect_any(__wrap__merror, formatted_msg); // "invalid or incomplete remote_upgrade payload..."

    cJSON *payload = cJSON_CreateObject();
    cJSON_AddStringToObject(payload, "wpk_file", "wazuh_agent.wpk");
    cJSON_AddStringToObject(payload, "wpk_sha1", "abc123");
    // "installer" is intentionally omitted.

    assert_int_equal(legacy_task_deliver_remote_upgrade("038", payload), LEGACY_TASK_PUSH_PERMANENT);
    cJSON_Delete(payload);
}

/* A missing/unreadable local WPK file (wfopen() failure) is a manager-local filesystem problem,
 * not a wire issue -- permanent, unlike test_deliver_fails_on_open_step's *wire* 'open' step
 * failure. The wire 'open' step must succeed here so the two failure points stay unambiguous. */
static void test_deliver_fails_on_local_wpk_file_missing_is_permanent(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."

    expect_req_step("ok ", 0);                                    // lock_restart
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);       // open (wire step succeeds)

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, NULL); // local wfopen() fails: file missing/unreadable on this host

    expect_any(__wrap__merror, formatted_msg); // "cannot open local WPK file..."

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_int_equal(legacy_task_deliver_remote_upgrade("039", payload), LEGACY_TASK_PUSH_PERMANENT);
    cJSON_Delete(payload);

    // No 'write'/'close'/'sha1'/'upgrade' step is queued: a retry here would exhaust the mock queue.
}

/* The 'upgrade' step's ack being lost entirely (no response) is permanent, unlike every other
 * step's no-ack case: we can't tell whether the agent already started running the installer
 * before the ack was lost, so retrying risks a double install -- worse than losing the task. */
static void test_deliver_fails_on_upgrade_step_no_ack_is_permanent_not_retryable(void **state) {
    (void) state;

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);

    expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."

    expect_req_step("ok ", 0);                                    // lock_restart
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);       // open

    expect_string(__wrap_wfopen, path, "var/upgrade/wazuh_agent.wpk");
    expect_string(__wrap_wfopen, mode, "rb");
    will_return(__wrap_wfopen, fake_file);

    expect_fread("hello", 5);
    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);       // write
    expect_fread("", 0);
    expect_fclose(fake_file, 0);

    expect_req_step("{\"error\":0,\"message\":\"ok\"}", 0);           // close
    expect_req_step("{\"error\":0,\"message\":\"abc123\"}", 0);      // sha1, matches

    expect_req_step(NULL, -1);                  // upgrade: no ack at all
    expect_any(__wrap__mwarn, formatted_msg);    // "no response for step targeting 'upgrade'"
    expect_any(__wrap__merror, formatted_msg);   // "'upgrade' step failed"

    cJSON *payload = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    assert_int_equal(legacy_task_deliver_remote_upgrade("039b", payload), LEGACY_TASK_PUSH_PERMANENT);
    cJSON_Delete(payload);
}

/* ---------------------------------------------------------------------- */
/* Retry loop boundedness (legacy_upgrade_poll_cycle)                      */
/* ---------------------------------------------------------------------- */

static keyentry *make_key(const char *id, int sock) {
    keyentry *key;
    os_calloc(1, sizeof(keyentry), key);
    key->id = strdup(id);
    key->sock = sock;
    return key;
}

/* Builds a single-agent, single-remote_upgrade-task poll cycle scenario and lets the caller queue
 * whatever req_send_and_wait()/log expectations it needs for the push attempt(s) before invoking
 * legacy_upgrade_poll_cycle(). Returns the allocated keyentries array; *out_response is set to the
 * heap-allocated task-manager response string. Both must stay alive until after
 * legacy_upgrade_poll_cycle() runs (mock() values are dequeued lazily, not at will_return() time)
 * and are freed by free_single_task_poll_cycle(). */
static keyentry **setup_single_task_poll_cycle(const char *agent_id, int agent_id_int, const char *version,
                                                int sock_id, char **out_response) {
    keyentry **keyentries;
    os_calloc(1, sizeof(keyentry *), keyentries);
    keyentries[0] = make_key(agent_id, sock_id);
    keys.keyentries = keyentries;
    keys.keysize = 1;

    expect_any(__wrap__mdebug2, formatted_msg); // "checking 1 connected agent(s)"

    expect_cache_miss(agent_id);
    expect_wdb_version(agent_id_int, version);
    expect_any(__wrap__mdebug2, formatted_msg); // "is eligible, retrieving pending tasks"

    cJSON *up_payload_obj = build_payload("wazuh_agent.wpk", "abc123", "upgrade.sh");
    char *up_payload_str = cJSON_PrintUnformatted(up_payload_obj);
    cJSON *task_up = cJSON_CreateObject();
    cJSON_AddStringToObject(task_up, "task_id", "t-retry");
    cJSON_AddStringToObject(task_up, "task_type", "remote_upgrade");
    cJSON_AddStringToObject(task_up, "payload", up_payload_str);
    os_free(up_payload_str);
    cJSON_Delete(up_payload_obj);

    cJSON *tasks_array = cJSON_CreateArray();
    cJSON_AddItemToArray(tasks_array, task_up);

    cJSON *response_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(response_obj, "status", "ok");
    cJSON_AddItemToObject(response_obj, "tasks", tasks_array);
    char *response = cJSON_PrintUnformatted(response_obj);
    cJSON_Delete(response_obj);
    *out_response = response;

    expect_string(__wrap_OS_ConnectUnixDomain, path, "queue/tasks/task");
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, sock_id);

    expect_value(__wrap_OS_SendSecureTCP, sock, sock_id);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, sock_id);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, strlen(response));

    return keyentries;
}

static void free_single_task_poll_cycle(keyentry **keyentries, char *response) {
    os_free(response);
    os_free(keyentries[0]->id);
    os_free(keyentries[0]);
    os_free(keyentries);
}

/* A RETRYABLE first attempt (lock_restart no-ack) followed by a fully successful second attempt
 * must recover within the same cycle: exactly 2 delivery attempts, no "giving up" log. */
static void test_poll_cycle_retry_recovers_within_same_cycle(void **state) {
    (void) state;

    char *response = NULL;
    keyentry **keyentries = setup_single_task_poll_cycle("060", 60, "Wazuh v4.14.6", 70, &response);

    expect_any(__wrap__minfo, formatted_msg); // "delivering..." (attempt 1)
    expect_req_step(NULL, -1);                 // attempt 1: lock_restart no-ack
    expect_any(__wrap__mwarn, formatted_msg);
    expect_any(__wrap__merror, formatted_msg); // "'lock_restart' step failed..."

    FILE *fake_file = tmpfile();
    assert_non_null(fake_file);
    expect_full_successful_push(fake_file, "abc123"); // attempt 2: succeeds fully

    // No "giving up" merror is queued: if the code logged one after a SUCCESS, the mock string
    // wouldn't match (this uses expect_any elsewhere, so absence is enforced by exhausting exactly
    // the calls above and no more).
    legacy_upgrade_poll_cycle();

    free_single_task_poll_cycle(keyentries, response);
}

/* Every attempt fails RETRYABLE (lock_restart no-ack each time): the loop must stop after exactly
 * LEGACY_TASK_MAX_PUSH_ATTEMPTS attempts and log "giving up". Mock queues are sized for exactly
 * that many attempts -- a 4th attempt would hit an empty queue and fail the test, which is the
 * boundedness guarantee this test exists to prove. */
static void test_poll_cycle_retry_exhausts_cap_and_gives_up(void **state) {
    (void) state;

    char *response = NULL;
    keyentry **keyentries = setup_single_task_poll_cycle("061", 61, "Wazuh v4.14.6", 71, &response);

    for (int attempt = 0; attempt < LEGACY_TASK_MAX_PUSH_ATTEMPTS; attempt++) {
        expect_any(__wrap__minfo, formatted_msg); // "delivering..." (each attempt re-logs it)
        expect_req_step(NULL, -1);                 // lock_restart no-ack, every attempt
        expect_any(__wrap__mwarn, formatted_msg);
        expect_any(__wrap__merror, formatted_msg); // "'lock_restart' step failed..."
    }

    expect_string(__wrap__merror, formatted_msg,
        "legacy_task_delivery: agent '061': task 't-retry' did not succeed after 3 attempt(s), "
        "giving up -- the Task Manager has already marked it delivered, so it will not be offered again");

    legacy_upgrade_poll_cycle();

    free_single_task_poll_cycle(keyentries, response);
}

/* A PERMANENT failure on the first attempt (invalid payload) must short-circuit immediately and
 * waste no retry budget: the mock queue is sized for exactly one attempt, and no "giving up" log
 * fires (that log is RETRYABLE-only). */
static void test_poll_cycle_permanent_failure_short_circuits_no_retry(void **state) {
    (void) state;

    keyentry **keyentries;
    os_calloc(1, sizeof(keyentry *), keyentries);
    keyentries[0] = make_key("062", 72);
    keys.keyentries = keyentries;
    keys.keysize = 1;

    expect_any(__wrap__mdebug2, formatted_msg); // "checking 1 connected agent(s)"

    expect_cache_miss("062");
    expect_wdb_version(62, "Wazuh v4.14.6");
    expect_any(__wrap__mdebug2, formatted_msg); // "is eligible, retrieving pending tasks"

    // Invalid payload (missing "installer"), embedded as the task's payload string -- this
    // classifies PERMANENT (upgrade-no-ack is the other PERMANENT case, but that requires a full
    // six-step mock sequence; the invalid-payload case is the simplest one-shot PERMANENT proof).
    cJSON *bad_payload_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(bad_payload_obj, "wpk_file", "wazuh_agent.wpk");
    cJSON_AddStringToObject(bad_payload_obj, "wpk_sha1", "abc123");
    char *bad_payload_str = cJSON_PrintUnformatted(bad_payload_obj);
    cJSON_Delete(bad_payload_obj);

    cJSON *task_up = cJSON_CreateObject();
    cJSON_AddStringToObject(task_up, "task_id", "t-bad");
    cJSON_AddStringToObject(task_up, "task_type", "remote_upgrade");
    cJSON_AddStringToObject(task_up, "payload", bad_payload_str);
    os_free(bad_payload_str);

    cJSON *tasks_array = cJSON_CreateArray();
    cJSON_AddItemToArray(tasks_array, task_up);

    cJSON *response_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(response_obj, "status", "ok");
    cJSON_AddItemToObject(response_obj, "tasks", tasks_array);
    char *response = cJSON_PrintUnformatted(response_obj);
    cJSON_Delete(response_obj);

    expect_string(__wrap_OS_ConnectUnixDomain, path, "queue/tasks/task");
    expect_any(__wrap_OS_ConnectUnixDomain, type);
    expect_any(__wrap_OS_ConnectUnixDomain, max_msg_size);
    will_return(__wrap_OS_ConnectUnixDomain, 72);

    expect_value(__wrap_OS_SendSecureTCP, sock, 72);
    expect_any(__wrap_OS_SendSecureTCP, size);
    expect_any(__wrap_OS_SendSecureTCP, msg);
    will_return(__wrap_OS_SendSecureTCP, 0);

    expect_value(__wrap_OS_RecvSecureTCP, sock, 72);
    expect_any(__wrap_OS_RecvSecureTCP, size);
    will_return(__wrap_OS_RecvSecureTCP, response);
    will_return(__wrap_OS_RecvSecureTCP, strlen(response));

    // Exactly one merror ("invalid or incomplete...") is queued: if the loop retried, no
    // req_send_and_wait mock exists at all for this task, so a retry attempt would abort the test
    // via an unexpected-call error long before reaching a second "invalid payload" check.
    expect_any(__wrap__merror, formatted_msg); // "invalid or incomplete remote_upgrade payload..."

    legacy_upgrade_poll_cycle();

    free_single_task_poll_cycle(keyentries, response);
}

/* ---------------------------------------------------------------------- */
/* Poll cycle: version-gate ordering + task-type filtering + bounded retry  */
/* ---------------------------------------------------------------------- */

/* One cycle, three connected agents:
 *  - '040' is >= v5.0.0: get_pending_tasks must never be reached for it.
 *  - '041' is < v5.0.0: its remote_upgrade task delivers, its active_response task is dropped
 *    (only 6 req_send_and_wait calls, not 12).
 *  - '042' is < v5.0.0: its remote_upgrade task's first step fails every attempt, retried up to
 *    LEGACY_TASK_MAX_PUSH_ATTEMPTS times, then given up on. */
static void test_poll_cycle_gating_filtering_and_bounded_retry(void **state) {
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

    // Agent 042: eligible, one remote_upgrade task whose push fails at the first step on every attempt.
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

    // A lock_restart no-ack is RETRYABLE, so this is retried up to LEGACY_TASK_MAX_PUSH_ATTEMPTS
    // times -- queue exactly that many failing attempts, or the loop trying a further attempt
    // would hit an empty mock queue and fail the test (the boundedness guarantee this proves).
    for (int attempt = 0; attempt < LEGACY_TASK_MAX_PUSH_ATTEMPTS; attempt++) {
        expect_any(__wrap__minfo, formatted_msg); // "delivering remote_upgrade task..."
        expect_req_step(NULL, -1);
        expect_any(__wrap__mwarn, formatted_msg); // "no response for step targeting 'com'"
        expect_any(__wrap__merror, formatted_msg); // "'lock_restart' step failed, aborting push"
    }

    expect_string(__wrap__merror, formatted_msg,
        "legacy_task_delivery: agent '042': task 't-up-2' did not succeed after 3 attempt(s), "
        "giving up -- the Task Manager has already marked it delivered, so it will not be offered again");

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

    // No req_send_and_wait/minfo/merror calls are queued: an empty task list must not attempt
    // any push and must not log a failure -- any unexpected call here fails the test.
    legacy_upgrade_poll_cycle();

    os_free(response);
    os_free(keyentries[0]->id);
    os_free(keyentries[0]);
    os_free(keyentries);
}

/* Tests for legacy_task_process_upgrade_ack() -- the ack must always be replied to with
 * clear_upgrade_result when it's a recognized upgrade_update_status message, regardless of the
 * reported outcome, and never touch any task's stored status (that's out of scope -- 'delivered'
 * is the Task Manager's own terminal state for a legacy push, by design). */

void test_process_upgrade_ack_success_replies_clear_upgrade_result(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg); // "reported upgrade result ..."

    // No req_send_and_wait mock queued: proves the ack call only enqueues, it does not block on
    // the reply round-trip itself.
    bool result = legacy_task_process_upgrade_ack("001",
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":0,"
        "\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}");

    assert_true(result);

    expect_string(__wrap_req_send_and_wait, agent_id, "001");
    expect_string(__wrap_req_send_and_wait, payload, "upgrade {\"command\":\"clear_upgrade_result\",\"parameters\":{}}");
    will_return(__wrap_req_send_and_wait, "{\"error\":0}");
    will_return(__wrap_req_send_and_wait, 0);

    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_failure_still_replies_clear_upgrade_result(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg); // "reported upgrade result ..."

    bool result = legacy_task_process_upgrade_ack("002",
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":2,"
        "\"message\":\"Upgrade failed\",\"status\":\"Failed\"}}");

    assert_true(result);

    // Reported outcome doesn't matter -- still enqueues and, on drain, still replies.
    expect_string(__wrap_req_send_and_wait, agent_id, "002");
    expect_string(__wrap_req_send_and_wait, payload, "upgrade {\"command\":\"clear_upgrade_result\",\"parameters\":{}}");
    will_return(__wrap_req_send_and_wait, "{\"error\":0}");
    will_return(__wrap_req_send_and_wait, 0);

    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_malformed_json_ignored(void **state) {
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg,
        "legacy_task_delivery: agent '003' sent an unparseable upgrade acknowledgment, ignoring");

    // No req_send_and_wait call queued -- any call here fails the test.
    bool result = legacy_task_process_upgrade_ack("003", "not json");

    assert_false(result);

    // Nothing was enqueued for a rejected ack: draining with no mocks queued must be a no-op.
    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_unexpected_command_ignored(void **state) {
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg,
        "legacy_task_delivery: agent '004' sent an upgrade acknowledgment with an unexpected "
        "'command', ignoring");

    bool result = legacy_task_process_upgrade_ack("004", "{\"command\":\"something_else\",\"parameters\":{}}");

    assert_false(result);

    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_missing_parameters_ignored(void **state) {
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg,
        "legacy_task_delivery: agent '005' sent an upgrade acknowledgment with a missing or "
        "invalid 'parameters', ignoring");

    bool result = legacy_task_process_upgrade_ack("005", "{\"command\":\"upgrade_update_status\"}");

    assert_false(result);

    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_non_object_parameters_ignored(void **state) {
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg,
        "legacy_task_delivery: agent '005' sent an upgrade acknowledgment with a missing or "
        "invalid 'parameters', ignoring");

    bool result = legacy_task_process_upgrade_ack("005",
        "{\"command\":\"upgrade_update_status\",\"parameters\":\"not an object\"}");

    assert_false(result);

    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_missing_error_field_ignored(void **state) {
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg,
        "legacy_task_delivery: agent '005' sent an upgrade acknowledgment with a missing or "
        "invalid 'parameters.error', ignoring");

    bool result = legacy_task_process_upgrade_ack("005",
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"message\":\"x\",\"status\":\"Done\"}}");

    assert_false(result);

    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_missing_parameters_object_ignored(void **state) {
    (void) state;

    expect_string(__wrap__mdebug1, formatted_msg,
        "legacy_task_delivery: agent '005' sent an upgrade acknowledgment with a missing or "
        "invalid 'parameters', ignoring");

    // No "parameters" object at all: caught by the standalone 'parameters' guard, before
    // the 'parameters.error' check is ever reached.
    bool result = legacy_task_process_upgrade_ack("005",
        "{\"command\":\"upgrade_update_status\"}");

    assert_false(result);

    legacy_task_drain_clear_upgrade_replies();
}

void test_process_upgrade_ack_reply_failure_still_returns_true(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg); // "reported upgrade result ..."

    // The ack itself is well-formed and processed -- true even before any reply is attempted.
    bool result = legacy_task_process_upgrade_ack("006",
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":0,"
        "\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}");

    assert_true(result);

    // The wire round-trip itself fails during drain: the warning must still fire there without
    // crashing.
    expect_string(__wrap_req_send_and_wait, agent_id, "006");
    expect_string(__wrap_req_send_and_wait, payload, "upgrade {\"command\":\"clear_upgrade_result\",\"parameters\":{}}");
    will_return(__wrap_req_send_and_wait, NULL);
    will_return(__wrap_req_send_and_wait, -1);

    expect_string(__wrap__mwarn, formatted_msg,
        "legacy_task_delivery: agent '006': no response for step targeting 'upgrade'");
    expect_string(__wrap__mwarn, formatted_msg,
        "legacy_task_delivery: agent '006': failed to deliver 'clear_upgrade_result', the agent "
        "may keep resending its upgrade acknowledgment");

    legacy_task_drain_clear_upgrade_replies();
}

/* Core regression proof: several distinct agents' acks arriving back-to-back must never block on
 * each other, however many arrive in a row -- the scenario a burst of simultaneous upgrade
 * completions produces. Expressed as an ordering/non-blocking property (zero req_send_and_wait
 * mocks queued while processing every ack) rather than real concurrency: cmocka's mocking model
 * is single-threaded, so a genuine multi-thread stress test would be flaky/non-portable here. */
void test_process_upgrade_ack_burst_of_agents_does_not_block(void **state) {
    (void) state;

    const char *agent_ids[] = {"010", "011", "012", "013"};
    const size_t n = sizeof(agent_ids) / sizeof(agent_ids[0]);

    for (size_t i = 0; i < n; i++) {
        expect_any(__wrap__minfo, formatted_msg);
        bool result = legacy_task_process_upgrade_ack(agent_ids[i],
            "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":0,"
            "\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}");
        assert_true(result);
    }

    // One drain call flushes all of them, in FIFO enqueue order.
    for (size_t i = 0; i < n; i++) {
        expect_string(__wrap_req_send_and_wait, agent_id, agent_ids[i]);
        expect_string(__wrap_req_send_and_wait, payload,
                      "upgrade {\"command\":\"clear_upgrade_result\",\"parameters\":{}}");
        will_return(__wrap_req_send_and_wait, "{\"error\":0}");
        will_return(__wrap_req_send_and_wait, 0);
    }

    legacy_task_drain_clear_upgrade_replies();
}

/* Draining an empty queue must be a safe no-op: no crash, no wire call, no log. */
void test_drain_clear_upgrade_replies_empty_queue_is_noop(void **state) {
    (void) state;

    legacy_task_drain_clear_upgrade_replies();
}

/* No dedup by design: two acks queued for the same agent before draining must each get their own
 * reply, not be collapsed into one. */
void test_process_upgrade_ack_duplicate_same_agent_replies_twice(void **state) {
    (void) state;

    expect_any(__wrap__minfo, formatted_msg);
    assert_true(legacy_task_process_upgrade_ack("020",
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":0,"
        "\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}"));

    expect_any(__wrap__minfo, formatted_msg);
    assert_true(legacy_task_process_upgrade_ack("020",
        "{\"command\":\"upgrade_update_status\",\"parameters\":{\"error\":0,"
        "\"message\":\"Upgrade was successful\",\"status\":\"Done\"}}"));

    for (int i = 0; i < 2; i++) {
        expect_string(__wrap_req_send_and_wait, agent_id, "020");
        expect_string(__wrap_req_send_and_wait, payload,
                      "upgrade {\"command\":\"clear_upgrade_result\",\"parameters\":{}}");
        will_return(__wrap_req_send_and_wait, "{\"error\":0}");
        will_return(__wrap_req_send_and_wait, 0);
    }

    legacy_task_drain_clear_upgrade_replies();
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_version_gate_unknown_version_skips, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_version_gate_unparseable_version_skips, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_version_gate_5x_agent_skips, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_version_gate_legacy_agent_is_eligible, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_agent_meta_check_version_classifications, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_success, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_write_step_chunks_large_file, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_lock_restart_no_further_steps, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_write_step_no_retry, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_sha1_mismatch_no_upgrade_step, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_open_step, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_close_step, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_upgrade_exit_nonzero, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_invalid_payload_is_permanent, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_local_wpk_file_missing_is_permanent, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_deliver_fails_on_upgrade_step_no_ack_is_permanent_not_retryable, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_poll_cycle_retry_recovers_within_same_cycle, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_poll_cycle_retry_exhausts_cap_and_gives_up, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_poll_cycle_permanent_failure_short_circuits_no_retry, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_poll_cycle_gating_filtering_and_bounded_retry, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_poll_cycle_eligible_agent_zero_pending_tasks, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_success_replies_clear_upgrade_result, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_failure_still_replies_clear_upgrade_result, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_malformed_json_ignored, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_unexpected_command_ignored, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_missing_parameters_ignored, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_non_object_parameters_ignored, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_missing_error_field_ignored, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_missing_parameters_object_ignored, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_reply_failure_still_returns_true, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_burst_of_agents_does_not_block, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_drain_clear_upgrade_replies_empty_queue_is_noop, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_process_upgrade_ack_duplicate_same_agent_replies_twice, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
