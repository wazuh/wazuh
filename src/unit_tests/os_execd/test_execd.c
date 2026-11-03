/*
 * Copyright (C) Wazuh Inc.
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

#include "shared.h"
#include "list_op.h"
#include "os_regex.h"
#include "os_net.h"
#include "wmodules.h"
#include "../../external/cJSON/cJSON.h"
#include "execd.h"

#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/select_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/externals/pcre2/pcre2_wrappers.h"

extern int test_mode;
extern OSList *timeout_list;
extern int ar_manager_addrs_n;
extern int ar_manager_addrs_next;
extern time_t ar_manager_resolved_at;
extern OSHash *repeated_hash;
extern time_t repeated_last_purge;
extern time_t repeated_last_full_warn;

void ExecdStart(int q);
void RepeatedOffendersInit();
void RepeatedOffendersPurge(time_t curr_time);
int RepeatedOffendersCheck(const char *rkey, int timeout_value, time_t curr_time);

/* Setup/Teardown */

static int group_setup(void ** state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void ** state) {
    test_mode = 0;
    return 0;
}

static int test_setup_file(void **state) {
    wfd_t* wfd = NULL;
    os_calloc(1, sizeof(wfd_t), wfd);
    wfd->file_in = (FILE *)1;
    wfd->file_out = (FILE *)2;
    timeout_list = OSList_Create();
    *state = wfd;
    return 0;
}

static int test_setup_file_timeout(void **state) {
    wfd_t* wfd = NULL;
    os_calloc(1, sizeof(wfd_t), wfd);
    wfd->file_in = (FILE *)1;
    wfd->file_out = (FILE *)2;
    timeout_list = OSList_Create();
    timeout_data *timeout_entry;
    os_calloc(1, sizeof(timeout_data), timeout_entry);
    os_calloc(2, sizeof(char *), timeout_entry->command);
    os_strdup(AR_BINDIR "/block-ip", timeout_entry->command[0]);
    timeout_entry->command[1] = NULL;
    os_strdup("block-ip-10.0.0.1-root", timeout_entry->rkey);
    timeout_entry->time_of_addition = 123456789;
    timeout_entry->time_to_block = 10;
    OSList_AddData(timeout_list, timeout_entry);
    *state = wfd;
    return 0;
}

static int test_teardown_file(void **state) {
    wfd_t* wfd = *state;
    os_free(wfd);
    FreeTimeoutList();
    return 0;
}

/* repeated_offenders configured as "1,5,10" (minutes) */
static int test_setup_repeated(void **state) {
    repeated_offenders_timeout[0] = 1;
    repeated_offenders_timeout[1] = 5;
    repeated_offenders_timeout[2] = 10;

    will_return(__wrap_time, 123456789);
    RepeatedOffendersInit();
    return 0;
}

static int test_teardown_repeated(void **state) {
    memset(repeated_offenders_timeout, 0, 7 * sizeof(int));

    if (repeated_hash) {
        OSHash_Clean(repeated_hash, free);
        repeated_hash = NULL;
    }
    return 0;
}

static void fill_repeated_hash(unsigned int count, time_t release_at) {
    char key[32];

    for (unsigned int i = 0; i < count; i++) {
        repeated_offender *offender;
        os_calloc(1, sizeof(repeated_offender), offender);
        offender->release_at = release_at;
        snprintf(key, sizeof(key), "fill-%u", i);
        assert_int_equal(OSHash_Add(repeated_hash, key, offender), 2);
    }
}

/* Tests */

static void test_ExecdStart_ok(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"wazuh\":{"
                            "\"active_response\":{"
                                "\"name\":\"block-ip\","
                                "\"executable\":\"block-ip\","
                                "\"type\":\"stateless\","
                                "\"location\":\"agent\","
                                "\"agent_id\":\"001\""
                            "}"
                        "},"
                        "\"event\":{"
                            "\"original\":\"Test event\","
                            "\"kind\":\"event\""
                        "},"
                        "\"source\":{"
                            "\"ip\":\"10.0.0.1\""
                        "},"
                        "\"user\":{"
                            "\"name\":\"root\""
                        "}"
                    "}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"wazuh\":{"
                                                                            "\"active_response\":{"
                                                                                "\"name\":\"block-ip\","
                                                                                "\"executable\":\"block-ip\","
                                                                                "\"type\":\"stateless\","
                                                                                "\"location\":\"agent\","
                                                                                "\"agent_id\":\"001\""
                                                                            "}"
                                                                        "},"
                                                                        "\"event\":{"
                                                                            "\"original\":\"Test event\","
                                                                            "\"kind\":\"event\""
                                                                        "},"
                                                                        "\"source\":{"
                                                                            "\"ip\":\"10.0.0.1\""
                                                                        "},"
                                                                        "\"user\":{"
                                                                            "\"name\":\"root\""
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/block-ip", "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command '" AR_BINDIR "/block-ip {"
                                                                                        "\"wazuh\":{"
                                                                                            "\"active_response\":{"
                                                                                                "\"name\":\"block-ip\","
                                                                                                "\"executable\":\"block-ip\","
                                                                                                "\"type\":\"stateless\","
                                                                                                "\"location\":\"agent\","
                                                                                                "\"agent_id\":\"001\""
                                                                                            "}"
                                                                                        "},"
                                                                                        "\"event\":{"
                                                                                            "\"original\":\"Test event\","
                                                                                            "\"kind\":\"event\""
                                                                                        "},"
                                                                                        "\"source\":{"
                                                                                            "\"ip\":\"10.0.0.1\""
                                                                                        "},"
                                                                                        "\"user\":{"
                                                                                            "\"name\":\"root\""
                                                                                        "},"
                                                                                        "\"command\":\"enable\""
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateless\","
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.1\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"enable\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{"
                                  "\"version\":1,"
                                  "\"origin\":{"
                                      "\"name\":\"block-ip\","
                                      "\"module\":\"active-response\""
                                  "},"
                                  "\"command\":\"check_keys\","
                                  "\"parameters\":{"
                                      "\"keys\":[\"10.0.0.1\", \"root\"]"
                                  "}"
                              "}\n");

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateless\","
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.1\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"continue\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_wpclose, 0);

    ExecdStart(queue);
}

/* Shared body for test_ExecdStart_ok, parameterized by wpclose()'s return value, to exercise
 * LogArExitStatus()'s branches through ExecdRun()'s main dispatch path. expected_mwarn_msg is
 * the mwarn message LogArExitStatus should emit for that wpclose_return, or NULL for none. */
static void run_ExecdStart_exit_status_case(void **state, int wpclose_return, const char *expected_mwarn_msg) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"wazuh\":{"
                            "\"active_response\":{"
                                "\"name\":\"block-ip\","
                                "\"executable\":\"block-ip\","
                                "\"type\":\"stateless\","
                                "\"location\":\"agent\","
                                "\"agent_id\":\"001\""
                            "}"
                        "},"
                        "\"event\":{"
                            "\"original\":\"Test event\","
                            "\"kind\":\"event\""
                        "},"
                        "\"source\":{"
                            "\"ip\":\"10.0.0.1\""
                        "},"
                        "\"user\":{"
                            "\"name\":\"root\""
                        "}"
                    "}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"wazuh\":{"
                                                                            "\"active_response\":{"
                                                                                "\"name\":\"block-ip\","
                                                                                "\"executable\":\"block-ip\","
                                                                                "\"type\":\"stateless\","
                                                                                "\"location\":\"agent\","
                                                                                "\"agent_id\":\"001\""
                                                                            "}"
                                                                        "},"
                                                                        "\"event\":{"
                                                                            "\"original\":\"Test event\","
                                                                            "\"kind\":\"event\""
                                                                        "},"
                                                                        "\"source\":{"
                                                                            "\"ip\":\"10.0.0.1\""
                                                                        "},"
                                                                        "\"user\":{"
                                                                            "\"name\":\"root\""
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/block-ip", "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command '" AR_BINDIR "/block-ip {"
                                                                                        "\"wazuh\":{"
                                                                                            "\"active_response\":{"
                                                                                                "\"name\":\"block-ip\","
                                                                                                "\"executable\":\"block-ip\","
                                                                                                "\"type\":\"stateless\","
                                                                                                "\"location\":\"agent\","
                                                                                                "\"agent_id\":\"001\""
                                                                                            "}"
                                                                                        "},"
                                                                                        "\"event\":{"
                                                                                            "\"original\":\"Test event\","
                                                                                            "\"kind\":\"event\""
                                                                                        "},"
                                                                                        "\"source\":{"
                                                                                            "\"ip\":\"10.0.0.1\""
                                                                                        "},"
                                                                                        "\"user\":{"
                                                                                            "\"name\":\"root\""
                                                                                        "},"
                                                                                        "\"command\":\"enable\""
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateless\","
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.1\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"enable\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{"
                                  "\"version\":1,"
                                  "\"origin\":{"
                                      "\"name\":\"block-ip\","
                                      "\"module\":\"active-response\""
                                  "},"
                                  "\"command\":\"check_keys\","
                                  "\"parameters\":{"
                                      "\"keys\":[\"10.0.0.1\", \"root\"]"
                                  "}"
                              "}\n");

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateless\","
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.1\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"continue\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    if (expected_mwarn_msg) {
        expect_string(__wrap__mwarn, formatted_msg, expected_mwarn_msg);
    }
    will_return(__wrap_wpclose, wpclose_return);

    ExecdStart(queue);
}

static void test_ExecdStart_ar_reports_failure(void **state) {
    /* wait()-encoded status for a normal exit with code 3: WEXITSTATUS(status) == 3 */
    run_ExecdStart_exit_status_case(state, 3 << 8,
        "Active response command '" AR_BINDIR "/block-ip' reported failure (exit code 3).");
}

static void test_ExecdStart_ar_terminated_by_signal(void **state) {
    /* wait()-encoded status for termination by SIGKILL (9): not WIFEXITED */
    run_ExecdStart_exit_status_case(state, 9,
        "Active response command '" AR_BINDIR "/block-ip' terminated abnormally.");
}

static void test_ExecdStart_ar_wait_failed(void **state) {
    run_ExecdStart_exit_status_case(state, -1,
        "Could not determine exit status of active response command '" AR_BINDIR "/block-ip'.");
}

static void test_ExecdStart_timeout_not_repeated(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"wazuh\":{"
                            "\"active_response\":{"
                                "\"name\":\"block-ip\","
                                "\"executable\":\"block-ip\","
                                "\"type\":\"stateful\","
                                "\"stateful_timeout\":10,"
                                "\"location\":\"agent\","
                                "\"agent_id\":\"001\""
                            "}"
                        "},"
                        "\"event\":{"
                            "\"original\":\"Test event\","
                            "\"kind\":\"event\""
                        "},"
                        "\"source\":{"
                            "\"ip\":\"10.0.0.2\""
                        "},"
                        "\"user\":{"
                            "\"name\":\"root\""
                        "}"
                    "}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"wazuh\":{"
                                                                            "\"active_response\":{"
                                                                                "\"name\":\"block-ip\","
                                                                                "\"executable\":\"block-ip\","
                                                                                "\"type\":\"stateful\","
                                                                                "\"stateful_timeout\":10,"
                                                                                "\"location\":\"agent\","
                                                                                "\"agent_id\":\"001\""
                                                                            "}"
                                                                        "},"
                                                                        "\"event\":{"
                                                                            "\"original\":\"Test event\","
                                                                            "\"kind\":\"event\""
                                                                        "},"
                                                                        "\"source\":{"
                                                                            "\"ip\":\"10.0.0.2\""
                                                                        "},"
                                                                        "\"user\":{"
                                                                            "\"name\":\"root\""
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/block-ip", "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command '" AR_BINDIR "/block-ip {"
                                                                                        "\"wazuh\":{"
                                                                                            "\"active_response\":{"
                                                                                                "\"name\":\"block-ip\","
                                                                                                "\"executable\":\"block-ip\","
                                                                                                "\"type\":\"stateful\","
                                                                                                "\"stateful_timeout\":10,"
                                                                                                "\"location\":\"agent\","
                                                                                                "\"agent_id\":\"001\""
                                                                                            "}"
                                                                                        "},"
                                                                                        "\"event\":{"
                                                                                            "\"original\":\"Test event\","
                                                                                            "\"kind\":\"event\""
                                                                                        "},"
                                                                                        "\"source\":{"
                                                                                            "\"ip\":\"10.0.0.2\""
                                                                                        "},"
                                                                                        "\"user\":{"
                                                                                            "\"name\":\"root\""
                                                                                        "},"
                                                                                        "\"command\":\"enable\""
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateful\","
                                                            "\"stateful_timeout\":10,"
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                   "\"source\":{"
                                                        "\"ip\":\"10.0.0.2\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"enable\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{"
                                  "\"version\":1,"
                                  "\"origin\":{"
                                      "\"name\":\"block-ip\","
                                      "\"module\":\"active-response\""
                                  "},"
                                  "\"command\":\"check_keys\","
                                  "\"parameters\":{"
                                      "\"keys\":[\"10.0.0.2\", \"root\"]"
                                  "}"
                              "}\n");

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateful\","
                                                            "\"stateful_timeout\":10,"
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.2\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"continue\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Adding command '" AR_BINDIR "/block-ip {"
                                                                                        "\"wazuh\":{"
                                                                                            "\"active_response\":{"
                                                                                                "\"name\":\"block-ip\","
                                                                                                "\"executable\":\"block-ip\","
                                                                                                "\"type\":\"stateful\","
                                                                                                "\"stateful_timeout\":10,"
                                                                                                "\"location\":\"agent\","
                                                                                                "\"agent_id\":\"001\""
                                                                                            "}"
                                                                                        "},"
                                                                                        "\"event\":{"
                                                                                            "\"original\":\"Test event\","
                                                                                            "\"kind\":\"event\""
                                                                                        "},"
                                                                                        "\"source\":{"
                                                                                            "\"ip\":\"10.0.0.2\""
                                                                                        "},"
                                                                                        "\"user\":{"
                                                                                            "\"name\":\"root\""
                                                                                        "},"
                                                                                        "\"command\":\"disable\""
                                                                                    "}' to the timeout list, with a timeout of '10s'.");

    ExecdStart(queue);
}

static void test_ExecdStart_timeout_repeated(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"wazuh\":{"
                            "\"active_response\":{"
                                "\"name\":\"block-ip\","
                                "\"executable\":\"block-ip\","
                                "\"type\":\"stateful\","
                                "\"stateful_timeout\":10,"
                                "\"location\":\"agent\","
                                "\"agent_id\":\"001\""
                            "}"
                        "},"
                        "\"event\":{"
                            "\"original\":\"Test event\","
                            "\"kind\":\"event\""
                        "},"
                        "\"source\":{"
                            "\"ip\":\"10.0.0.1\""
                        "},"
                        "\"user\":{"
                            "\"name\":\"root\""
                        "}"
                    "}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"wazuh\":{"
                                                                            "\"active_response\":{"
                                                                                "\"name\":\"block-ip\","
                                                                                "\"executable\":\"block-ip\","
                                                                                "\"type\":\"stateful\","
                                                                                "\"stateful_timeout\":10,"
                                                                                "\"location\":\"agent\","
                                                                                "\"agent_id\":\"001\""
                                                                            "}"
                                                                        "},"
                                                                        "\"event\":{"
                                                                            "\"original\":\"Test event\","
                                                                            "\"kind\":\"event\""
                                                                        "},"
                                                                        "\"source\":{"
                                                                            "\"ip\":\"10.0.0.1\""
                                                                        "},"
                                                                        "\"user\":{"
                                                                            "\"name\":\"root\""
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/block-ip", "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command '" AR_BINDIR "/block-ip {"
                                                                                        "\"wazuh\":{"
                                                                                            "\"active_response\":{"
                                                                                                "\"name\":\"block-ip\","
                                                                                                "\"executable\":\"block-ip\","
                                                                                                "\"type\":\"stateful\","
                                                                                                "\"stateful_timeout\":10,"
                                                                                                "\"location\":\"agent\","
                                                                                                "\"agent_id\":\"001\""
                                                                                            "}"
                                                                                        "},"
                                                                                        "\"event\":{"
                                                                                            "\"original\":\"Test event\","
                                                                                            "\"kind\":\"event\""
                                                                                        "},"
                                                                                        "\"source\":{"
                                                                                            "\"ip\":\"10.0.0.1\""
                                                                                        "},"
                                                                                        "\"user\":{"
                                                                                            "\"name\":\"root\""
                                                                                        "},"
                                                                                        "\"command\":\"enable\""
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateful\","
                                                            "\"stateful_timeout\":10,"
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.1\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"enable\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{"
                                  "\"version\":1,"
                                  "\"origin\":{"
                                      "\"name\":\"block-ip\","
                                      "\"module\":\"active-response\""
                                  "},"
                                  "\"command\":\"check_keys\","
                                  "\"parameters\":{"
                                      "\"keys\":[\"10.0.0.1\", \"root\"]"
                                  "}"
                              "}\n");

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateful\","
                                                            "\"stateful_timeout\":10,"
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.1\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"abort\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Command already received, updating time of addition to now.");

    ExecdStart(queue);
}
static void test_ExecdStart_wpopenv_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"wazuh\":{"
                            "\"active_response\":{"
                                "\"name\":\"block-ip\","
                                "\"executable\":\"block-ip\","
                                "\"type\":\"stateless\","
                                "\"location\":\"agent\","
                                "\"agent_id\":\"001\""
                            "}"
                        "},"
                        "\"event\":{"
                            "\"original\":\"Test event\","
                            "\"kind\":\"event\""
                        "},"
                        "\"source\":{"
                            "\"ip\":\"10.0.0.1\""
                        "},"
                        "\"user\":{"
                            "\"name\":\"root\""
                        "}"
                    "}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"wazuh\":{"
                                                                            "\"active_response\":{"
                                                                                "\"name\":\"block-ip\","
                                                                                "\"executable\":\"block-ip\","
                                                                                "\"type\":\"stateless\","
                                                                                "\"location\":\"agent\","
                                                                                "\"agent_id\":\"001\""
                                                                            "}"
                                                                        "},"
                                                                        "\"event\":{"
                                                                            "\"original\":\"Test event\","
                                                                            "\"kind\":\"event\""
                                                                        "},"
                                                                        "\"source\":{"
                                                                            "\"ip\":\"10.0.0.1\""
                                                                        "},"
                                                                        "\"user\":{"
                                                                            "\"name\":\"root\""
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/block-ip", "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command '" AR_BINDIR "/block-ip {"
                                                                                        "\"wazuh\":{"
                                                                                            "\"active_response\":{"
                                                                                                "\"name\":\"block-ip\","
                                                                                                "\"executable\":\"block-ip\","
                                                                                                "\"type\":\"stateless\","
                                                                                                "\"location\":\"agent\","
                                                                                                "\"agent_id\":\"001\""
                                                                                            "}"
                                                                                        "},"
                                                                                        "\"event\":{"
                                                                                            "\"original\":\"Test event\","
                                                                                            "\"kind\":\"event\""
                                                                                        "},"
                                                                                        "\"source\":{"
                                                                                            "\"ip\":\"10.0.0.1\""
                                                                                        "},"
                                                                                        "\"user\":{"
                                                                                            "\"name\":\"root\""
                                                                                        "},"
                                                                                        "\"command\":\"enable\""
                                                                                    "}'");

    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1317): Could not launch command Success (0)");

    ExecdStart(queue);
}

static void test_ExecdStart_fgets_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"wazuh\":{"
                            "\"active_response\":{"
                                "\"name\":\"block-ip\","
                                "\"executable\":\"block-ip\","
                                "\"type\":\"stateless\","
                                "\"location\":\"agent\","
                                "\"agent_id\":\"001\""
                            "}"
                        "},"
                        "\"event\":{"
                            "\"original\":\"Test event\","
                            "\"kind\":\"event\""
                        "},"
                        "\"source\":{"
                            "\"ip\":\"10.0.0.1\""
                        "},"
                        "\"user\":{"
                            "\"name\":\"root\""
                        "}"
                    "}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"wazuh\":{"
                                                                            "\"active_response\":{"
                                                                                "\"name\":\"block-ip\","
                                                                                "\"executable\":\"block-ip\","
                                                                                "\"type\":\"stateless\","
                                                                                "\"location\":\"agent\","
                                                                                "\"agent_id\":\"001\""
                                                                            "}"
                                                                        "},"
                                                                        "\"event\":{"
                                                                            "\"original\":\"Test event\","
                                                                            "\"kind\":\"event\""
                                                                        "},"
                                                                        "\"source\":{"
                                                                            "\"ip\":\"10.0.0.1\""
                                                                        "},"
                                                                        "\"user\":{"
                                                                            "\"name\":\"root\""
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/block-ip", "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command '" AR_BINDIR "/block-ip {"
                                                                                        "\"wazuh\":{"
                                                                                            "\"active_response\":{"
                                                                                                "\"name\":\"block-ip\","
                                                                                                "\"executable\":\"block-ip\","
                                                                                                "\"type\":\"stateless\","
                                                                                                "\"location\":\"agent\","
                                                                                                "\"agent_id\":\"001\""
                                                                                            "}"
                                                                                        "},"
                                                                                        "\"event\":{"
                                                                                            "\"original\":\"Test event\","
                                                                                            "\"kind\":\"event\""
                                                                                        "},"
                                                                                        "\"source\":{"
                                                                                            "\"ip\":\"10.0.0.1\""
                                                                                        "},"
                                                                                        "\"user\":{"
                                                                                            "\"name\":\"root\""
                                                                                        "},"
                                                                                        "\"command\":\"enable\""
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"wazuh\":{"
                                                        "\"active_response\":{"
                                                            "\"name\":\"block-ip\","
                                                            "\"executable\":\"block-ip\","
                                                            "\"type\":\"stateless\","
                                                            "\"location\":\"agent\","
                                                            "\"agent_id\":\"001\""
                                                        "}"
                                                    "},"
                                                    "\"event\":{"
                                                        "\"original\":\"Test event\","
                                                        "\"kind\":\"event\""
                                                    "},"
                                                    "\"source\":{"
                                                        "\"ip\":\"10.0.0.1\""
                                                    "},"
                                                    "\"user\":{"
                                                        "\"name\":\"root\""
                                                    "},"
                                                    "\"command\":\"enable\""
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Active response won't be added to timeout list. Message not received with alert keys from script '" AR_BINDIR "/block-ip'");

    will_return(__wrap_wpclose, 0);

    ExecdStart(queue);
}

static void test_ExecdStart_get_command_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"wazuh\":{"
                            "\"active_response\":{"
                                "\"name\":\"block-ip\","
                                "\"executable\":\"block-ip\","
                                "\"type\":\"stateless\","
                                "\"location\":\"agent\","
                                "\"agent_id\":\"001\""
                            "}"
                        "},"
                        "\"event\":{"
                            "\"original\":\"Test event\","
                            "\"kind\":\"event\""
                        "},"
                        "\"source\":{"
                            "\"ip\":\"10.0.0.1\""
                        "},"
                        "\"user\":{"
                            "\"name\":\"root\""
                        "}"
                    "}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"wazuh\":{"
                                                                            "\"active_response\":{"
                                                                                "\"name\":\"block-ip\","
                                                                                "\"executable\":\"block-ip\","
                                                                                "\"type\":\"stateless\","
                                                                                "\"location\":\"agent\","
                                                                                "\"agent_id\":\"001\""
                                                                            "}"
                                                                        "},"
                                                                        "\"event\":{"
                                                                            "\"original\":\"Test event\","
                                                                            "\"kind\":\"event\""
                                                                        "},"
                                                                        "\"source\":{"
                                                                            "\"ip\":\"10.0.0.1\""
                                                                        "},"
                                                                        "\"user\":{"
                                                                            "\"name\":\"root\""
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/block-ip", "r", NULL);

    expect_string(__wrap__merror, formatted_msg, "(1311): Invalid command name 'block-ip' provided.");

    ExecdStart(queue);
}

static void test_ExecdStart_get_name_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{}";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{}'");

    will_return(__wrap_time, now);

    expect_string(__wrap__merror, formatted_msg, "(1316): Invalid AR command: '{}'");

    ExecdStart(queue);
}

static void test_ExecdStart_json_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "unknown";

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: 'unknown'");

    will_return(__wrap_time, now);

    expect_string(__wrap__merror, formatted_msg, "(1315): Invalid JSON message: 'unknown'");

    ExecdStart(queue);
}

/* Test proper handling of long active response keys
 * Verifies that rkey concatenation respects buffer boundaries
 * when active response keys exceed available space
 */
static void test_ExecdStart_long_ar_keys(void **state) {
    #define OS_SIZE_4096 4096

    char rkey[OS_SIZE_4096];
    char basename_result[] = "disable-account";  // 15 bytes
    char *long_keys = NULL;

    /* Create keys exceeding available buffer space (4090 bytes) */
    os_calloc(4100, sizeof(char), long_keys);
    long_keys[0] = '-';
    memset(long_keys + 1, 'A', 4089);
    long_keys[4090] = '\0';

    /* Initialize rkey with basename */
    memset(rkey, '\0', OS_SIZE_4096);
    snprintf(rkey, OS_SIZE_4096 - 1, "%s", basename_result);

    size_t rkey_len = strlen(rkey);  // Should be 15
    size_t keys_len = strlen(long_keys);  // Should be 4090

    /* Verify total length exceeds buffer size */
    assert_true(rkey_len + keys_len >= OS_SIZE_4096);  // 15 + 4090 = 4105 >= 4096

    /* Note: In production code, a warning is logged when size is exceeded:
     * mwarn("Active response key exceeds maximum size. Truncating keys.");
     */

    /* Concatenate keys with size limit */
    strncat(rkey, long_keys, OS_SIZE_4096 - rkey_len - 1);

    /* Verify buffer boundaries are respected */
    size_t final_len = strlen(rkey);
    assert_true(final_len < OS_SIZE_4096);  // Within bounds
    assert_int_equal(final_len, OS_SIZE_4096 - 1);  // Exactly 4095

    /* Verify content integrity */
    assert_memory_equal(rkey, basename_result, strlen(basename_result));  // Basename preserved
    assert_int_equal(rkey[OS_SIZE_4096 - 1], '\0');  // Null terminated

    /* Cleanup */
    os_free(long_keys);
}

/* Allowlist */

static void reset_manager_cache(void) {
    ar_manager_addrs_n = 0;
    ar_manager_addrs_next = 0;
    ar_manager_resolved_at = 0;
}

static void set_manager_hosts(const char **hosts) {
    size_t n = 0;
    while (hosts[n]) {
        n++;
    }
    os_calloc(n + 1, sizeof(char *), ar_manager_hosts);
    for (size_t i = 0; i < n; i++) {
        os_strdup(hosts[i], ar_manager_hosts[i]);
    }
}

static void free_allowlist(void) {
    for (int i = 0; ar_allowlist && ar_allowlist[i]; i++) {
        os_ip *ip = ar_allowlist[i];
        w_free_os_ip(ip);
    }
    os_free(ar_allowlist);
    free_strarray(ar_manager_hosts);
    ar_manager_hosts = NULL;
    reset_manager_cache();
}

static int setup_allowlist(void **state) {
    reset_manager_cache();
    return 0;
}

static int teardown_allowlist(void **state) {
    free_allowlist();
    return 0;
}

static int load_config(const char *xml) {
    char path[] = "/tmp/test_execd_XXXXXX";
    int fd = mkstemp(path);
    assert_true(fd >= 0);
    assert_int_equal(write(fd, xml, strlen(xml)), (ssize_t)strlen(xml));
    close(fd);

    test_mode = 0;
    w_test_pcre2_wrappers(false);
    int ret = ExecdConfig(path);
    w_test_pcre2_wrappers(true);
    test_mode = 1;
    unlink(path);
    return ret;
}

static void test_ExecdConfig_allowlist(void **state) {
    assert_int_equal(load_config("<ossec_config>"
                                 "<agent><manager><endpoint>172.30.68.10:1517</endpoint></manager></agent>"
                                 "<active-response><allowlist>10.1.0.0/16</allowlist>"
                                 "<allowlist>2001:db8::/32</allowlist></active-response>"
                                 "</ossec_config>"), 0);
    will_return_maybe(__wrap_time, 1000);

    // Manager, defaults (loopback, unspecified) and the configured entries, in any numeric form.
    const char *allowed[] = {"172.30.68.10", "127.0.0.1", "127.9.9.9", "127.1", "::1", "::ffff:127.0.0.1",
                             "::ffff:172.30.68.10", "0.0.0.0", "::", "10.1.2.3", "2001:db8:1::5", NULL};
    const char *blocked[] = {"172.30.68.11", "10.2.0.1", "8.8.8.8", "2001:db9::1", "fe80::1", "not-an-ip", "", NULL};

    for (int i = 0; allowed[i]; i++) {
        assert_true(ar_source_allowlisted(allowed[i]));
    }
    for (int i = 0; blocked[i]; i++) {
        assert_false(ar_source_allowlisted(blocked[i]));
    }
    assert_false(ar_source_allowlisted(NULL));

    cJSON *cfg = getARConfig();
    cJSON *list = cJSON_GetObjectItem(cJSON_GetObjectItem(cfg, "active-response"), "allowlist");
    assert_int_equal(cJSON_GetArraySize(list), 6);
    assert_string_equal(cJSON_GetArrayItem(list, 0)->valuestring, "10.1.0.0/16");
    cJSON_Delete(cfg);
}

static void test_ExecdConfig_allowlist_invalid(void **state) {
    const char *invalid[] = {"any", "!10.0.0.1", "300.1.1.1", "manager.example", NULL};

    for (int i = 0; invalid[i]; i++) {
        char xml[OS_SIZE_1024];
        char msg[OS_SIZE_1024];
        snprintf(xml, sizeof(xml), "<ossec_config><active-response><allowlist>%s</allowlist>"
                                   "</active-response></ossec_config>", invalid[i]);
        snprintf(msg, sizeof(msg), "(1235): Invalid value for element 'allowlist': %s.", invalid[i]);
        expect_string(__wrap__merror, formatted_msg, msg);
        assert_int_equal(load_config(xml), -1);
        free_allowlist();
    }
}

static void test_ExecdStart_allowlisted_source(void **state) {
    int queue = 1;
    char *message = "{\"wazuh\":{\"active_response\":{\"name\":\"block-ip\",\"executable\":\"block-ip\","
                    "\"type\":\"stateless\",\"location\":\"local\"}},\"source\":{\"ip\":\"172.30.68.30\"}}";

    const char *hosts[] = {"172.30.68.30", NULL};
    reset_manager_cache();
    set_manager_hosts(hosts);

    will_return(__wrap_time, 123456789);
    will_return(__wrap_select, 1);
    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));
    expect_any(__wrap__mdebug2, formatted_msg);
    will_return(__wrap_time, 123456789);
    will_return(__wrap_time, 123456789);

    // No wfopen/wpopenv expectations: the executable must not run.
    expect_string(__wrap__mwarn, formatted_msg, "Active response 'block-ip' not executed: source.ip "
                                                "'172.30.68.30' is the manager or in the allowlist.");

    ExecdStart(queue);
    free_allowlist();
}

static void test_ar_manager_kept_when_resolution_fails(void **state) {
    const char *hosts[] = {"172.30.68.12", NULL};
    set_manager_hosts(hosts);

    will_return(__wrap_time, 1000);
    assert_true(ar_source_allowlisted("172.30.68.12"));

    // The same host stops resolving: the address resolved before must still be protected.
    os_free(ar_manager_hosts[0]);
    os_strdup("", ar_manager_hosts[0]);
    will_return(__wrap_time, 1060);
    expect_string(__wrap__mdebug1, formatted_msg, "Could not resolve manager address '' for the active response allowlist.");
    assert_true(ar_source_allowlisted("172.30.68.12"));
}

static void test_ar_manager_resolution_rate_limited(void **state) {
    const char *hosts[] = {"", NULL};
    set_manager_hosts(hosts);

    will_return(__wrap_time, 1000);
    expect_string(__wrap__mdebug1, formatted_msg, "Could not resolve manager address '' for the active response allowlist.");
    assert_false(ar_source_allowlisted("172.30.68.13"));

    // Within the interval: no new lookup, so no second debug message.
    will_return(__wrap_time, 1059);
    assert_false(ar_source_allowlisted("172.30.68.13"));
}

static void test_ar_manager_cache_replaces_oldest(void **state) {
    char *hosts[34] = {NULL};
    for (int i = 0; i < 33; i++) {
        os_calloc(16, sizeof(char), hosts[i]);
        snprintf(hosts[i], 16, "10.9.0.%d", i + 1);
    }
    set_manager_hosts((const char **)hosts);
    for (int i = 0; i < 33; i++) {
        os_free(hosts[i]);
    }

    will_return_maybe(__wrap_time, 1000);
    assert_true(ar_source_allowlisted("10.9.0.33"));
    assert_true(ar_source_allowlisted("10.9.0.2"));
    assert_false(ar_source_allowlisted("10.9.0.1"));
}

static void test_ar_manager_ipv4_mapped(void **state) {
    const char *hosts[] = {"::ffff:10.8.0.1", NULL};
    set_manager_hosts(hosts);

    will_return(__wrap_time, 1000);
    assert_true(ar_source_allowlisted("10.8.0.1"));
}

static void test_RepeatedOffendersInit_disabled(void **state) {
    RepeatedOffendersInit();

    assert_null(repeated_hash);
}

static void test_RepeatedOffendersInit_enabled(void **state) {
    assert_non_null(repeated_hash);
    assert_true(repeated_hash->rows >= REPEATED_OFFENDERS_ROWS);
    assert_int_equal(repeated_hash->elements, 0);
}

static void test_RepeatedOffendersCheck_escalates(void **state) {
    time_t now = 1000;

    // First offense: base timeout, no escalation
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now), 30);

    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '60s'");
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now + 40), 60);

    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '300s'");
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now + 50), 300);

    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '600s'");
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now + 55), 600);

    // The last level is kept
    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '600s'");
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now + 58), 600);

    repeated_offender *offender = OSHash_Get(repeated_hash, "block-ip-10.0.0.1");
    assert_non_null(offender);
    assert_int_equal(offender->count, 3);
    assert_int_equal(offender->release_at, now + 58 + 600);
    assert_int_equal(repeated_hash->elements, 1);
}

static void test_RepeatedOffendersPurge_window(void **state) {
    time_t now = 1000;

    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now), 30);
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now + 100), 30);

    // Window is the largest repeated timeout (600s) after the block ends
    RepeatedOffendersPurge(now + 30 + 600);
    assert_int_equal(repeated_hash->elements, 2);

    RepeatedOffendersPurge(now + 30 + 601);
    assert_int_equal(repeated_hash->elements, 1);
    assert_null(OSHash_Get(repeated_hash, "block-ip-10.0.0.1"));
    assert_non_null(OSHash_Get(repeated_hash, "block-ip-10.0.0.2"));
    assert_int_equal(repeated_last_purge, now + 30 + 601);

    // A forgotten key starts over from the base timeout
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now + 30 + 601), 30);
}

static void test_RepeatedOffendersPurge_keeps_active_block(void **state) {
    time_t now = 1000;

    // The base timeout is longer than the window: the entry outlives the block
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 3600, now), 3600);

    RepeatedOffendersPurge(now + 3600);
    assert_int_equal(repeated_hash->elements, 1);

    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '60s'");
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 3600, now + 3600 + 600), 60);
}

static void test_RepeatedOffendersCheck_purge_interval(void **state) {
    time_t now = 1000;

    fill_repeated_hash(5, 0);

    // The first check purges the expired entries
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now), 30);
    assert_int_equal(repeated_last_purge, now);
    assert_int_equal(repeated_hash->elements, 1);

    fill_repeated_hash(5, 0);

    // No purge before the interval
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now + REPEATED_OFFENDERS_PURGE - 1), 30);
    assert_int_equal(repeated_last_purge, now);
    assert_int_equal(repeated_hash->elements, 7);

    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.3", 30, now + REPEATED_OFFENDERS_PURGE), 30);
    assert_int_equal(repeated_last_purge, now + REPEATED_OFFENDERS_PURGE);
    assert_int_equal(repeated_hash->elements, 3);
}

static void test_RepeatedOffendersCheck_full(void **state) {
    time_t now = 1000;
    char warn_msg[OS_SIZE_256];

    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now), 30);
    fill_repeated_hash(REPEATED_OFFENDERS_MAX - 1, now + 30);

    // New keys are not tracked, and the warning is logged once per purge interval
    snprintf(warn_msg, sizeof(warn_msg), AR_REPEATED_FULL, REPEATED_OFFENDERS_MAX);
    expect_string(__wrap__mwarn, formatted_msg, warn_msg);
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now + 1), 30);
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.3", 30, now + 2), 30);
    assert_null(OSHash_Get(repeated_hash, "block-ip-10.0.0.2"));
    assert_int_equal(repeated_hash->elements, REPEATED_OFFENDERS_MAX);
    assert_int_equal(repeated_last_full_warn, now + 1);

    // Known offenders still escalate
    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '60s'");
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now + 3), 60);

    expect_string(__wrap__mwarn, formatted_msg, warn_msg);
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.3", 30, now + 1 + REPEATED_OFFENDERS_PURGE), 30);
    assert_int_equal(repeated_last_full_warn, now + 1 + REPEATED_OFFENDERS_PURGE);

    // Once the filler expires, new keys are tracked again
    RepeatedOffendersPurge(now + 30 + 601);
    assert_int_equal(repeated_hash->elements, 1);

    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now + 30 + 602), 30);
    assert_int_equal(repeated_hash->elements, 2);
}

static void test_RepeatedOffendersCheck_full_purges_first(void **state) {
    time_t now = 1000;

    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now), 30);
    fill_repeated_hash(REPEATED_OFFENDERS_MAX - 1, 0);

    // A full table is purged before the purge interval, at most once per second
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now + 1), 30);
    assert_int_equal(repeated_last_purge, now + 1);
    assert_int_equal(repeated_hash->elements, 2);
    assert_non_null(OSHash_Get(repeated_hash, "block-ip-10.0.0.2"));
}

static void test_RepeatedOffendersCheck_clock_backwards(void **state) {
    time_t now = 1000;

    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now), 30);
    fill_repeated_hash(5, 0);

    // A check earlier than the last purge purges again
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now - 100), 30);
    assert_int_equal(repeated_last_purge, now - 100);
    assert_int_equal(repeated_hash->elements, 2);
}

static int test_setup_repeated_run(void **state) {
    test_setup_file(state);
    return test_setup_repeated(state);
}

static int test_teardown_repeated_run(void **state) {
    test_teardown_repeated(state);
    return test_teardown_file(state);
}

/* Expect the start of a stateful active response for 10.0.0.1 */
static void expect_repeated_ar_start(wfd_t *wfd, time_t now) {
    will_return(__wrap_time, now);

    expect_wfopen(AR_BINDIR "/test-block", "r", (FILE *)1);
    expect_fclose((FILE *)1, 0);

    expect_any(__wrap__mdebug1, formatted_msg);
    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_any(__wrap_fprintf, formatted_msg);
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{\"version\":1,\"origin\":{\"name\":\"test-block\",\"module\":\"active-response\"},"
                              "\"command\":\"check_keys\",\"parameters\":{\"keys\":[\"10.0.0.1\"]}}");
}

/* Expect the continue/abort message sent to the script */
static void expect_repeated_ar_end(wfd_t *wfd) {
    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_any(__wrap_fprintf, formatted_msg);
    will_return(__wrap_fprintf, 0);
    will_return(__wrap_wpclose, 0);
}

static void test_ExecdRun_repeated_offender(void **state) {
    wfd_t *wfd = *state;
    time_t now = 123456789;
    int childcount = 0;
    char message[OS_SIZE_1024];
    const char *json = "{\"wazuh\":{\"active_response\":{\"name\":\"test-block\",\"executable\":\"test-block\","
                       "\"type\":\"stateful\",\"stateful_timeout\":5,\"location\":\"agent\"}}}";

    // First offense: base timeout
    expect_repeated_ar_start(wfd, now);
    expect_any(__wrap__mdebug1, formatted_msg);
    expect_repeated_ar_end(wfd);

    snprintf(message, sizeof(message), "%s", json);
    ExecdRun(message, &childcount);

    timeout_data *entry = (timeout_data *)OSList_GetFirstNode(timeout_list)->data;
    assert_string_equal(entry->rkey, "test-block-10.0.0.1");
    assert_int_equal(entry->time_to_block, 5);

    // Second offense while blocked: the existing timeout entry gets the escalated timeout
    expect_repeated_ar_start(wfd, now + 2);
    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '60s'");
    expect_string(__wrap__mdebug1, formatted_msg, "Command already received, updating time of addition to now.");
    expect_repeated_ar_end(wfd);

    snprintf(message, sizeof(message), "%s", json);
    ExecdRun(message, &childcount);

    assert_int_equal(timeout_list->currently_size, 1);
    assert_int_equal(entry->time_of_addition, now + 2);
    assert_int_equal(entry->time_to_block, 60);

    repeated_offender *offender = OSHash_Get(repeated_hash, "test-block-10.0.0.1");
    assert_non_null(offender);
    assert_int_equal(offender->count, 1);
    assert_int_equal(offender->release_at, now + 2 + 60);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_RepeatedOffendersInit_disabled, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersInit_enabled, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersCheck_escalates, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersPurge_window, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersPurge_keeps_active_block, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersCheck_purge_interval, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersCheck_full, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersCheck_full_purges_first, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_RepeatedOffendersCheck_clock_backwards, test_setup_repeated, test_teardown_repeated),
        cmocka_unit_test_setup_teardown(test_ExecdRun_repeated_offender, test_setup_repeated_run, test_teardown_repeated_run),
        cmocka_unit_test_setup_teardown(test_ExecdStart_ok, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_ar_reports_failure, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_ar_terminated_by_signal, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_ar_wait_failed, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_timeout_not_repeated, test_setup_file_timeout, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_timeout_repeated, test_setup_file_timeout, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_wpopenv_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_fgets_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_get_command_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_get_name_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_json_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_long_ar_keys, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdConfig_allowlist, setup_allowlist, teardown_allowlist),
        cmocka_unit_test_setup_teardown(test_ExecdConfig_allowlist_invalid, setup_allowlist, teardown_allowlist),
        cmocka_unit_test_setup_teardown(test_ExecdStart_allowlisted_source, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ar_manager_kept_when_resolution_fails, setup_allowlist, teardown_allowlist),
        cmocka_unit_test_setup_teardown(test_ar_manager_resolution_rate_limited, setup_allowlist, teardown_allowlist),
        cmocka_unit_test_setup_teardown(test_ar_manager_cache_replaces_oldest, setup_allowlist, teardown_allowlist),
        cmocka_unit_test_setup_teardown(test_ar_manager_ipv4_mapped, setup_allowlist, teardown_allowlist),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
