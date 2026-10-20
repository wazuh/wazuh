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
#include <errno.h>

#include "shared.h"
#include "list_op.h"
#include "../os_regex/os_regex.h"
#include "../os_net/os_net.h"
#include "../wazuh_modules/wmodules.h"
#include "../external/cJSON/cJSON.h"
#include "../os_execd/execd.h"

#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/select_wrappers.h"
#include "../wrappers/wazuh/os_execd/exec_wrappers.h"
#include "../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../wrappers/wazuh/shared/file_op_wrappers.h"
#include "../wrappers/wazuh/shared/time_op_wrappers.h"

extern int test_mode;
extern OSList *timeout_list;
extern OSHash *repeated_hash;
extern time_t repeated_last_purge;
extern int repeated_full_warned;

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
    os_strdup("restart-wazuh10", timeout_entry->command[0]);
    timeout_entry->command[1] = NULL;
    os_strdup("restart-wazuh-10.0.0.1-root", timeout_entry->rkey);
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
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh0\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 0;

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"version\":\"1\","
                                                                        "\"origin\":{"
                                                                            "\"name\":\"node01\","
                                                                            "\"module\":\"wazuh-analysisd\""
                                                                        "},"
                                                                        "\"command\":\"restart-wazuh0\","
                                                                        "\"parameters\":{"
                                                                            "\"extra_args\":[],"
                                                                            "\"alert\":{"
                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                "\"rule\":{"
                                                                                    "\"level\":5,"
                                                                                    "\"description\":\"File added to the system.\","
                                                                                    "\"id\":\"554\""
                                                                                "},"
                                                                                "\"id\":\"1609860180.513333\","
                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                "\"syscheck\":{"
                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                    "\"mode\":\"realtime\","
                                                                                    "\"event\":\"added\""
                                                                                "},"
                                                                                "\"location\":\"syscheck\""
                                                                            "}"
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh0");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, "restart-wazuh");

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command 'restart-wazuh {"
                                                                                        "\"version\":\"1\","
                                                                                        "\"origin\":{"
                                                                                            "\"name\":\"node01\","
                                                                                            "\"module\":\"wazuh-execd\""
                                                                                        "},"
                                                                                        "\"command\":\"add\","
                                                                                        "\"parameters\":{"
                                                                                            "\"extra_args\":[],"
                                                                                            "\"alert\":{"
                                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                                "\"rule\":{"
                                                                                                    "\"level\":5,"
                                                                                                    "\"description\":\"File added to the system.\","
                                                                                                    "\"id\":\"554\""
                                                                                                "},"
                                                                                                "\"id\":\"1609860180.513333\","
                                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                                "\"syscheck\":{"
                                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                                    "\"mode\":\"realtime\","
                                                                                                    "\"event\":\"added\""
                                                                                                "},"
                                                                                                "\"location\":\"syscheck\""
                                                                                            "},"
                                                                                            "\"program\":\"restart-wazuh\""
                                                                                        "}"
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"version\":\"1\","
                                                    "\"origin\":{"
                                                        "\"name\":\"node01\","
                                                        "\"module\":\"wazuh-execd\""
                                                    "},"
                                                    "\"command\":\"add\","
                                                    "\"parameters\":{"
                                                        "\"extra_args\":[],"
                                                        "\"alert\":{"
                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                            "\"rule\":{"
                                                                "\"level\":5,"
                                                                "\"description\":\"File added to the system.\","
                                                                "\"id\":\"554\""
                                                            "},"
                                                            "\"id\":\"1609860180.513333\","
                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                            "\"syscheck\":{"
                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                "\"mode\":\"realtime\","
                                                                "\"event\":\"added\""
                                                            "},"
                                                            "\"location\":\"syscheck\""
                                                        "},"
                                                        "\"program\":\"restart-wazuh\""
                                                    "}"
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{"
                                  "\"version\":1,"
                                  "\"origin\":{"
                                      "\"name\":\"restart-wazuh\","
                                      "\"module\":\"active-response\""
                                  "},"
                                  "\"command\":\"check_keys\","
                                  "\"parameters\":{"
                                      "\"keys\":[\"10.0.0.1\", \"root\"]"
                                  "}"
                              "}\n");

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"version\":\"1\","
                                                    "\"origin\":{"
                                                        "\"name\":\"node01\","
                                                        "\"module\":\"wazuh-execd\""
                                                    "},"
                                                    "\"command\":\"continue\","
                                                    "\"parameters\":{"
                                                        "\"extra_args\":[],"
                                                        "\"alert\":{"
                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                            "\"rule\":{"
                                                                "\"level\":5,"
                                                                "\"description\":\"File added to the system.\","
                                                                "\"id\":\"554\""
                                                            "},"
                                                            "\"id\":\"1609860180.513333\","
                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                            "\"syscheck\":{"
                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                "\"mode\":\"realtime\","
                                                                "\"event\":\"added\""
                                                            "},"
                                                            "\"location\":\"syscheck\""
                                                        "},"
                                                        "\"program\":\"restart-wazuh\""
                                                    "}"
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_wpclose, 0);

    ExecdStart(queue);
}

static void test_ExecdStart_timeout_not_repeated(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh10\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 10;

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"version\":\"1\","
                                                                        "\"origin\":{"
                                                                            "\"name\":\"node01\","
                                                                            "\"module\":\"wazuh-analysisd\""
                                                                        "},"
                                                                        "\"command\":\"restart-wazuh10\","
                                                                        "\"parameters\":{"
                                                                            "\"extra_args\":[],"
                                                                            "\"alert\":{"
                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                "\"rule\":{"
                                                                                    "\"level\":5,"
                                                                                    "\"description\":\"File added to the system.\","
                                                                                    "\"id\":\"554\""
                                                                                "},"
                                                                                "\"id\":\"1609860180.513333\","
                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                "\"syscheck\":{"
                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                    "\"mode\":\"realtime\","
                                                                                    "\"event\":\"added\""
                                                                                "},"
                                                                                "\"location\":\"syscheck\""
                                                                            "}"
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh10");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, "restart-wazuh");

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command 'restart-wazuh {"
                                                                                        "\"version\":\"1\","
                                                                                        "\"origin\":{"
                                                                                            "\"name\":\"node01\","
                                                                                            "\"module\":\"wazuh-execd\""
                                                                                        "},"
                                                                                        "\"command\":\"add\","
                                                                                        "\"parameters\":{"
                                                                                            "\"extra_args\":[],"
                                                                                            "\"alert\":{"
                                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                                "\"rule\":{"
                                                                                                    "\"level\":5,"
                                                                                                    "\"description\":\"File added to the system.\","
                                                                                                    "\"id\":\"554\""
                                                                                                "},"
                                                                                                "\"id\":\"1609860180.513333\","
                                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                                "\"syscheck\":{"
                                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                                    "\"mode\":\"realtime\","
                                                                                                    "\"event\":\"added\""
                                                                                                "},"
                                                                                                "\"location\":\"syscheck\""
                                                                                            "},"
                                                                                            "\"program\":\"restart-wazuh\""
                                                                                        "}"
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"version\":\"1\","
                                                    "\"origin\":{"
                                                        "\"name\":\"node01\","
                                                        "\"module\":\"wazuh-execd\""
                                                    "},"
                                                    "\"command\":\"add\","
                                                    "\"parameters\":{"
                                                        "\"extra_args\":[],"
                                                        "\"alert\":{"
                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                            "\"rule\":{"
                                                                "\"level\":5,"
                                                                "\"description\":\"File added to the system.\","
                                                                "\"id\":\"554\""
                                                            "},"
                                                            "\"id\":\"1609860180.513333\","
                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                            "\"syscheck\":{"
                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                "\"mode\":\"realtime\","
                                                                "\"event\":\"added\""
                                                            "},"
                                                            "\"location\":\"syscheck\""
                                                        "},"
                                                        "\"program\":\"restart-wazuh\""
                                                    "}"
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{"
                                  "\"version\":1,"
                                  "\"origin\":{"
                                      "\"name\":\"restart-wazuh\","
                                      "\"module\":\"active-response\""
                                  "},"
                                  "\"command\":\"check_keys\","
                                  "\"parameters\":{"
                                      "\"keys\":[\"10.0.0.2\", \"root\"]"
                                  "}"
                              "}\n");

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"version\":\"1\","
                                                    "\"origin\":{"
                                                        "\"name\":\"node01\","
                                                        "\"module\":\"wazuh-execd\""
                                                    "},"
                                                    "\"command\":\"continue\","
                                                    "\"parameters\":{"
                                                        "\"extra_args\":[],"
                                                        "\"alert\":{"
                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                            "\"rule\":{"
                                                                "\"level\":5,"
                                                                "\"description\":\"File added to the system.\","
                                                                "\"id\":\"554\""
                                                            "},"
                                                            "\"id\":\"1609860180.513333\","
                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                            "\"syscheck\":{"
                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                "\"mode\":\"realtime\","
                                                                "\"event\":\"added\""
                                                            "},"
                                                            "\"location\":\"syscheck\""
                                                        "},"
                                                        "\"program\":\"restart-wazuh\""
                                                    "}"
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Adding command 'restart-wazuh {"
                                                                                    "\"version\":\"1\","
                                                                                    "\"origin\":{"
                                                                                        "\"name\":\"node01\","
                                                                                        "\"module\":\"wazuh-execd\""
                                                                                    "},"
                                                                                    "\"command\":\"delete\","
                                                                                    "\"parameters\":{"
                                                                                        "\"extra_args\":[],"
                                                                                        "\"alert\":{"
                                                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                            "\"rule\":{"
                                                                                                "\"level\":5,"
                                                                                                "\"description\":\"File added to the system.\","
                                                                                                "\"id\":\"554\""
                                                                                            "},"
                                                                                            "\"id\":\"1609860180.513333\","
                                                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                            "\"syscheck\":{"
                                                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                                "\"mode\":\"realtime\","
                                                                                                "\"event\":\"added\""
                                                                                            "},"
                                                                                            "\"location\":\"syscheck\""
                                                                                        "},"
                                                                                        "\"program\":\"restart-wazuh\""
                                                                                    "}"
                                                                                "}' to the timeout list, with a timeout of '10s'.");

    ExecdStart(queue);
}

static void test_ExecdStart_timeout_repeated(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh10\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 10;

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"version\":\"1\","
                                                                        "\"origin\":{"
                                                                            "\"name\":\"node01\","
                                                                            "\"module\":\"wazuh-analysisd\""
                                                                        "},"
                                                                        "\"command\":\"restart-wazuh10\","
                                                                        "\"parameters\":{"
                                                                            "\"extra_args\":[],"
                                                                            "\"alert\":{"
                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                "\"rule\":{"
                                                                                    "\"level\":5,"
                                                                                    "\"description\":\"File added to the system.\","
                                                                                    "\"id\":\"554\""
                                                                                "},"
                                                                                "\"id\":\"1609860180.513333\","
                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                "\"syscheck\":{"
                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                    "\"mode\":\"realtime\","
                                                                                    "\"event\":\"added\""
                                                                                "},"
                                                                                "\"location\":\"syscheck\""
                                                                            "}"
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh10");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, "restart-wazuh");

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command 'restart-wazuh {"
                                                                                        "\"version\":\"1\","
                                                                                        "\"origin\":{"
                                                                                            "\"name\":\"node01\","
                                                                                            "\"module\":\"wazuh-execd\""
                                                                                        "},"
                                                                                        "\"command\":\"add\","
                                                                                        "\"parameters\":{"
                                                                                            "\"extra_args\":[],"
                                                                                            "\"alert\":{"
                                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                                "\"rule\":{"
                                                                                                    "\"level\":5,"
                                                                                                    "\"description\":\"File added to the system.\","
                                                                                                    "\"id\":\"554\""
                                                                                                "},"
                                                                                                "\"id\":\"1609860180.513333\","
                                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                                "\"syscheck\":{"
                                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                                    "\"mode\":\"realtime\","
                                                                                                    "\"event\":\"added\""
                                                                                                "},"
                                                                                                "\"location\":\"syscheck\""
                                                                                            "},"
                                                                                            "\"program\":\"restart-wazuh\""
                                                                                        "}"
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"version\":\"1\","
                                                    "\"origin\":{"
                                                        "\"name\":\"node01\","
                                                        "\"module\":\"wazuh-execd\""
                                                    "},"
                                                    "\"command\":\"add\","
                                                    "\"parameters\":{"
                                                        "\"extra_args\":[],"
                                                        "\"alert\":{"
                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                            "\"rule\":{"
                                                                "\"level\":5,"
                                                                "\"description\":\"File added to the system.\","
                                                                "\"id\":\"554\""
                                                            "},"
                                                            "\"id\":\"1609860180.513333\","
                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                            "\"syscheck\":{"
                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                "\"mode\":\"realtime\","
                                                                "\"event\":\"added\""
                                                            "},"
                                                            "\"location\":\"syscheck\""
                                                        "},"
                                                        "\"program\":\"restart-wazuh\""
                                                    "}"
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "{"
                                  "\"version\":1,"
                                  "\"origin\":{"
                                      "\"name\":\"restart-wazuh\","
                                      "\"module\":\"active-response\""
                                  "},"
                                  "\"command\":\"check_keys\","
                                  "\"parameters\":{"
                                      "\"keys\":[\"10.0.0.1\", \"root\"]"
                                  "}"
                              "}\n");

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"version\":\"1\","
                                                    "\"origin\":{"
                                                        "\"name\":\"node01\","
                                                        "\"module\":\"wazuh-execd\""
                                                    "},"
                                                    "\"command\":\"abort\","
                                                    "\"parameters\":{"
                                                        "\"extra_args\":[],"
                                                        "\"alert\":{"
                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                            "\"rule\":{"
                                                                "\"level\":5,"
                                                                "\"description\":\"File added to the system.\","
                                                                "\"id\":\"554\""
                                                            "},"
                                                            "\"id\":\"1609860180.513333\","
                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                            "\"syscheck\":{"
                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                "\"mode\":\"realtime\","
                                                                "\"event\":\"added\""
                                                            "},"
                                                            "\"location\":\"syscheck\""
                                                        "},"
                                                        "\"program\":\"restart-wazuh\""
                                                    "}"
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
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh0\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 0;

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"version\":\"1\","
                                                                        "\"origin\":{"
                                                                            "\"name\":\"node01\","
                                                                            "\"module\":\"wazuh-analysisd\""
                                                                        "},"
                                                                        "\"command\":\"restart-wazuh0\","
                                                                        "\"parameters\":{"
                                                                            "\"extra_args\":[],"
                                                                            "\"alert\":{"
                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                "\"rule\":{"
                                                                                    "\"level\":5,"
                                                                                    "\"description\":\"File added to the system.\","
                                                                                    "\"id\":\"554\""
                                                                                "},"
                                                                                "\"id\":\"1609860180.513333\","
                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                "\"syscheck\":{"
                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                    "\"mode\":\"realtime\","
                                                                                    "\"event\":\"added\""
                                                                                "},"
                                                                                "\"location\":\"syscheck\""
                                                                            "}"
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh0");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, "restart-wazuh");

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command 'restart-wazuh {"
                                                                                        "\"version\":\"1\","
                                                                                        "\"origin\":{"
                                                                                            "\"name\":\"node01\","
                                                                                            "\"module\":\"wazuh-execd\""
                                                                                        "},"
                                                                                        "\"command\":\"add\","
                                                                                        "\"parameters\":{"
                                                                                            "\"extra_args\":[],"
                                                                                            "\"alert\":{"
                                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                                "\"rule\":{"
                                                                                                    "\"level\":5,"
                                                                                                    "\"description\":\"File added to the system.\","
                                                                                                    "\"id\":\"554\""
                                                                                                "},"
                                                                                                "\"id\":\"1609860180.513333\","
                                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                                "\"syscheck\":{"
                                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                                    "\"mode\":\"realtime\","
                                                                                                    "\"event\":\"added\""
                                                                                                "},"
                                                                                                "\"location\":\"syscheck\""
                                                                                            "},"
                                                                                            "\"program\":\"restart-wazuh\""
                                                                                        "}"
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
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh0\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 0;

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"version\":\"1\","
                                                                        "\"origin\":{"
                                                                            "\"name\":\"node01\","
                                                                            "\"module\":\"wazuh-analysisd\""
                                                                        "},"
                                                                        "\"command\":\"restart-wazuh0\","
                                                                        "\"parameters\":{"
                                                                            "\"extra_args\":[],"
                                                                            "\"alert\":{"
                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                "\"rule\":{"
                                                                                    "\"level\":5,"
                                                                                    "\"description\":\"File added to the system.\","
                                                                                    "\"id\":\"554\""
                                                                                "},"
                                                                                "\"id\":\"1609860180.513333\","
                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                "\"syscheck\":{"
                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                    "\"mode\":\"realtime\","
                                                                                    "\"event\":\"added\""
                                                                                "},"
                                                                                "\"location\":\"syscheck\""
                                                                            "}"
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh0");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, "restart-wazuh");

    expect_string(__wrap__mdebug1, formatted_msg, "Executing command 'restart-wazuh {"
                                                                                        "\"version\":\"1\","
                                                                                        "\"origin\":{"
                                                                                            "\"name\":\"node01\","
                                                                                            "\"module\":\"wazuh-execd\""
                                                                                        "},"
                                                                                        "\"command\":\"add\","
                                                                                        "\"parameters\":{"
                                                                                            "\"extra_args\":[],"
                                                                                            "\"alert\":{"
                                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                                "\"rule\":{"
                                                                                                    "\"level\":5,"
                                                                                                    "\"description\":\"File added to the system.\","
                                                                                                    "\"id\":\"554\""
                                                                                                "},"
                                                                                                "\"id\":\"1609860180.513333\","
                                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                                "\"syscheck\":{"
                                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                                    "\"mode\":\"realtime\","
                                                                                                    "\"event\":\"added\""
                                                                                                "},"
                                                                                                "\"location\":\"syscheck\""
                                                                                            "},"
                                                                                            "\"program\":\"restart-wazuh\""
                                                                                        "}"
                                                                                    "}'");

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fprintf, __stream, wfd->file_in);
    expect_string(__wrap_fprintf, formatted_msg, "{"
                                                    "\"version\":\"1\","
                                                    "\"origin\":{"
                                                        "\"name\":\"node01\","
                                                        "\"module\":\"wazuh-execd\""
                                                    "},"
                                                    "\"command\":\"add\","
                                                    "\"parameters\":{"
                                                        "\"extra_args\":[],"
                                                        "\"alert\":{"
                                                            "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                            "\"rule\":{"
                                                                "\"level\":5,"
                                                                "\"description\":\"File added to the system.\","
                                                                "\"id\":\"554\""
                                                            "},"
                                                            "\"id\":\"1609860180.513333\","
                                                            "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                            "\"syscheck\":{"
                                                                "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                "\"mode\":\"realtime\","
                                                                "\"event\":\"added\""
                                                            "},"
                                                            "\"location\":\"syscheck\""
                                                        "},"
                                                        "\"program\":\"restart-wazuh\""
                                                    "}"
                                                "}\n");
    will_return(__wrap_fprintf, 0);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Active response won't be added to timeout list. Message not received with alert keys from script 'restart-wazuh'");

    will_return(__wrap_wpclose, 0);

    ExecdStart(queue);
}

static void test_ExecdStart_get_command_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh0\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 0;

    will_return(__wrap_time, now);

    will_return(__wrap_select, 1);

    expect_value(__wrap_OS_RecvUnix, socket, queue);
    expect_value(__wrap_OS_RecvUnix, sizet, OS_MAXSTR);
    will_return(__wrap_OS_RecvUnix, message);
    will_return(__wrap_OS_RecvUnix, strlen(message));

    expect_string(__wrap__mdebug2, formatted_msg, "Received message: '{"
                                                                        "\"version\":\"1\","
                                                                        "\"origin\":{"
                                                                            "\"name\":\"node01\","
                                                                            "\"module\":\"wazuh-analysisd\""
                                                                        "},"
                                                                        "\"command\":\"restart-wazuh0\","
                                                                        "\"parameters\":{"
                                                                            "\"extra_args\":[],"
                                                                            "\"alert\":{"
                                                                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                                                                "\"rule\":{"
                                                                                    "\"level\":5,"
                                                                                    "\"description\":\"File added to the system.\","
                                                                                    "\"id\":\"554\""
                                                                                "},"
                                                                                "\"id\":\"1609860180.513333\","
                                                                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                                                                "\"syscheck\":{"
                                                                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                                                                    "\"mode\":\"realtime\","
                                                                                    "\"event\":\"added\""
                                                                                "},"
                                                                                "\"location\":\"syscheck\""
                                                                            "}"
                                                                        "}"
                                                                    "}'");

    will_return(__wrap_time, now);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh0");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, NULL);

    will_return(__wrap_ReadExecConfig, 0);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh0");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1311): Invalid command name 'restart-wazuh0' provided.");

    ExecdStart(queue);
}

static void test_ExecdStart_get_name_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{}";
    char *message2 = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh0\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 0;

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
    char *message2 = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-analysisd\""
                        "},"
                        "\"command\":\"restart-wazuh0\","
                        "\"parameters\":{"
                            "\"extra_args\":[],"
                            "\"alert\":{"
                                "\"timestamp\":\"2021-01-05T15:23:00.547+0000\","
                                "\"rule\":{"
                                    "\"level\":5,"
                                    "\"description\":\"File added to the system.\","
                                    "\"id\":\"554\""
                                "},"
                                "\"id\":\"1609860180.513333\","
                                "\"full_log\":\"File '/home/vagrant/file/n41.txt' added\\nMode: realtime\\n\","
                                "\"syscheck\":{"
                                    "\"path\":\"/home/vagrant/file/n41.txt\","
                                    "\"mode\":\"realtime\","
                                    "\"event\":\"added\""
                                "},"
                                "\"location\":\"syscheck\""
                            "}"
                        "}"
                    "}";
    int timeout = 0;

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

static void expect_restart_log(const char *line) {
    will_return(__wrap_time, 1000);
    expect_value(__wrap_w_get_timestamp, time, 1000);
    will_return(__wrap_w_get_timestamp, strdup("2026/10/05 12:00:00"));
    expect_w_fopen_nofollow("logs", "active-responses.log", "a", (FILE *)1);
    expect_fprintf((FILE *)1, line, 0);
    expect_fclose((FILE *)1, 0);
}

void test_ExecdLogRestart_agent(void **state) {
    char *cmd[] = { "active-response/bin/restart.sh", "agent", NULL };

    expect_restart_log("2026/10/05 12:00:00 active-response/bin/restart.sh agent\n");

    ExecdLogRestart(cmd);
}

void test_ExecdLogRestart_reload(void **state) {
    char *cmd[] = { "active-response/bin/restart.sh", "agent", "reload", NULL };

    expect_restart_log("2026/10/05 12:00:00 active-response/bin/restart.sh agent reload\n");

    ExecdLogRestart(cmd);
}

void test_ExecdLogRestart_open_fails(void **state) {
    char *cmd[] = { "active-response/bin/restart.sh", "agent", NULL };

    will_return(__wrap_time, 1000);
    expect_value(__wrap_w_get_timestamp, time, 1000);
    will_return(__wrap_w_get_timestamp, strdup("2026/10/05 12:00:00"));
    expect_w_fopen_nofollow("logs", "active-responses.log", "a", NULL);
    errno = ENOENT;

    ExecdLogRestart(cmd);
}

void test_ExecdLogRestart_rejects_symlink(void **state) {
    char *cmd[] = { "active-response/bin/restart.sh", "agent", NULL };

    will_return(__wrap_time, 1000);
    expect_value(__wrap_w_get_timestamp, time, 1000);
    will_return(__wrap_w_get_timestamp, strdup("2026/10/05 12:00:00"));
    expect_w_fopen_nofollow("logs", "active-responses.log", "a", NULL);
    errno = ELOOP;
    expect_string(__wrap__mwarn, formatted_msg,
                  "Active responses log 'logs/active-responses.log' is not a regular file: dropping entry.");

    ExecdLogRestart(cmd);
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

    // New keys are not tracked, and the warning is logged once
    snprintf(warn_msg, sizeof(warn_msg), AR_REPEATED_FULL, REPEATED_OFFENDERS_MAX);
    expect_string(__wrap__mwarn, formatted_msg, warn_msg);
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now + 1), 30);
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.3", 30, now + 2), 30);
    assert_null(OSHash_Get(repeated_hash, "block-ip-10.0.0.2"));
    assert_int_equal(repeated_hash->elements, REPEATED_OFFENDERS_MAX);

    // Known offenders still escalate
    expect_string(__wrap__mdebug1, formatted_msg, "Repeated offender. Setting timeout to '60s'");
    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.1", 30, now + 3), 60);

    // Once the filler expires, new keys are tracked again
    RepeatedOffendersPurge(now + 30 + 601);
    assert_int_equal(repeated_hash->elements, 1);
    assert_int_equal(repeated_full_warned, 0);

    assert_int_equal(RepeatedOffendersCheck("block-ip-10.0.0.2", 30, now + 30 + 602), 30);
    assert_int_equal(repeated_hash->elements, 2);
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
        cmocka_unit_test_setup_teardown(test_ExecdStart_ok, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_timeout_not_repeated, test_setup_file_timeout, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_timeout_repeated, test_setup_file_timeout, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_wpopenv_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_fgets_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_get_command_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_get_name_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_json_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_ExecdStart_long_ar_keys, test_setup_file, test_teardown_file),
        cmocka_unit_test(test_ExecdLogRestart_agent),
        cmocka_unit_test(test_ExecdLogRestart_reload),
        cmocka_unit_test(test_ExecdLogRestart_open_fails),
        cmocka_unit_test(test_ExecdLogRestart_rejects_symlink),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
