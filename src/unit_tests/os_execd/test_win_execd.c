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

#include "shared.h"
#include "list_op.h"
#include "../os_regex/os_regex.h"
#include "../os_net/os_net.h"
#include "../os_execd/execd.h"

#include "../wrappers/common.h"
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/wazuh/os_execd/exec_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../wrappers/windows/libc/stdio_wrappers.h"

extern int test_mode;
extern OSList *timeout_list;

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

/* Tests */

static void test_WinExecdRun_ok(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-engine\""
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

    expect_value(wrap_fprintf, __stream, wfd->file_in);
    expect_string(wrap_fprintf, formatted_msg, "{"
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
    will_return(wrap_fprintf, 0);

    expect_value(wrap_fgets, __stream, wfd->file_out);
    will_return(wrap_fgets, "{"
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

    expect_value(wrap_fprintf, __stream, wfd->file_in);
    expect_string(wrap_fprintf, formatted_msg, "{"
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
    will_return(wrap_fprintf, 0);

    will_return(__wrap_wpclose, 0);

    ExecdRun(message);
}

static void test_WinExecdRun_timeout_not_repeated(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-engine\""
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

    expect_value(wrap_fprintf, __stream, wfd->file_in);
    expect_string(wrap_fprintf, formatted_msg, "{"
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
    will_return(wrap_fprintf, 0);

    expect_value(wrap_fgets, __stream, wfd->file_out);
    will_return(wrap_fgets, "{"
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

    expect_value(wrap_fprintf, __stream, wfd->file_in);
    expect_string(wrap_fprintf, formatted_msg, "{"
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
    will_return(wrap_fprintf, 0);

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

    ExecdRun(message);
}

static void test_WinExecdRun_timeout_repeated(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-engine\""
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

    expect_value(wrap_fprintf, __stream, wfd->file_in);
    expect_string(wrap_fprintf, formatted_msg, "{"
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
    will_return(wrap_fprintf, 0);

    expect_value(wrap_fgets, __stream, wfd->file_out);
    will_return(wrap_fgets, "{"
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

    expect_value(wrap_fprintf, __stream, wfd->file_in);
    expect_string(wrap_fprintf, formatted_msg, "{"
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
    will_return(wrap_fprintf, 0);

    will_return(__wrap_wpclose, 0);

    expect_string(__wrap__mdebug1, formatted_msg, "Command already received, updating time of addition to now.");

    ExecdRun(message);
}

static void test_WinExecdRun_wpopenv_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-engine\""
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

    ExecdRun(message);
}

static void test_WinExecdRun_fgets_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-engine\""
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

    expect_value(wrap_fprintf, __stream, wfd->file_in);
    expect_string(wrap_fprintf, formatted_msg, "{"
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
    will_return(wrap_fprintf, 0);

    expect_value(wrap_fgets, __stream, wfd->file_out);
    will_return(wrap_fgets, NULL);

    expect_string(__wrap__mdebug1, formatted_msg, "Active response won't be added to timeout list. Message not received with alert keys from script 'restart-wazuh'");

    will_return(__wrap_wpclose, 0);

    ExecdRun(message);
}

static void test_WinExecdRun_get_command_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{"
                        "\"version\":\"1\","
                        "\"origin\":{"
                            "\"name\":\"node01\","
                            "\"module\":\"wazuh-engine\""
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

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh0");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, NULL);

    will_return(__wrap_ReadExecConfig, 0);

    expect_string(__wrap_GetCommandbyName, name, "restart-wazuh0");
    will_return(__wrap_GetCommandbyName, timeout);
    will_return(__wrap_GetCommandbyName, NULL);

    expect_string(__wrap__merror, formatted_msg, "(1311): Invalid command name 'restart-wazuh0' provided.");

    ExecdRun(message);
}

static void test_WinExecdRun_get_name_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "{}";
    int timeout = 0;

    expect_string(__wrap__merror, formatted_msg, "(1316): Invalid AR command: '{}'");

    ExecdRun(message);
}

static void test_WinExecdRun_json_err(void **state) {
    wfd_t * wfd = *state;
    int queue = 1;
    int now = 123456789;
    char *message = "unknown";
    int timeout = 0;

    expect_string(__wrap__merror, formatted_msg, "(1315): Invalid JSON message: 'unknown'");

    ExecdRun(message);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_WinExecdRun_ok, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_WinExecdRun_timeout_not_repeated, test_setup_file_timeout, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_WinExecdRun_timeout_repeated, test_setup_file_timeout, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_WinExecdRun_wpopenv_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_WinExecdRun_fgets_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_WinExecdRun_get_command_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_WinExecdRun_get_name_err, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_WinExecdRun_json_err, test_setup_file, test_teardown_file),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
