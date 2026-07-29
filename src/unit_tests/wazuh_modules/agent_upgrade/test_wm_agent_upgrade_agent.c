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
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>

#include "../../wrappers/common.h"
#include "../../wrappers/libc/stdio_wrappers.h"
#include "../../wrappers/posix/select_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wmodules_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_agent_upgrade_wrappers.h"

#include "wmodules.h"
#include "wm_agent_upgrade_agent.h"
#include "shared.h"

#ifndef TEST_WINAGENT
void* wm_agent_upgrade_listen_messages(void *arg);
#endif
void wm_agent_upgrade_check_status(const wm_agent_configs* agent_config);
bool wm_upgrade_agent_search_upgrade_result(unsigned int *raw_code);

// Setup / teardown

static int setup_group(void **state) {
    wm_agent_configs *config = NULL;
    os_calloc(1, sizeof(wm_agent_configs), config);
    *state = config;
    test_mode = 1;
    return 0;
}

static int teardown_group(void **state) {
    wm_agent_configs *config = *state;
    os_free(config);
    test_mode = 0;
    return 0;
}

static int setup_test_executions(void **state) {
    wm_max_eps = 1;
    wm_shutdown_requested = 0;
    return 0;
}

// Wrappers

int __wrap_accept() {
    return mock();
}

int __wrap_CreateThread(void * (*function_pointer)(void *), void *data) {
    check_expected_ptr(function_pointer);
    return 1;
}

// Tests

void test_wm_upgrade_agent_search_upgrade_result_successful(void **state)
{
    (void) state;
    unsigned int raw_code = 999;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    bool ret = wm_upgrade_agent_search_upgrade_result(&raw_code);

    assert_true(ret);
    assert_int_equal(raw_code, 0);
}

void test_wm_upgrade_agent_search_upgrade_result_failed_missing_dependency(void **state)
{
    (void) state;
    unsigned int raw_code = 999;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "1\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "1\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    bool ret = wm_upgrade_agent_search_upgrade_result(&raw_code);

    assert_true(ret);
    assert_int_equal(raw_code, 1);
}

void test_wm_upgrade_agent_search_upgrade_result_failed(void **state)
{
    (void) state;
    unsigned int raw_code = 999;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "2\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "2\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    bool ret = wm_upgrade_agent_search_upgrade_result(&raw_code);

    assert_true(ret);
    assert_int_equal(raw_code, 2);
}

void test_wm_upgrade_agent_search_upgrade_result_error_open(void **state)
{
    (void) state;
    unsigned int raw_code = 999;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    bool ret = wm_upgrade_agent_search_upgrade_result(&raw_code);

    assert_false(ret);
    // Untouched when no file is present.
    assert_int_equal(raw_code, 999);
}

void test_wm_upgrade_agent_search_upgrade_result_empty_file(void **state)
{
    (void) state;
    unsigned int raw_code = 999;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, NULL);
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, NULL);
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    bool ret = wm_upgrade_agent_search_upgrade_result(&raw_code);

    // A one-shot check has nothing to retry against: an unreadable/empty file is
    // treated the same as "no result found".
    assert_false(ret);
    assert_int_equal(raw_code, 999);
}

void test_wm_upgrade_agent_search_upgrade_result_error_code(void **state)
{
    (void) state;
    unsigned int raw_code = 999;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "5\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "5\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    // Out-of-range raw_code (5 >= WM_UPGRADE_MAX_STATE) is still returned as-is;
    // it is the caller's job (wm_agent_upgrade_check_status) to coerce it.
    bool ret = wm_upgrade_agent_search_upgrade_result(&raw_code);

    assert_true(ret);
    assert_int_equal(raw_code, 5);
}

void test_wm_upgrade_agent_search_upgrade_result_invalid_content(void **state)
{
    (void) state;
    unsigned int raw_code = 999;

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "not_a_number\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "not_a_number\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    bool ret = wm_upgrade_agent_search_upgrade_result(&raw_code);

    assert_false(ret);
    assert_int_equal(raw_code, 999);
}

void test_wm_agent_upgrade_check_status_successful(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

#ifndef TEST_WINAGENT
    expect_any_always(__wrap_sleep, seconds);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "0\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "0\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    // Purely informational now (#37733/#37834): nothing is sent to the manager.
    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "Upgrade was successful");

    expect_string(__wrap_remove, filename, WM_AGENT_UPGRADE_RESULT_FILE);
    will_return(__wrap_remove, 0);

    wm_agent_upgrade_check_status(config);

    assert_int_equal(allow_upgrades, true);
}

void test_wm_agent_upgrade_check_status_remove_fails_still_allows(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

#ifndef TEST_WINAGENT
    expect_any_always(__wrap_sleep, seconds);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, (FILE*)1);

#ifdef TEST_WINAGENT
    expect_value(wrap_fgets, __stream, (FILE*)1);
    will_return(wrap_fgets, "2\n");
#else
    expect_value(__wrap_fgets, __stream, (FILE*)1);
    will_return(__wrap_fgets, "2\n");
#endif

    expect_value(__wrap_fclose, _File, (FILE*)1);
    will_return(__wrap_fclose, 1);

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtinfo, formatted_msg, "Upgrade failed");

    expect_string(__wrap_remove, filename, WM_AGENT_UPGRADE_RESULT_FILE);
    will_return(__wrap_remove, -1);

    /* WM_AGENT_UPGRADE_RESULT_FILE (and so UPGRADE_DIR) is platform-conditional
     * (backslash-separated on Windows) -- build the expected message from the
     * same macro every other expectation in this file already uses, instead of
     * hardcoding one platform's literal path. */
    char expected_erase_error[256];
    snprintf(expected_erase_error, sizeof(expected_erase_error),
             "(8136): At check_status: Could not erase file '%s'", WM_AGENT_UPGRADE_RESULT_FILE);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, expected_erase_error);

    wm_agent_upgrade_check_status(config);

    // Upgrades are re-allowed regardless: there is no manager round-trip left to
    // gate this on.
    assert_int_equal(allow_upgrades, true);
}

void test_wm_agent_upgrade_check_status_no_result_file(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

#ifndef TEST_WINAGENT
    expect_any_always(__wrap_sleep, seconds);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    wm_agent_upgrade_check_status(config);

    assert_int_equal(allow_upgrades, true);
}

#ifndef TEST_WINAGENT
void test_wm_agent_upgrade_check_status_shutdown_during_wait(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;
    wm_shutdown_requested = 1;

    // wm_sleep_interruptible's loop condition is false from the first check, so it
    // never calls sleep(); check_status() then returns immediately without ever
    // looking at the result file or touching allow_upgrades.
    wm_agent_upgrade_check_status(config);

    assert_int_equal(allow_upgrades, false);

    wm_shutdown_requested = 0;
}
#endif

#ifndef TEST_WINAGENT

void test_wm_agent_upgrade_listen_messages_ok(void **state)
{
    int socket = 0;
    int peer = 1111;

    char *input = "{"
                  "   \"command\": \"upgrade\","
                  "   \"parameters\": {"
                  "        \"file\":\"test.wpk\","
                  "        \"installer\":\"test.sh\""
                  "    }"
                  "}";

    size_t input_size = strlen(input) + 1;
    char *response = NULL;
    os_calloc(OS_SIZE_256, sizeof(char), response);

    sprintf(response, "{"
                      "    \"error\":0,"
                      "    \"data\":[],"
                      "    \"message\":\"ok\""
                      "}");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, input_size);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8155): Incomming message: '{"
                                                                               "   \"command\": \"upgrade\","
                                                                               "   \"parameters\": {"
                                                                               "        \"file\":\"test.wpk\","
                                                                               "        \"installer\":\"test.sh\""
                                                                               "    }"
                                                                               "}'");

    expect_memory(__wrap_wm_agent_upgrade_process_command, buffer, input, sizeof(input));
    will_return(__wrap_wm_agent_upgrade_process_command, response);
    will_return(__wrap_wm_agent_upgrade_process_command, strlen(response));

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8156): Response message: '{"
                                                                              "    \"error\":0,"
                                                                              "    \"data\":[],"
                                                                              "    \"message\":\"ok\""
                                                                              "}'");

    expect_value(__wrap_OS_SendSecureTCP, sock, peer);
    expect_value(__wrap_OS_SendSecureTCP, size, strlen(response));
    expect_string(__wrap_OS_SendSecureTCP, msg, response);
    will_return(__wrap_OS_SendSecureTCP, 0);

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_empty(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8159): Empty message from local client.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8111): Error in recv(): 'Success'");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_receive_sock_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_accept_error_eintr(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_accept_error(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8110): Error in accept(): 'Operation not permitted'");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_zero(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_error_eintr(void **state)
{
    int socket = 0;
    int peer = 1111;
    char *input = "Bad JSON";
    errno = EINTR;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, -1);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, input);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8112): Response size is bigger than expected.");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_select_error(void **state)
{
    int socket = 0;
    errno = 1;

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, socket);

    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8109): Error in select(): 'Operation not permitted'. Exiting...");

    wm_agent_upgrade_listen_messages(NULL);
}

void test_wm_agent_upgrade_listen_messages_bind_error(void **state)
{
    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, AGENT_UPGRADE_SOCK);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, uid);
    expect_any(__wrap_OS_BindUnixDomainWithPerms, gid);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);
    will_return(__wrap_OS_BindUnixDomainWithPerms, -1);

    expect_string(__wrap__mterror, tag, "wazuh-modulesd:agent-upgrade");
    expect_string(__wrap__mterror, formatted_msg, "(8108): Unable to bind to socket 'queue/sockets/upgrade': 'Operation not permitted'");

    wm_agent_upgrade_listen_messages(NULL);
}

#endif

void test_wm_agent_upgrade_start_agent_module_enabled(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

    expect_string(__wrap__mtinfo, tag, "wazuh-modulesd:agent-upgrade");
    expect_any(__wrap__mtinfo, formatted_msg);

#ifndef TEST_WINAGENT
    expect_memory(__wrap_CreateThread, function_pointer, wm_agent_upgrade_listen_messages, sizeof(wm_agent_upgrade_listen_messages));

    expect_any_always(__wrap_sleep, seconds);
#endif

    expect_string(__wrap_wfopen, path, WM_AGENT_UPGRADE_RESULT_FILE);
    expect_string(__wrap_wfopen, mode, "r");
    will_return(__wrap_wfopen, NULL);

    wm_agent_upgrade_start_agent_module(config, 1);

    assert_int_equal(allow_upgrades, true);
}

void test_wm_agent_upgrade_start_agent_module_disabled(void **state)
{
    wm_agent_configs *config = *state;

    allow_upgrades = false;

#ifndef TEST_WINAGENT
    expect_memory(__wrap_CreateThread, function_pointer, wm_agent_upgrade_listen_messages, sizeof(wm_agent_upgrade_listen_messages));
#endif

    wm_agent_upgrade_start_agent_module(config, 0);

    assert_int_equal(allow_upgrades, false);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_upgrade_agent_search_upgrade_result
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_failed, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_failed_missing_dependency, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_open, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_empty_file, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_error_code, setup_test_executions),
        cmocka_unit_test_setup(test_wm_upgrade_agent_search_upgrade_result_invalid_content, setup_test_executions),
        // wm_agent_upgrade_check_status
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_successful, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_remove_fails_still_allows, setup_test_executions),
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_no_result_file, setup_test_executions),
#ifndef TEST_WINAGENT
        cmocka_unit_test_setup(test_wm_agent_upgrade_check_status_shutdown_during_wait, setup_test_executions),
#endif
#ifndef TEST_WINAGENT
        // wm_agent_upgrade_listen_messages
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_ok),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_empty),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_receive_sock_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_accept_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_zero),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error_eintr),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_select_error),
        cmocka_unit_test(test_wm_agent_upgrade_listen_messages_bind_error),
#endif
        // wm_agent_upgrade_start_agent_module
        cmocka_unit_test_setup(test_wm_agent_upgrade_start_agent_module_enabled, setup_test_executions),
        cmocka_unit_test(test_wm_agent_upgrade_start_agent_module_disabled)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
