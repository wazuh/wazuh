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

#include "../../wrappers/posix/pthread_wrappers.h"
#include "../../wrappers/posix/select_wrappers.h"
#include "../../wrappers/posix/unistd_wrappers.h"
#include "../../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../../wrappers/wazuh/shared/pthreads_op_wrappers.h"
#include "../../wrappers/wazuh/os_net/os_net_wrappers.h"
#include "../../wrappers/wazuh/wazuh_modules/wm_task_manager_wrappers.h"

#include "wmodules.h"
#include "wm_task_manager.h"
#include "wm_task_manager_tasks.h"
#include "shared.h"

int wm_task_manager_init(wm_task_manager *task_config);
void* wm_task_manager_main(wm_task_manager* task_config);
void wm_task_manager_destroy(wm_task_manager* task_config);
cJSON* wm_task_manager_dump(const wm_task_manager* task_config);

// Setup / teardown

static int setup_group(void **state) {
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);
    *state = config;
    return 0;
}

static int teardown_group(void **state) {
    wm_task_manager *config = *state;
    os_free(config);
    return 0;
}

static int teardown_json(void **state) {
    if (state[1]) {
        cJSON *json = state[1];
        cJSON_Delete(json);
    }
    return 0;
}

static int teardown_string(void **state) {
    if (state[1]) {
        char *string = state[1];
        os_free(string);
    }
    return 0;
}

// Wrappers

int __wrap_accept() {
    return mock();
}

// Tests

void test_wm_task_manager_dump_enabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "yes");
}

void test_wm_task_manager_dump_disabled(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 0;

    cJSON *ret = wm_task_manager_dump(config);

    state[1] = ret;

    assert_non_null(ret);
    cJSON *conf = cJSON_GetObjectItem(ret, "task-manager");
    assert_non_null(conf);
    assert_non_null(cJSON_GetObjectItem(conf, "enabled"));
    assert_string_equal(cJSON_GetObjectItem(conf, "enabled")->valuestring, "no");
}

void test_wm_task_manager_destroy(void **state)
{
    wm_task_manager *config = NULL;
    os_calloc(1, sizeof(wm_task_manager), config);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8201): Module Task Manager finished.");

    wm_task_manager_destroy(config);
}

void test_wm_task_manager_init_ok(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 1;
    config->cache_ttl = 60;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "Task cache initialized with TTL: 60 seconds");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    int ret = wm_task_manager_init(config);

    assert_int_equal(ret, sock);
}

void test_wm_task_manager_init_bind_err(void **state)
{
    wm_task_manager *config = *state;

    config->enabled = 1;
    config->cache_ttl = 60;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "Task cache initialized with TTL: 60 seconds");

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, OS_INVALID);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8251): Queue 'queue/tasks/task' not accessible: 'Success'. Exiting...");

    expect_assert_failure(wm_task_manager_init(config));
}

void test_wm_task_manager_init_disabled(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;

    config->enabled = 0;

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtinfo, formatted_msg, "(8202): Module disabled. Exiting...");

    expect_assert_failure(wm_task_manager_init(config));
}

void test_wm_task_manager_main_recv_max_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;
    config->cache_ttl = 60;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    // wm_task_manager_init

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_MAXLEN);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8256): Received message > '4194304'");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_recv_empty_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;
    config->cache_ttl = 60;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    // wm_task_manager_init

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, 0);

    expect_string(__wrap__mtdebug1, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mtdebug1, formatted_msg, "(8203): Empty message from local client.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_recv_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;
    config->cache_ttl = 60;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    // wm_task_manager_init

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8254): Error in recv(): 'Success'");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_sockterr_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;
    config->cache_ttl = 60;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    // wm_task_manager_init

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8255): Response size is bigger than expected.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_accept_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;
    config->cache_ttl = 60;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    // wm_task_manager_init

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8253): Error in accept(): 'Success'");

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8255): Response size is bigger than expected.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_select_empty_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;
    config->cache_ttl = 60;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    // wm_task_manager_init

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    will_return(__wrap_select, 0);

    will_return(__wrap_select, 1);

    will_return(__wrap_accept, peer);

    expect_value(__wrap_OS_RecvSecureTCP, sock, peer);
    expect_value(__wrap_OS_RecvSecureTCP, size, OS_MAXSTR);
    will_return(__wrap_OS_RecvSecureTCP, message);
    will_return(__wrap_OS_RecvSecureTCP, OS_SOCKTERR);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8255): Response size is bigger than expected.");

    wm_task_manager_main(config);
}

void test_wm_task_manager_main_select_err(void **state)
{
    wm_task_manager *config = *state;
    int sock = 555;
    int peer = 1111;

    config->enabled = 1;
    config->cache_ttl = 60;

    char *message = "{"
                    "  \"origin\": {"
                    "      \"name\": \"node05\","
                    "      \"module\": \"upgrade_module\""
                    "   },"
                    "  \"command\": \"upgrade\","
                    "  \"parameters\": {"
                    "      \"agents\": [1, 2]"
                    "   }"
                    "}";

    // wm_task_manager_init

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    expect_string(__wrap_OS_BindUnixDomainWithPerms, path, TASK_QUEUE);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, type, SOCK_STREAM);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, max_msg_size, OS_MAXSTR);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, uid, getuid());
    expect_value(__wrap_OS_BindUnixDomainWithPerms, gid, 0);
    expect_value(__wrap_OS_BindUnixDomainWithPerms, perm, 0660);

    will_return(__wrap_OS_BindUnixDomainWithPerms, sock);

    expect_string(__wrap__mtinfo, tag, "wazuh-manager-modulesd:task-manager");
    expect_any(__wrap__mtinfo, formatted_msg);

    will_return(__wrap_select, -1);

    expect_string(__wrap__mterror, tag, "wazuh-manager-modulesd:task-manager");
    expect_string(__wrap__mterror, formatted_msg, "(8252): Error in select(): 'Success'. Exiting...");

    expect_assert_failure(wm_task_manager_main(config));
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // wm_task_manager_dump
        cmocka_unit_test_teardown(test_wm_task_manager_dump_enabled, teardown_json),
        cmocka_unit_test_teardown(test_wm_task_manager_dump_disabled, teardown_json),
        // wm_task_manager_destroy
        cmocka_unit_test(test_wm_task_manager_destroy),
        // wm_task_manager_init
        cmocka_unit_test(test_wm_task_manager_init_ok),
        cmocka_unit_test(test_wm_task_manager_init_bind_err),
        cmocka_unit_test(test_wm_task_manager_init_disabled),
        // wm_task_manager_dispatch
        // wm_task_manager_main
        cmocka_unit_test(test_wm_task_manager_main_recv_max_err),
        cmocka_unit_test(test_wm_task_manager_main_recv_empty_err),
        cmocka_unit_test(test_wm_task_manager_main_recv_err),
        cmocka_unit_test(test_wm_task_manager_main_sockterr_err),
        cmocka_unit_test(test_wm_task_manager_main_accept_err),
        cmocka_unit_test(test_wm_task_manager_main_select_empty_err),
        cmocka_unit_test(test_wm_task_manager_main_select_err)
    };
    return cmocka_run_group_tests(tests, setup_group, teardown_group);
}
