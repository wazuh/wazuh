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
#include <unistd.h>

#include "../../headers/shared.h"
#include "../../analysisd/active-response.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/privsep_op_wrappers.h"

#define CFG_FILE "ossec.conf"

#define AR_BUILTIN_LINES                                                                   \
    "restart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\n"     \
    "restart-wazuh0 - restart-ossec.sh - 0\nrestart-wazuh0 - restart-ossec.cmd - 0\n"     \
    "restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n"

#define CMD_TEST                                \
    "<command>"                                 \
    "<name>test1578</name>"                     \
    "<executable>restart-wazuh</executable>"    \
    "<timeout_allowed>no</timeout_allowed>"     \
    "</command>"

#define AR_TEST                         \
    "<active-response>"                 \
    "<command>test1578</command>"       \
    "<location>local</location>"        \
    "<rules_id>5712</rules_id>"         \
    "</active-response>"

#define AR_TEST_DISABLED                \
    "<active-response>"                 \
    "<disabled>yes</disabled>"          \
    "<command>test1578</command>"       \
    "<location>local</location>"        \
    "<rules_id>5712</rules_id>"         \
    "</active-response>"

#define OTHER_ROOT "<ossec_config><global><logall>no</logall></global></ossec_config>"

static char work_dir[] = "/tmp/test_analysisd_active-response.XXXXXX";
static char orig_dir[PATH_MAX];

/* helpers */

static void free_ar_command(void *data)
{
    ar_command *cmd = (ar_command *)data;
    os_free(cmd->name);
    os_free(cmd->executable);
    os_free(cmd->extra_args);
    os_free(cmd);
}

static void free_active_response(void *data)
{
    active_response *ar = (active_response *)data;
    os_free(ar->name);
    os_free(ar->command);
    os_free(ar->agent_id);
    os_free(ar->rules_id);
    os_free(ar->rules_group);
    os_free(ar);
}

static void write_config(const char *content)
{
    FILE *fp = fopen(CFG_FILE, "w");
    assert_non_null(fp);
    assert_int_not_equal(fputs(content, fp), EOF);
    fclose(fp);
}

static void assert_ar_file(const char *expected)
{
    char buffer[OS_MAXSTR] = {0};
    FILE *fp = fopen(DEFAULTAR, "r");
    assert_non_null(fp);
    size_t len = fread(buffer, 1, sizeof(buffer) - 1, fp);
    fclose(fp);
    buffer[len] = '\0';
    assert_string_equal(buffer, expected);
}

/* Privsep_GetGroup is called once by AR_ReadConfig and once per <active-response> block */
static void expect_get_group(int times)
{
    for (int i = 0; i < times; i++) {
        expect_string(__wrap_Privsep_GetGroup, name, USER);
        will_return(__wrap_Privsep_GetGroup, getgid());
    }
}

/* cmocka keeps the expected string's pointer, so it must be a literal */
#define expect_ar_written(command) \
    expect_string(__wrap__mdebug1, formatted_msg, "Writing command '" command "' to '" DEFAULTAR "'")

/* A single active response bound to the single test1578 command */
static void assert_single_ar_bound(void)
{
    assert_int_equal(ar_commands->currently_size, 1);
    assert_int_equal(active_responses->currently_size, 1);

    ar_command *cmd = (ar_command *)ar_commands->first_node->data;
    active_response *ar = (active_response *)active_responses->first_node->data;

    assert_string_equal(cmd->name, "test1578");
    assert_ptr_equal(ar->ar_cmd, cmd);
    assert_string_equal(ar->name, "test15780");
    assert_ar_file(AR_BUILTIN_LINES "test15780 - restart-wazuh - 0\n");
}

/* setup/teardown */

static int group_setup(void **state)
{
    (void) state;
    if (getcwd(orig_dir, sizeof(orig_dir)) == NULL || mkdtemp(work_dir) == NULL) {
        return -1;
    }
    if (chdir(work_dir) < 0 || mkdir("etc", 0700) < 0 || mkdir("etc/shared", 0700) < 0) {
        return -1;
    }
    return 0;
}

static int group_teardown(void **state)
{
    (void) state;
    char cmd[PATH_MAX + 16];

    if (chdir(orig_dir) < 0) {
        return -1;
    }
    snprintf(cmd, sizeof(cmd), "rm -rf %s", work_dir);
    return system(cmd);
}

static int test_setup(void **state)
{
    (void) state;
    AR_Init();
    return 0;
}

static int test_teardown(void **state)
{
    (void) state;
    OSList_SetFreeDataPointer(active_responses, free_active_response);
    OSList_SetFreeDataPointer(ar_commands, free_ar_command);
    OSList_Destroy(active_responses);
    OSList_Destroy(ar_commands);
    active_responses = NULL;
    ar_commands = NULL;
    unlink(CFG_FILE);
    return 0;
}

/* tests */

static void test_AR_ReadConfig_command_first_same_root(void **state)
{
    (void) state;
    write_config("<ossec_config>" CMD_TEST AR_TEST "</ossec_config>");

    expect_get_group(2);
    expect_ar_written("test1578");

    assert_int_equal(AR_ReadConfig(CFG_FILE), 0);
    assert_single_ar_bound();
}

static void test_AR_ReadConfig_command_first_split_roots(void **state)
{
    (void) state;
    write_config(OTHER_ROOT "<ossec_config>" CMD_TEST "</ossec_config>"
                 "<ossec_config>" AR_TEST "</ossec_config>");

    expect_get_group(2);
    expect_ar_written("test1578");

    assert_int_equal(AR_ReadConfig(CFG_FILE), 0);
    assert_single_ar_bound();
}

/* The active response precedes its command in the same root */
static void test_AR_ReadConfig_ar_first_same_root(void **state)
{
    (void) state;
    write_config("<ossec_config>" AR_TEST CMD_TEST "</ossec_config>");

    expect_get_group(2);
    expect_ar_written("test1578");

    assert_int_equal(AR_ReadConfig(CFG_FILE), 0);
    assert_single_ar_bound();
}

/* The active response lives in a root that precedes its command's root */
static void test_AR_ReadConfig_ar_first_split_roots(void **state)
{
    (void) state;
    write_config("<ossec_config>" AR_TEST "</ossec_config>" OTHER_ROOT
                 "<ossec_config>" CMD_TEST "</ossec_config>");

    expect_get_group(2);
    expect_ar_written("test1578");

    assert_int_equal(AR_ReadConfig(CFG_FILE), 0);
    assert_single_ar_bound();
}

static void test_AR_ReadConfig_undefined_command(void **state)
{
    (void) state;
    char inv_cmd_msg[OS_SIZE_256];
    char config_error_msg[OS_SIZE_256];
    write_config("<ossec_config>" AR_TEST "</ossec_config>");

    expect_get_group(2);
    expect_string(__wrap__mdebug1, formatted_msg, "Invalid command");
    snprintf(inv_cmd_msg, sizeof(inv_cmd_msg), AR_INV_CMD, "test1578");
    expect_string(__wrap__merror, formatted_msg, inv_cmd_msg);
    snprintf(config_error_msg, sizeof(config_error_msg), CONFIG_ERROR, CFG_FILE);
    expect_string(__wrap__merror, formatted_msg, config_error_msg);

    assert_int_equal(AR_ReadConfig(CFG_FILE), OS_INVALID);
    assert_int_equal(active_responses->currently_size, 0);
    assert_ar_file(AR_BUILTIN_LINES);
}

static void test_AR_ReadConfig_disabled_ar_first(void **state)
{
    (void) state;
    write_config("<ossec_config>" AR_TEST_DISABLED CMD_TEST "</ossec_config>");

    expect_get_group(2);
    expect_string(__wrap__mdebug1, formatted_msg, "active response command 'test1578' is disabled");

    assert_int_equal(AR_ReadConfig(CFG_FILE), 0);
    assert_int_equal(ar_commands->currently_size, 1);
    assert_int_equal(active_responses->currently_size, 0);
    assert_ar_file(AR_BUILTIN_LINES);
}

/* ar.conf keeps the active responses in file order, wherever their commands are */
static void test_AR_ReadConfig_mixed_order_keeps_ar_order(void **state)
{
    (void) state;
    write_config("<ossec_config>"
                 "<active-response><command>cmd_a</command><location>local</location></active-response>"
                 "<command><name>cmd_b</name><executable>b.sh</executable></command>"
                 "<active-response><command>cmd_b</command><location>local</location></active-response>"
                 "<command><name>cmd_a</name><executable>a.sh</executable></command>"
                 "</ossec_config>");

    expect_get_group(3);
    expect_ar_written("cmd_a");
    expect_ar_written("cmd_b");

    assert_int_equal(AR_ReadConfig(CFG_FILE), 0);
    assert_int_equal(ar_commands->currently_size, 2);
    assert_int_equal(active_responses->currently_size, 2);

    active_response *ar_a = (active_response *)active_responses->first_node->data;
    active_response *ar_b = (active_response *)active_responses->first_node->next->data;
    assert_string_equal(ar_a->ar_cmd->executable, "a.sh");
    assert_string_equal(ar_b->ar_cmd->executable, "b.sh");
    assert_ar_file(AR_BUILTIN_LINES "cmd_a0 - a.sh - 0\ncmd_b0 - b.sh - 0\n");
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_AR_ReadConfig_command_first_same_root, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_AR_ReadConfig_command_first_split_roots, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_AR_ReadConfig_ar_first_same_root, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_AR_ReadConfig_ar_first_split_roots, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_AR_ReadConfig_undefined_command, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_AR_ReadConfig_disabled_ar_first, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_AR_ReadConfig_mixed_order_keeps_ar_order, test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
