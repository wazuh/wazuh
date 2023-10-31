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
#include <errno.h>
#include <string.h>
#ifndef TEST_WINAGENT
#include "../wrappers/externals/audit/libaudit_wrappers.h"
#endif
#include "../wrappers/libc/stdio_wrappers.h"
#include "../wrappers/posix/select_wrappers.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"
#include "../wrappers/wazuh/shared/exec_op_wrappers.h"
#include "../wrappers/wazuh/shared/binaries_op_wrappers.h"
#include "../wrappers/common.h"
#include "../headers/audit_op.h"
#include "../headers/defs.h"
#include "../headers/exec_op.h"
#include "../headers/list_op.h"

#define PERMS (AUDIT_PERM_WRITE | AUDIT_PERM_ATTR)

extern OSList *audit_rules_list;

/* auxiliary structs */

typedef struct __audit_replies {
    struct audit_reply *reply1;
    struct audit_reply *reply2;
    struct audit_reply *reply3;
}audit_replies;

/* setups/teardowns */

static int group_setup(void **state) {
    test_mode = 1;
    return 0;
}

static int group_teardown(void **state) {
    test_mode = 0;
    audit_rules_list_free();
    return 0;
}

static int test_setup_kernel_get_reply(void **state) {
    audit_replies *replies = calloc(1, sizeof(audit_replies));

    struct audit_reply *reply1 = calloc(1, sizeof(struct audit_reply));
    struct audit_reply *reply2 = calloc(1, sizeof(struct audit_reply));
    struct audit_reply *reply3 = calloc(1, sizeof(struct audit_reply));

    reply1->type = NLMSG_ERROR;
    reply1->error = calloc(1, sizeof(struct nlmsgerr));
    reply1->error->error = 0;

    reply2->type = AUDIT_LIST_RULES;
    reply2->ruledata = calloc(1, sizeof(struct audit_rule_data));
    reply2->ruledata->field_count = 0;

    replies->reply1 = reply1;
    replies->reply2 = reply2;
    replies->reply3 = reply3;

    *state = replies;

    return 0;
}

static int test_teardown_kernel_get_reply(void **state) {
    audit_replies *replies = *state;

    free(replies->reply3);
    free(replies->reply2->ruledata);
    free(replies->reply2);
    free(replies->reply1->error);
    free(replies->reply1);
    free(replies);

    return 0;
}

static int test_setup_print_reply(void **state) {
    struct audit_reply *reply = calloc(1, sizeof(struct audit_reply));

    reply->type = AUDIT_LIST_RULES;
    reply->ruledata = calloc(1, sizeof(struct audit_rule_data));
    reply->ruledata->field_count = 4;
    reply->ruledata->fields[0] = AUDIT_DIR;
    reply->ruledata->values[0] = 0;
    reply->ruledata->fields[1] = AUDIT_FILTERKEY;
    reply->ruledata->values[1] = 0;
    reply->ruledata->fields[3] = AUDIT_PERM;
    reply->ruledata->values[3] = AUDIT_PERM_EXEC | AUDIT_PERM_WRITE | AUDIT_PERM_READ | AUDIT_PERM_ATTR;

    *state = reply;

    return 0;
}

static int test_teardown_print_reply(void **state) {
    struct audit_reply *reply = *state;

    free(reply->ruledata);
    free(reply);

    return 0;
}

static int test_teardown_free_path(void **state) {
    char *path = *state;

    free(path);

    return 0;
}

static int test_setup_file(void **state) {
    wfd_t * wfd = calloc(1, sizeof(wfd_t));

    *state = wfd;

    return 0;
}

static int test_teardown_file(void **state) {
    wfd_t * wfd = *state;

    free(wfd);

    return 0;
}

/* tests */

static void test_audit_get_rule_list_error(void **state) {
    (void) state;

    expect_value(__wrap_audit_send, fd, 0);
    expect_value(__wrap_audit_send, type, 1013);
    expect_any(__wrap_audit_send, data);
    will_return(__wrap_audit_send, -1);

    expect_string(__wrap__merror, formatted_msg, "Error sending rule list data request (Operation not permitted)");

    int ret = audit_get_rule_list(0);

    assert_int_equal(ret, -1);
}

static void test_audit_get_rule_list(void **state) {
    (void) state;

    expect_value(__wrap_audit_send, fd, 0);
    expect_value(__wrap_audit_send, type, AUDIT_LIST_RULES);
    expect_any(__wrap_audit_send, data);
    will_return(__wrap_audit_send, 0);

    will_return_always(__wrap_select, 0);

    expect_value_count(__wrap_audit_get_reply, fd, 0, 40);
    expect_value_count(__wrap_audit_get_reply, block, GET_REPLY_NONBLOCKING, 40);
    will_return_always(__wrap_audit_get_reply, 0);

    int ret = audit_get_rule_list(0);

    assert_int_equal(ret, 1);
    assert_non_null(audit_rules_list);
}

static void test_kernel_get_reply(void **state) {
    audit_replies *replies = *state;

    will_return(__wrap_select, -1);
    will_return(__wrap_select, 0);

    expect_value(__wrap_audit_get_reply, fd, 0);
    expect_value(__wrap_audit_get_reply, block, GET_REPLY_NONBLOCKING);
    will_return(__wrap_audit_get_reply, replies->reply1);
    will_return(__wrap_audit_get_reply, 1);

    will_return(__wrap_select, 0);

    expect_value(__wrap_audit_get_reply, fd, 0);
    expect_value(__wrap_audit_get_reply, block, GET_REPLY_NONBLOCKING);
    will_return(__wrap_audit_get_reply, replies->reply2);
    will_return(__wrap_audit_get_reply, 1);

    will_return(__wrap_select, 0);

    expect_value(__wrap_audit_get_reply, fd, 0);
    expect_value(__wrap_audit_get_reply, block, GET_REPLY_NONBLOCKING);
    will_return(__wrap_audit_get_reply, replies->reply3);
    will_return(__wrap_audit_get_reply, 1);

    errno = EINTR;

    kernel_get_reply(0);

    errno = 0;
}

static void test_audit_print_reply(void **state) {
    struct audit_reply *reply = *state;

    expect_string(__wrap__mdebug2, formatted_msg, "Audit rule loaded: -w  -p rwxa -k ");

    int ret = audit_print_reply(reply);
    w_audit_rule *rule = (w_audit_rule *) OSList_GetFirstNode(audit_rules_list)->data;

    assert_int_equal(ret, 1);
    assert_non_null(audit_rules_list->first_node);
    assert_string_equal(rule->path, "");
    assert_string_equal(rule->key, "");
    assert_int_equal(rule->perm, (AUDIT_PERM_EXEC | AUDIT_PERM_WRITE | AUDIT_PERM_READ | AUDIT_PERM_ATTR));
    assert_int_equal(audit_rules_list->currently_size, 1);
}

static void test_audit_clean_path(void **state) {
    char *path = "../test/file";
    char *cwd = "/home/folder";

    char *full_path = audit_clean_path(cwd, path);

    *state = full_path;

    assert_string_equal(full_path, "/home/test/file");
}

static void test_audit_restart(void **state) {
    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char *service_path = NULL;
    service_path = strdup("/path/to/service");
    expect_string(__wrap_get_binary_path, command, "service");
    will_return(__wrap_get_binary_path, service_path);
    will_return(__wrap_get_binary_path, 0);

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug1, formatted_msg, "auditd: test");

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_wpclose, 0);

    int ret = audit_restart();

    assert_int_equal(ret, 0);
}

static void test_audit_restart_open_error(void **state) {
    char *service_path = NULL;
    service_path = strdup("/path/to/service");
    expect_string(__wrap_get_binary_path, command, "service");
    will_return(__wrap_get_binary_path, service_path);
    will_return(__wrap_get_binary_path, 0);

    will_return(__wrap_wpopenv, NULL);

    expect_string(__wrap__merror, formatted_msg, "Could not launch command to restart Auditd: Success (0)");

    int ret = audit_restart();

    assert_int_equal(ret, -1);
}

static void test_audit_restart_close_exec_error(void **state) {
    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char *service_path = NULL;
    service_path = strdup("/path/to/service");
    expect_string(__wrap_get_binary_path, command, "service");
    will_return(__wrap_get_binary_path, service_path);
    will_return(__wrap_get_binary_path, 0);

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug1, formatted_msg, "auditd: test");

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_wpclose, 0x7f00);

    expect_string(__wrap__merror, formatted_msg, "Could not launch command to restart Auditd.");

    int ret = audit_restart();

    assert_int_equal(ret, -1);
}

static void test_audit_restart_close_error(void **state) {
    wfd_t * wfd = *state;
    wfd->file_out = (FILE*) 1234;

    char *service_path = NULL;
    service_path = strdup("/path/to/service");
    expect_string(__wrap_get_binary_path, command, "service");
    will_return(__wrap_get_binary_path, service_path);
    will_return(__wrap_get_binary_path, 0);

    will_return(__wrap_wpopenv, wfd);

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, "test");

    expect_string(__wrap__mdebug1, formatted_msg, "auditd: test");

    expect_value(__wrap_fgets, __stream, wfd->file_out);
    will_return(__wrap_fgets, NULL);

    will_return(__wrap_wpclose, 0xff00);

    expect_string(__wrap__merror, formatted_msg, "Could not restart Auditd service.");

    int ret = audit_restart();

    assert_int_equal(ret, -1);
}

static void test_audit_rules_list_append(void **state) {
    (void) state;

    int i;
    for(i = 0; i < 30; ++i) {
        w_audit_rule *rule = calloc(1, sizeof(w_audit_rule));
        rule->path = strdup("/test/file");
        rule->key = strdup("key");
        rule->perm = PERMS;
        OSList_AddData(audit_rules_list, rule);
    }

    assert_int_equal(audit_rules_list->currently_size, 31);
}

static void test_search_audit_rule(void **state) {
    (void) state;

    int ret = search_audit_rule("/test/file", PERMS, "key");

    assert_int_equal(ret, 1);
}

static void test_search_audit_rule_null(void **state) {
    (void) state;

    int ret = search_audit_rule(NULL, PERMS, NULL);

    assert_int_equal(ret, -1);
}

static void test_search_audit_rule_not_found(void **state) {
    (void) state;

    int ret = search_audit_rule("/test/search2", (PERMS | AUDIT_PERM_EXEC)  , "search2");

    assert_int_equal(ret, 0);
}

static void test_audit_add_rule(void **state) {
    (void) state;

    will_return(__wrap_audit_open, 1);

    expect_value(__wrap_audit_add_watch_dir, type, AUDIT_DIR);
    expect_string(__wrap_audit_add_watch_dir, path, "/usr/bin");
    will_return(__wrap_audit_add_watch_dir, 0);

    expect_value(__wrap_audit_update_watch_perms, perms, AUDIT_PERM_WRITE | AUDIT_PERM_ATTR);
    will_return(__wrap_audit_update_watch_perms, 0);

    expect_string(__wrap_audit_rule_fieldpair_data, pair, "key=bin-folder");
    expect_value(__wrap_audit_rule_fieldpair_data, flags, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK);
    will_return(__wrap_audit_rule_fieldpair_data, 0);

    will_return(__wrap_audit_add_rule_data, 1);

    will_return(__wrap_audit_close, 1);

    int ret = audit_add_rule("/usr/bin", PERMS, "bin-folder");

    assert_int_equal(ret, 1);
}

static void test_audit_delete_rule(void **state) {
    (void) state;

    will_return(__wrap_audit_open, 1);

    expect_value(__wrap_audit_add_watch_dir, type, AUDIT_DIR);
    expect_string(__wrap_audit_add_watch_dir, path, "/usr/bin");
    will_return(__wrap_audit_add_watch_dir, 0);

    expect_value(__wrap_audit_update_watch_perms, perms, AUDIT_PERM_WRITE | AUDIT_PERM_ATTR);
    will_return(__wrap_audit_update_watch_perms, 0);

    expect_string(__wrap_audit_rule_fieldpair_data, pair, "key=bin-folder");
    expect_value(__wrap_audit_rule_fieldpair_data, flags, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK);
    will_return(__wrap_audit_rule_fieldpair_data, 0);

    will_return(__wrap_audit_delete_rule_data, -1);

    will_return(__wrap_audit_errno_to_name, "AUDIT ERROR");

    expect_string(__wrap__mdebug2, formatted_msg, "Can't add or delete a rule (-1) = AUDIT ERROR");

    will_return(__wrap_audit_close, 1);

    int ret = audit_delete_rule("/usr/bin", PERMS, "bin-folder");

    assert_int_equal(ret, -1);
}

static void test_audit_manage_rules_open_error(void **state) {
    (void) state;

    will_return(__wrap_audit_open, -1);

    int ret = audit_manage_rules(ADD_RULE, "/folder/path", PERMS, "key-test");

    assert_int_equal(ret, -1);
}

static void test_audit_manage_rules_stat_error(void **state) {
    (void) state;

    will_return(__wrap_audit_open, 1);

    expect_string(__wrap__mdebug2, formatted_msg, "(6222): Stat() function failed on: '/folder/path' due to [(2)-(No such file or directory)]");

    will_return(__wrap_audit_close, 1);

    int ret = audit_manage_rules(ADD_RULE, "/folder/path", PERMS, "key-test");

    errno = 0;

    assert_int_equal(ret, -1);
}

static void test_audit_manage_rules_add_dir_error(void **state) {
    (void) state;

    will_return(__wrap_audit_open, 1);

    expect_value(__wrap_audit_add_watch_dir, type, AUDIT_DIR);
    expect_string(__wrap_audit_add_watch_dir, path, "/usr/bin");
    will_return(__wrap_audit_add_watch_dir, 1);

    will_return(__wrap_audit_errno_to_name, "AUDIT ERROR");

    expect_string(__wrap__mdebug2, formatted_msg, "audit_add_watch_dir = (1) AUDIT ERROR");

    will_return(__wrap_audit_close, 1);

    int ret = audit_manage_rules(ADD_RULE, "/usr/bin", PERMS, "bin-folder");

    assert_int_equal(ret, -1);
}

static void test_audit_manage_rules_update_perms_error(void **state) {
    (void) state;

    will_return(__wrap_audit_open, 1);

    expect_value(__wrap_audit_add_watch_dir, type, AUDIT_DIR);
    expect_string(__wrap_audit_add_watch_dir, path, "/usr/bin");
    will_return(__wrap_audit_add_watch_dir, 0);

    expect_value(__wrap_audit_update_watch_perms, perms, AUDIT_PERM_WRITE | AUDIT_PERM_ATTR);
    will_return(__wrap_audit_update_watch_perms, 1);

    will_return(__wrap_audit_errno_to_name, "AUDIT ERROR");

    expect_string(__wrap__mdebug2, formatted_msg, "audit_update_watch_perms = (1) AUDIT ERROR");

    will_return(__wrap_audit_close, 1);

    int ret = audit_manage_rules(ADD_RULE, "/usr/bin", PERMS, "bin-folder");

    assert_int_equal(ret, -1);
}

static void test_audit_manage_rules_key_length_error(void **state) {
    (void) state;

    char *key = "this is a very long key - this is a very long key - this is a very long key - this is a very long key - this is a very long key -"
                "this is a very long key - this is a very long key - this is a very long key - this is a very long key - this is a very long key -"
                "this is a very long key - this is a very long key - this is a very long key - this is a very long key - this is a very long key -"
                "this is a very long key - this is a very long key - this is a very long key - this is a very long key - this is a very long key -"
                "this is a very long key - this is a very long key - this is a very long key - this is a very long key - this is a very long key";

    will_return(__wrap_audit_open, 1);

    expect_value(__wrap_audit_add_watch_dir, type, AUDIT_DIR);
    expect_string(__wrap_audit_add_watch_dir, path, "/usr/bin");
    will_return(__wrap_audit_add_watch_dir, 0);

    expect_value(__wrap_audit_update_watch_perms, perms, AUDIT_PERM_WRITE | AUDIT_PERM_ATTR);
    will_return(__wrap_audit_update_watch_perms, 0);

    will_return(__wrap_audit_close, 1);

    int ret = audit_manage_rules(ADD_RULE, "/usr/bin", PERMS, key);

    assert_int_equal(ret, -1);
}

static void test_audit_manage_rules_fieldpair_error(void **state) {
    (void) state;

    will_return(__wrap_audit_open, 1);

    expect_value(__wrap_audit_add_watch_dir, type, AUDIT_DIR);
    expect_string(__wrap_audit_add_watch_dir, path, "/usr/bin");
    will_return(__wrap_audit_add_watch_dir, 0);

    expect_value(__wrap_audit_update_watch_perms, perms, AUDIT_PERM_WRITE | AUDIT_PERM_ATTR);
    will_return(__wrap_audit_update_watch_perms, 0);

    expect_string(__wrap_audit_rule_fieldpair_data, pair, "key=bin-folder");
    expect_value(__wrap_audit_rule_fieldpair_data, flags, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK);
    will_return(__wrap_audit_rule_fieldpair_data, 1);

    will_return(__wrap_audit_errno_to_name, "AUDIT ERROR");

    expect_string(__wrap__mdebug2, formatted_msg, "audit_rule_fieldpair_data = (1) AUDIT ERROR");

    will_return(__wrap_audit_close, 1);

    int ret = audit_manage_rules(ADD_RULE, "/usr/bin", PERMS, "bin-folder");

    assert_int_equal(ret, -1);
}

static void test_audit_manage_rules_action_error(void **state) {
    (void) state;

    will_return(__wrap_audit_open, 1);

    expect_value(__wrap_audit_add_watch_dir, type, AUDIT_DIR);
    expect_string(__wrap_audit_add_watch_dir, path, "/usr/bin");
    will_return(__wrap_audit_add_watch_dir, 0);

    expect_value(__wrap_audit_update_watch_perms, perms, AUDIT_PERM_WRITE | AUDIT_PERM_ATTR);
    will_return(__wrap_audit_update_watch_perms, 0);

    expect_string(__wrap_audit_rule_fieldpair_data, pair, "key=bin-folder");
    expect_value(__wrap_audit_rule_fieldpair_data, flags, AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK);
    will_return(__wrap_audit_rule_fieldpair_data, 0);

    will_return(__wrap_audit_close, 1);

    int ret = audit_manage_rules(-1, "/usr/bin", PERMS, "bin-folder");

    assert_int_equal(ret, -1);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_audit_get_rule_list_error),
        cmocka_unit_test(test_audit_get_rule_list),
        cmocka_unit_test_setup_teardown(test_kernel_get_reply, test_setup_kernel_get_reply, test_teardown_kernel_get_reply),
        cmocka_unit_test_setup_teardown(test_audit_print_reply, test_setup_print_reply, test_teardown_print_reply),
        cmocka_unit_test_teardown(test_audit_clean_path, test_teardown_free_path),
        cmocka_unit_test_setup_teardown(test_audit_restart, test_setup_file, test_teardown_file),
        cmocka_unit_test(test_audit_restart_open_error),
        cmocka_unit_test_setup_teardown(test_audit_restart_close_exec_error, test_setup_file, test_teardown_file),
        cmocka_unit_test_setup_teardown(test_audit_restart_close_error, test_setup_file, test_teardown_file),
        cmocka_unit_test(test_audit_rules_list_append),
        cmocka_unit_test(test_search_audit_rule),
        cmocka_unit_test(test_search_audit_rule_null),
        cmocka_unit_test(test_search_audit_rule_not_found),
        cmocka_unit_test(test_audit_add_rule),
        cmocka_unit_test(test_audit_delete_rule),
        cmocka_unit_test(test_audit_manage_rules_open_error),
        cmocka_unit_test(test_audit_manage_rules_stat_error),
        cmocka_unit_test(test_audit_manage_rules_add_dir_error),
        cmocka_unit_test(test_audit_manage_rules_update_perms_error),
        cmocka_unit_test(test_audit_manage_rules_key_length_error),
        cmocka_unit_test(test_audit_manage_rules_fieldpair_error),
        cmocka_unit_test(test_audit_manage_rules_action_error),
    };
    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
