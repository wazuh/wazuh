/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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

#include "../headers/audit_op.h"
#include "../headers/defs.h"

extern w_audit_rules_list *_audit_rules_list;

/* auxiliary structs */

typedef struct __audit_replies {
    struct audit_reply *reply1;
    struct audit_reply *reply2;
    struct audit_reply *reply3;
}audit_replies;

/* redefinitons/wrapping */

void __wrap__merror(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(const char * file, int line, const char * func, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

int __wrap_audit_send(int fd, int type, const void *data, unsigned int size) {
    check_expected(fd);
    check_expected(type);

    return mock();
}

int __wrap_audit_get_reply(int fd, struct audit_reply *rep, reply_t block, int peek) {
    check_expected(fd);
    check_expected(block);

    struct audit_reply *reply = mock_type(struct audit_reply *);
    if (reply) {
        *rep = *reply;
    }

    return mock();
}

int __wrap_select() {
    return mock();
}

/* setups/teardowns */

static int group_teardown(void **state) {
    audit_free_list();

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

/* tests */

static void test_audit_get_rule_list_error(void **state) {
    (void) state;

    expect_value(__wrap_audit_send, fd, 0);
    expect_value(__wrap_audit_send, type, 1013);
    will_return(__wrap_audit_send, -1);

    expect_string(__wrap__merror, formatted_msg, "Error sending rule list data request (Operation not permitted)");

    int ret = audit_get_rule_list(0);

    assert_int_equal(ret, -1);
}

static void test_audit_get_rule_list_success(void **state) {
    (void) state;

    expect_value(__wrap_audit_send, fd, 0);
    expect_value(__wrap_audit_send, type, AUDIT_LIST_RULES);
    will_return(__wrap_audit_send, 0);

    will_return_always(__wrap_select, 0);

    expect_value_count(__wrap_audit_get_reply, fd, 0, 40);
    expect_value_count(__wrap_audit_get_reply, block, GET_REPLY_NONBLOCKING, 40);
    will_return_always(__wrap_audit_get_reply, 0);

    int ret = audit_get_rule_list(0);

    assert_int_equal(ret, 1);
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

    assert_int_equal(ret, 1);
    assert_non_null(_audit_rules_list->list[0]);
    assert_string_equal(_audit_rules_list->list[0]->path, "");
    assert_string_equal(_audit_rules_list->list[0]->key, "");
    assert_string_equal(_audit_rules_list->list[0]->perm, "rwxa");
}


int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_audit_get_rule_list_error),
        cmocka_unit_test(test_audit_get_rule_list_success),
        cmocka_unit_test_setup_teardown(test_kernel_get_reply, test_setup_kernel_get_reply, test_teardown_kernel_get_reply),
        cmocka_unit_test_setup_teardown(test_audit_print_reply, test_setup_print_reply, test_teardown_print_reply),
    };
    return cmocka_run_group_tests(tests, NULL, group_teardown);
}
