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

#include "../../headers/shared.h"
#include "../../analysisd/eventinfo.h"
#include "../../analysisd/rules.h"

void os_remove_rules_list(RuleNode *node);

/* Rule 1 is a top-level rule in group "loop". Each other rule is in group "loop" and is a child of group "loop",
 * as in the ruleset of issue #39930: rule 100101 adds 1 node, 100102 adds 2, 100103 adds 4 and 100104 adds 8.
 */
static const char *LOOP_RULES =
    "<group name=\"loop,\">\n"
    "  <rule id=\"1\" level=\"0\">\n"
    "    <match>loop</match>\n"
    "    <description>Root</description>\n"
    "  </rule>\n"
    "  <rule id=\"100101\" level=\"3\">\n"
    "    <if_group>loop</if_group>\n"
    "    <description>Loop</description>\n"
    "  </rule>\n"
    "  <rule id=\"100102\" level=\"3\">\n"
    "    <if_group>loop</if_group>\n"
    "    <description>Loop</description>\n"
    "  </rule>\n"
    "  <rule id=\"100103\" level=\"3\">\n"
    "    <if_group>loop</if_group>\n"
    "    <description>Loop</description>\n"
    "  </rule>\n"
    "  <rule id=\"100104\" level=\"3\">\n"
    "    <if_group>loop</if_group>\n"
    "    <description>Loop</description>\n"
    "  </rule>\n"
    "</group>\n";

/* setup/teardown */

static int setup_rules_file(void **state) {
    char *path;
    os_strdup("/tmp/wazuh_rules_read_test_XXXXXX", path);

    int fd = mkstemp(path);
    if (fd < 0) {
        os_free(path);
        return -1;
    }

    size_t size = strlen(LOOP_RULES);
    if (write(fd, LOOP_RULES, size) != (ssize_t)size) {
        close(fd);
        unlink(path);
        os_free(path);
        return -1;
    }

    close(fd);
    *state = path;
    return 0;
}

static int teardown_rules_file(void **state) {
    char *path = *state;
    unlink(path);
    os_free(path);
    return 0;
}

/* wraps */

void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                    const char * file, char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected(formatted_msg);
}

/* tests */

static int read_rules(const char *path, RuleNode **tree, w_rule_tree_build_t *build) {
    EventList events = {0};
    EventList *last_events = &events;

    // analysisd.default_timeframe
    will_return(__wrap_getDefine_Int, 360);

    return Rules_OP_ReadRules(path, tree, NULL, &last_events, NULL, NULL, false, build);
}

/* cmocka keeps the pointer to the expected message: it must outlive the call */
static void expect_limit_error(char *expected, size_t size, const char *path, int sigid, size_t node_count,
                               size_t rule_node_count, size_t node_limit) {
    snprintf(expected, size,
             "(5108): Rule '%d' in '%s' exceeds the rule tree node limit (%zu nodes in the tree, %zu added by this "
             "rule, limit %zu). Ruleset loading aborted.",
             sigid, path, node_count, rule_node_count, node_limit);

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg, expected);
}

void test_Rules_OP_ReadRules_no_limit(void **state)
{
    const char *path = *state;
    w_rule_tree_build_t build = {0};
    RuleNode *tree = NULL;

    assert_int_equal(read_rules(path, &tree, &build), 0);

    assert_int_equal(build.node_count, 16);
    assert_false(build.limit_reached);

    os_remove_rules_list(tree);
}

void test_Rules_OP_ReadRules_limit_mid_rule(void **state)
{
    const char *path = *state;
    w_rule_tree_build_t build = {.node_limit = 10};
    RuleNode *tree = NULL;
    char expected[OS_SIZE_1024];

    // Rule 100104 adds 2 of its 8 nodes: the tree references its RuleInfo and releases it
    expect_limit_error(expected, sizeof(expected), path, 100104, 10, 2, 10);

    assert_int_equal(read_rules(path, &tree, &build), -1);

    assert_true(build.limit_reached);
    assert_int_equal(build.rule_node_count, 2);

    os_remove_rules_list(tree);
}

void test_Rules_OP_ReadRules_limit_before_first_node(void **state)
{
    const char *path = *state;
    w_rule_tree_build_t build = {.node_limit = 8};
    RuleNode *tree = NULL;
    char expected[OS_SIZE_1024];

    // Rule 100104 adds no node: no node references its RuleInfo and the parser releases it
    expect_limit_error(expected, sizeof(expected), path, 100104, 8, 0, 8);

    assert_int_equal(read_rules(path, &tree, &build), -1);

    assert_true(build.limit_reached);
    assert_int_equal(build.rule_node_count, 0);

    os_remove_rules_list(tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_Rules_OP_ReadRules_no_limit, setup_rules_file, teardown_rules_file),
        cmocka_unit_test_setup_teardown(test_Rules_OP_ReadRules_limit_mid_rule, setup_rules_file,
                                        teardown_rules_file),
        cmocka_unit_test_setup_teardown(test_Rules_OP_ReadRules_limit_before_first_node, setup_rules_file,
                                        teardown_rules_file),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
