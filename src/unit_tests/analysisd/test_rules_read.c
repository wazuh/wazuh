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
void w_test_pcre2_wrappers(bool enable);

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

/* First file of the if_matched_group test: source A (group g) and the if_matched_group rules on g.
 * 200 and 201 link by group (implicit if_group); 202 links by level and 203 by if_matched_sid. */
static const char *MATCHED_GROUP_FIRST =
    "<group name=\"base,\">\n"
    "  <rule id=\"1\" level=\"0\">\n"
    "    <match>source</match>\n"
    "    <description>Root</description>\n"
    "  </rule>\n"
    "</group>\n"
    "<group name=\"g,\">\n"
    "  <rule id=\"100\" level=\"3\">\n"
    "    <if_sid>1</if_sid>\n"
    "    <description>Source A</description>\n"
    "  </rule>\n"
    "</group>\n"
    "<group name=\"corr,\">\n"
    "  <rule id=\"200\" level=\"10\" frequency=\"2\" timeframe=\"60\">\n"
    "    <if_matched_group>g</if_matched_group>\n"
    "    <description>Correlation C</description>\n"
    "  </rule>\n"
    "  <rule id=\"201\" level=\"10\" frequency=\"2\" timeframe=\"60\">\n"
    "    <if_matched_group>g</if_matched_group>\n"
    "    <description>Correlation C2</description>\n"
    "  </rule>\n"
    "  <rule id=\"202\" level=\"10\" frequency=\"2\" timeframe=\"60\">\n"
    "    <if_level>3</if_level>\n"
    "    <if_matched_group>g</if_matched_group>\n"
    "    <description>Correlation by level</description>\n"
    "  </rule>\n"
    "  <rule id=\"203\" level=\"10\" frequency=\"2\" timeframe=\"60\">\n"
    "    <if_matched_sid>100</if_matched_sid>\n"
    "    <if_matched_group>g</if_matched_group>\n"
    "    <description>Correlation by sid</description>\n"
    "  </rule>\n"
    "</group>\n";

/* Second file: source B (group g), loaded after the if_matched_group rules */
static const char *MATCHED_GROUP_SECOND =
    "<group name=\"g,\">\n"
    "  <rule id=\"300\" level=\"3\">\n"
    "    <if_sid>1</if_sid>\n"
    "    <description>Source B</description>\n"
    "  </rule>\n"
    "</group>\n";

/* setup/teardown */

static char *write_rules_file(const char *content) {
    char *path;
    os_strdup("/tmp/wazuh_rules_read_test_XXXXXX", path);

    int fd = mkstemp(path);
    if (fd < 0) {
        os_free(path);
        return NULL;
    }

    size_t size = strlen(content);
    if (write(fd, content, size) != (ssize_t)size) {
        close(fd);
        unlink(path);
        os_free(path);
        return NULL;
    }

    close(fd);
    return path;
}

static int setup_matched_group_files(void **state) {
    char **paths;
    os_calloc(2, sizeof(char *), paths);
    // These rules compile real expressions
    w_test_pcre2_wrappers(false);
    paths[0] = write_rules_file(MATCHED_GROUP_FIRST);
    paths[1] = write_rules_file(MATCHED_GROUP_SECOND);
    *state = paths;
    return paths[0] && paths[1] ? 0 : -1;
}

static int teardown_matched_group_files(void **state) {
    char **paths = *state;
    for (int i = 0; i < 2; i++) {
        if (paths[i]) {
            unlink(paths[i]);
            os_free(paths[i]);
        }
    }
    os_free(paths);
    w_test_pcre2_wrappers(true);
    return 0;
}

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

/* First node of the tree whose rule has the given id */
static RuleNode *find_rule(RuleNode *node, int sigid) {
    for (; node != NULL; node = node->next) {
        if (node->ruleinfo->sigid == sigid) {
            return node;
        }
        RuleNode *found = find_rule(node->child, sigid);
        if (found) {
            return found;
        }
    }
    return NULL;
}

static bool has_child(const RuleNode *node, int sigid) {
    for (const RuleNode *child = node->child; child != NULL; child = child->next) {
        if (child->ruleinfo->sigid == sigid) {
            return true;
        }
    }
    return false;
}

void test_w_rules_link_matched_groups_read_two_files(void **state)
{
    char **paths = *state;
    w_rule_tree_build_t build = {0};
    RuleNode *tree = NULL;


    assert_int_equal(read_rules(paths[0], &tree, &build), 0);
    assert_int_equal(read_rules(paths[1], &tree, &build), 0);

    RuleNode *a = find_rule(tree, 100);
    RuleNode *b = find_rule(tree, 300);
    assert_non_null(a);
    assert_non_null(b);

    // Load order and how each if_matched_group rule links
    assert_int_equal(find_rule(tree, 200)->ruleinfo->matched_group_order, 1);
    assert_int_equal(find_rule(tree, 201)->ruleinfo->matched_group_order, 2);
    assert_int_equal(find_rule(tree, 202)->ruleinfo->matched_group_order, 3);
    assert_int_equal(find_rule(tree, 203)->ruleinfo->matched_group_order, 0);
    assert_true(find_rule(tree, 200)->ruleinfo->implicit_if_group);
    assert_false(find_rule(tree, 202)->ruleinfo->implicit_if_group);
    assert_false(find_rule(tree, 203)->ruleinfo->implicit_if_group);

    // When the rules were read, B did not exist yet
    assert_true(has_child(a, 200));
    assert_true(has_child(a, 201));
    assert_false(has_child(b, 200));

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    // B now has both correlations by group and feeds their lists, but not the rules linked by level or sid
    assert_true(has_child(b, 200));
    assert_true(has_child(b, 201));
    assert_false(has_child(b, 202));
    assert_false(has_child(b, 203));

    RuleInfo *c = find_rule(tree, 200)->ruleinfo;
    bool fed = false;
    for (unsigned int i = 0; i < b->ruleinfo->group_prev_matched_sz; i++) {
        fed = fed || b->ruleinfo->group_prev_matched[i] == c->group_search;
    }
    assert_true(fed);

    os_remove_rules_list(tree);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_Rules_OP_ReadRules_no_limit, setup_rules_file, teardown_rules_file),
        cmocka_unit_test_setup_teardown(test_w_rules_link_matched_groups_read_two_files, setup_matched_group_files,
                                        teardown_matched_group_files),
        cmocka_unit_test_setup_teardown(test_Rules_OP_ReadRules_limit_mid_rule, setup_rules_file,
                                        teardown_rules_file),
        cmocka_unit_test_setup_teardown(test_Rules_OP_ReadRules_limit_before_first_node, setup_rules_file,
                                        teardown_rules_file),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
