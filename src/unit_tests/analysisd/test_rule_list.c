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
#include "../../analysisd/cdb/cdb.h"
#include "../../analysisd/analysisd.h"
#include "../../analysisd/rules.h"
#include "../wrappers/wazuh/shared/debug_op_wrappers.h"

void os_count_rules(RuleNode *node, int *num_rules);
void os_remove_rulenode(RuleNode *node, RuleInfo **rules, int *pos, int *max_size);
void os_remove_ruleinfo(RuleInfo *ruleinfo);
void os_remove_rules_list(RuleNode *node);
int OS_AddChild(RuleInfo *read_rule, RuleNode **r_node, OSList* log_msg, w_rule_tree_build_t *build);
RuleNode *_OS_AddRule(RuleNode *_rulenode, RuleInfo *read_rule, w_rule_tree_build_t *build);
bool w_rule_tree_add_node(w_rule_tree_build_t *build, const RuleInfo *read_rule);
void os_mark_ruleinfo(RuleNode *node, bool value, int *changed);

/* helpers */

static RuleInfo *create_rule(int sigid, int level, const char *group) {
    RuleInfo *rule;
    os_calloc(1, sizeof(RuleInfo), rule);
    rule->sigid = sigid;
    rule->level = level;
    os_strdup(group, rule->group);
    os_strdup("rules.xml", rule->file);
    return rule;
}

static RuleNode *create_node(RuleInfo *rule) {
    RuleNode *node;
    os_calloc(1, sizeof(RuleNode), node);
    node->ruleinfo = rule;
    return node;
}

/* Three top-level rules (100, 200 and 300) with level 300 and group "parent" */
static RuleNode *create_parents(void) {
    RuleNode *first = create_node(create_rule(100, 300, "parent,"));
    first->next = create_node(create_rule(200, 300, "parent,"));
    first->next->next = create_node(create_rule(300, 300, "parent,"));
    return first;
}

/* Rule in group "loop" that is also a child of group "loop", as in the ruleset of issue #39930 */
static RuleInfo *create_loop_rule(int sigid) {
    RuleInfo *rule = create_rule(sigid, 3, "loop,");
    os_strdup("loop", rule->if_group);
    return rule;
}

/* setup/teardown */

static int setup_AR(void **state) {
    active_response *ar_info;
    os_calloc(1, sizeof(active_response), ar_info);

    os_strdup("test_ar_name", ar_info->name);
    os_strdup("test_ar_command", ar_info->command);
    os_strdup("test_ar_agent_id", ar_info->agent_id);
    os_strdup("test_ar_rules_id", ar_info->rules_id);
    os_strdup("test_ar_rules_group", ar_info->rules_group);
    os_calloc(1, sizeof(ar_command), ar_info->ar_cmd);
    os_strdup("test_ar_command_name", ar_info->ar_cmd->name);
    os_strdup("test_ar_command_executable", ar_info->ar_cmd->executable);
    os_strdup("test_ar_command_extra_args", ar_info->ar_cmd->extra_args);

    *state = ar_info;
    return OS_SUCCESS;
}

static int teardown_AR(void **state) {
    active_response *ar_info = *state;

    os_free(ar_info->name);
    os_free(ar_info->command);
    os_free(ar_info->agent_id);
    os_free(ar_info->rules_id);
    os_free(ar_info->rules_group);
    os_free(ar_info->ar_cmd->name);
    os_free(ar_info->ar_cmd->executable);
    os_free(ar_info->ar_cmd->extra_args);
    os_free(ar_info->ar_cmd);
    os_free(ar_info);

    return OS_SUCCESS;
}

/* wraps */

void __wrap_OSMatch_FreePattern(OSMatch *reg) {
    return;
}

void __real_OSMatch_FreePattern(OSMatch *reg);

void __wrap_OSRegex_FreePattern(OSRegex *reg) {
    return;
}

void __wrap_os_remove_cdbrules(ListRule **l_rule) {
    os_free(*l_rule);
    return;
}

void __wrap__os_analysisd_add_logmsg(OSList * list, int level, int line, const char * func,
                                    const char * file, char * msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(level);
    check_expected_ptr(list);
    check_expected(formatted_msg);
}


/* tests */

/* os_count_rules */
void test_os_count_rules_no_child(void **state)
{
    RuleNode *node;
    os_calloc(1,sizeof(RuleNode), node);

    int num_rules = 0;

    os_count_rules(node, &num_rules);

    os_free(node);

}

void test_os_count_rules_child(void **state)
{
    RuleNode *node;
    os_calloc(1, sizeof(RuleNode), node);
    os_calloc(1, sizeof(OSDecoderNode), node->child);

    int num_rules = 0;

    os_count_rules(node, &num_rules);

    os_free(node->child);
    os_free(node);

}

/* os_remove_rulenode */
void test_os_remove_rulenode_no_child(void **state)
{
    int pos = 0;
    int max_size = 2;

    RuleNode * node;
    os_calloc(1, sizeof(RuleNode), node);
    os_calloc(1, sizeof(RuleInfo), node->ruleinfo);
    node->ruleinfo->internal_saving = false;

    RuleInfo **rules_info;
    os_calloc(1, sizeof(OSDecoderInfo *), rules_info);

    int num_decoders = 0;

    os_remove_rulenode(node, rules_info, &pos, &max_size);

    os_free(rules_info[0]);
    os_free(rules_info);

}

void test_os_remove_rulenode_child(void **state)
{
    int pos = 0;
    int max_size = 2;

    RuleNode * node;
    os_calloc(1, sizeof(RuleNode), node);
    os_calloc(1, sizeof(RuleNode), node->child);
    os_calloc(1, sizeof(RuleInfo), node->ruleinfo);
    os_calloc(1, sizeof(RuleInfo), node->child->ruleinfo);
    node->ruleinfo->internal_saving = false;
    node->child->ruleinfo->internal_saving = false;

    RuleInfo **rules_info;
    os_calloc(2, sizeof(RuleInfo *), rules_info);

    int num_decoders = 0;

    os_remove_rulenode(node, rules_info, &pos, &max_size);

    os_free(rules_info[0]);
    os_free(rules_info[1]);
    os_free(rules_info);

}

/* os_remove_ruleinfo */
void test_os_remove_ruleinfo_NULL(void **state)
{
    RuleInfo *ruleinfo = NULL;

    os_remove_ruleinfo(ruleinfo);

}

void test_os_remove_ruleinfo_OK(void **state)
{
    RuleInfo *ruleinfo;
    os_calloc(1, sizeof(RuleInfo), ruleinfo);

    os_calloc(2, sizeof(char*), ruleinfo->ignore_fields);
    os_strdup("test_ignore_fields", ruleinfo->ignore_fields[0]);

    os_calloc(2, sizeof(char*), ruleinfo->ckignore_fields);
    os_strdup("test_ckignore_felds", ruleinfo->ckignore_fields[0]);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    w_expression_add_osip(&ruleinfo->srcip, "0.0.0.0");

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);
    w_expression_add_osip(&ruleinfo->dstip, "0.0.0.0");

    os_calloc(2, sizeof(FieldInfo*), ruleinfo->fields);
    os_calloc(1, sizeof(FieldInfo), ruleinfo->fields[0]);
    os_strdup("test_name", ruleinfo->fields[0]->name);
    os_calloc(1, sizeof(OSRegex), ruleinfo->fields[0]->regex);

    os_calloc(1, sizeof(RuleInfoDetail), ruleinfo->info_details);

    os_calloc(2, sizeof(active_response*), ruleinfo->ar);
    ruleinfo->ar[0] = *state;
    os_calloc(1, sizeof(ListRule), ruleinfo->lists);

    os_calloc(2, sizeof(char*), ruleinfo->same_fields);
    os_strdup("test_same_fields", ruleinfo->same_fields[0]);

    os_calloc(2, sizeof(char*), ruleinfo->not_same_fields);
    os_strdup("test_not_same_fields", ruleinfo->not_same_fields[0]);

    os_calloc(2, sizeof(char*), ruleinfo->mitre_id);
    os_strdup("test_mitre_id", ruleinfo->mitre_id[0]);

    w_calloc_expression_t(&ruleinfo->match, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->regex, EXP_TYPE_OSREGEX);
    w_calloc_expression_t(&ruleinfo->dstgeoip, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->srcport, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->dstport, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->user, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->url, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->id, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->status, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->hostname, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->program_name, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->data, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->extra_data, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->location, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->system_name, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&ruleinfo->protocol, EXP_TYPE_OSMATCH);

    os_calloc(1, sizeof(OSRegex), ruleinfo->if_matched_regex);
    os_calloc(1, sizeof(OSMatch), ruleinfo->if_matched_group);

    os_remove_ruleinfo(ruleinfo);
}

/* os_remove_rules_list */
void test_os_remove_rules_list_OK(void **state)
{
    RuleNode *node;
    os_calloc(1,sizeof(RuleNode), node);

    os_calloc(1, sizeof(RuleInfo), node->ruleinfo);

    os_calloc(2, sizeof(char*), node->ruleinfo->ignore_fields);
    os_strdup("test_ignore_fields", node->ruleinfo->ignore_fields[0]);

    os_calloc(2, sizeof(char*), node->ruleinfo->ckignore_fields);
    os_strdup("test_ckignore_felds", node->ruleinfo->ckignore_fields[0]);

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    w_expression_add_osip(&node->ruleinfo->srcip, "0.0.0.0");

    expect_any(__wrap_OS_IsValidIP, ip_address);
    expect_any(__wrap_OS_IsValidIP, final_ip);
    will_return(__wrap_OS_IsValidIP, -1);

    w_expression_add_osip(&node->ruleinfo->dstip, "0.0.0.0");

    os_calloc(2, sizeof(FieldInfo*), node->ruleinfo->fields);
    os_calloc(1, sizeof(FieldInfo), node->ruleinfo->fields[0]);
    os_strdup("test_name", node->ruleinfo->fields[0]->name);
    os_calloc(1, sizeof(OSRegex), node->ruleinfo->fields[0]->regex);

    os_calloc(1, sizeof(RuleInfoDetail), node->ruleinfo->info_details);

    os_calloc(2, sizeof(active_response*), node->ruleinfo->ar);
    node->ruleinfo->ar[0] = *state;
    os_calloc(1, sizeof(ListRule), node->ruleinfo->lists);

    os_calloc(2, sizeof(char*), node->ruleinfo->same_fields);
    os_strdup("test_same_fields", node->ruleinfo->same_fields[0]);

    os_calloc(2, sizeof(char*), node->ruleinfo->not_same_fields);
    os_strdup("test_same_fields", node->ruleinfo->not_same_fields[0]);

    os_calloc(2, sizeof(char*), node->ruleinfo->mitre_id);
    os_strdup("test_mitre_id", node->ruleinfo->mitre_id[0]);

    w_calloc_expression_t(&node->ruleinfo->match, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->regex, EXP_TYPE_OSREGEX);
    w_calloc_expression_t(&node->ruleinfo->dstgeoip, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->srcport, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->dstport, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->user, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->url, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->id, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->status, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->hostname, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->program_name, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->data, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->extra_data, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->location, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->system_name, EXP_TYPE_OSMATCH);
    w_calloc_expression_t(&node->ruleinfo->protocol, EXP_TYPE_OSMATCH);

    os_calloc(1, sizeof(OSRegex), node->ruleinfo->if_matched_regex);
    os_calloc(1, sizeof(OSMatch), node->ruleinfo->if_matched_group);

    os_remove_rules_list(node);

}

/* w_rule_tree_add_node */
void test_w_rule_tree_add_node_null_build(void **state)
{
    assert_true(w_rule_tree_add_node(NULL, NULL));
}

void test_w_rule_tree_add_node_no_limit(void **state)
{
    w_rule_tree_build_t build = {0};

    for (int i = 0; i < 3; i++) {
        assert_true(w_rule_tree_add_node(&build, NULL));
    }

    assert_int_equal(build.node_count, 3);
    assert_int_equal(build.rule_node_count, 3);
    assert_false(build.limit_reached);
}

void test_w_rule_tree_add_node_limit(void **state)
{
    w_rule_tree_build_t build = {.node_limit = 2};

    assert_true(w_rule_tree_add_node(&build, NULL));
    assert_true(w_rule_tree_add_node(&build, NULL));
    assert_false(w_rule_tree_add_node(&build, NULL));

    assert_int_equal(build.node_count, 2);
    assert_int_equal(build.rule_node_count, 2);
    assert_true(build.limit_reached);

    // Once reached, the build stays stopped
    build.node_limit = 0;
    assert_false(w_rule_tree_add_node(&build, NULL));
    assert_int_equal(build.node_count, 2);
}

void test_w_rule_tree_add_node_warning_on_crossing(void **state)
{
    OSList list_msg = {0};
    w_rule_tree_build_t build = {.node_warning = 2, .log_msg = &list_msg};
    RuleInfo *rule = create_rule(100, 300, "parent,");

    // Reaching the threshold is not exceeding it
    assert_true(w_rule_tree_add_node(&build, rule));
    assert_true(w_rule_tree_add_node(&build, rule));
    assert_false(build.warning_emitted);

    // The node that exceeds it is reported immediately, to the log and to the requester
    expect_string(__wrap__mwarn, formatted_msg,
                  "(7621): The rule tree exceeded the warning threshold of 2 nodes while adding rule '100' from 'rules.xml'.");
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7621): The rule tree exceeded the warning threshold of 2 nodes while adding rule '100' from 'rules.xml'.");

    assert_true(w_rule_tree_add_node(&build, rule));
    assert_true(build.warning_emitted);

    // Only once per build
    assert_true(w_rule_tree_add_node(&build, rule));
    assert_int_equal(build.node_count, 4);

    os_remove_ruleinfo(rule);
}

void test_w_rule_tree_add_node_warning_without_log_msg(void **state)
{
    w_rule_tree_build_t build = {.node_warning = 1, .node_count = 1};
    RuleInfo *rule = create_rule(100, 300, "parent,");

    // Without a requester list, the warning only goes to the log
    expect_string(__wrap__mwarn, formatted_msg,
                  "(7621): The rule tree exceeded the warning threshold of 1 nodes while adding rule '100' from 'rules.xml'.");

    assert_true(w_rule_tree_add_node(&build, rule));
    assert_true(build.warning_emitted);

    os_remove_ruleinfo(rule);
}

/* _OS_AddRule */
void test__OS_AddRule_limit_reached(void **state)
{
    w_rule_tree_build_t build = {.node_limit = 1, .node_count = 1};
    RuleInfo *rule = create_rule(100, 300, "parent,");

    assert_null(_OS_AddRule(NULL, rule, &build));

    assert_true(build.limit_reached);
    assert_int_equal(build.node_count, 1);
    assert_int_equal(build.rule_node_count, 0);

    os_remove_ruleinfo(rule);
}

/* OS_AddRule */
void test_OS_AddRule_limit_reached(void **state)
{
    w_rule_tree_build_t build = {.node_limit = 1};
    RuleNode *list = NULL;
    RuleInfo *first = create_rule(1, 0, "root,");
    RuleInfo *second = create_rule(2, 0, "root,");

    assert_int_equal(OS_AddRule(first, &list, &build), 0);
    assert_non_null(list);
    assert_ptr_equal(list->ruleinfo, first);

    assert_int_equal(OS_AddRule(second, &list, &build), RULE_TREE_LIMIT_REACHED);
    assert_null(list->next);
    assert_int_equal(build.node_count, 1);

    os_remove_ruleinfo(second);
    os_remove_rules_list(list);
}

/* OS_AddChild */
void test_OS_AddChild_if_group_no_build(void **state)
{
    RuleNode *tree = create_parents();
    RuleInfo *child = create_rule(400, 500, "child,");
    os_strdup("parent", child->if_group);

    assert_int_equal(OS_AddChild(child, &tree, NULL, NULL), 0);

    assert_ptr_equal(tree->child->ruleinfo, child);
    assert_ptr_equal(tree->next->child->ruleinfo, child);
    assert_ptr_equal(tree->next->next->child->ruleinfo, child);

    // The child RuleInfo appears in three nodes and must be released once
    os_remove_rules_list(tree);
}

void test_OS_AddChild_if_group_limit_mid_rule(void **state)
{
    w_rule_tree_build_t build = {.node_limit = 4, .node_count = 3};
    RuleNode *tree = create_parents();
    RuleInfo *child = create_rule(400, 500, "child,");
    os_strdup("parent", child->if_group);

    assert_int_equal(OS_AddChild(child, &tree, NULL, &build), RULE_TREE_LIMIT_REACHED);

    assert_ptr_equal(tree->child->ruleinfo, child);
    assert_null(tree->next->child);
    assert_null(tree->next->next->child);
    assert_int_equal(build.node_count, 4);
    assert_int_equal(build.rule_node_count, 1);

    // The tree references the child RuleInfo: it is released with the tree
    os_remove_rules_list(tree);
}

void test_OS_AddChild_if_sid_limit_mid_rule(void **state)
{
    w_rule_tree_build_t build = {.node_limit = 4, .node_count = 3};
    RuleNode *tree = create_parents();
    RuleInfo *child = create_rule(400, 500, "child,");
    os_strdup("100, 200", child->if_sid);

    // The second if_sid entry is not processed after the limit is reached
    assert_int_equal(OS_AddChild(child, &tree, NULL, &build), RULE_TREE_LIMIT_REACHED);

    assert_ptr_equal(tree->child->ruleinfo, child);
    assert_null(tree->next->child);
    assert_int_equal(build.rule_node_count, 1);

    os_remove_rules_list(tree);
}

void test_OS_AddChild_if_level_limit_mid_rule(void **state)
{
    w_rule_tree_build_t build = {.node_limit = 5, .node_count = 3};
    RuleNode *tree = create_parents();
    RuleInfo *child = create_rule(400, 500, "child,");
    os_strdup("3", child->if_level);

    assert_int_equal(OS_AddChild(child, &tree, NULL, &build), RULE_TREE_LIMIT_REACHED);

    assert_ptr_equal(tree->child->ruleinfo, child);
    assert_ptr_equal(tree->next->child->ruleinfo, child);
    assert_null(tree->next->next->child);
    assert_int_equal(build.rule_node_count, 2);

    os_remove_rules_list(tree);
}

void test_OS_AddChild_warning_then_limit_in_same_rule(void **state)
{
    OSList list_msg = {0};
    w_rule_tree_build_t build = {.node_warning = 4, .node_limit = 5, .node_count = 3, .log_msg = &list_msg};
    RuleNode *tree = create_parents();
    RuleInfo *child = create_rule(400, 500, "child,");
    os_strdup("parent", child->if_group);

    // The rule exceeds the warning threshold before reaching the limit: the warning is not lost
    expect_string(__wrap__mwarn, formatted_msg,
                  "(7621): The rule tree exceeded the warning threshold of 4 nodes while adding rule '400' from 'rules.xml'.");
    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_WARNING);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(7621): The rule tree exceeded the warning threshold of 4 nodes while adding rule '400' from 'rules.xml'.");

    assert_int_equal(OS_AddChild(child, &tree, NULL, &build), RULE_TREE_LIMIT_REACHED);

    assert_true(build.warning_emitted);
    assert_int_equal(build.node_count, 5);
    assert_int_equal(build.rule_node_count, 2);

    os_remove_rules_list(tree);
}

void test_OS_AddChild_limit_before_first_node(void **state)
{
    w_rule_tree_build_t build = {.node_limit = 3, .node_count = 3};
    RuleNode *tree = create_parents();
    RuleInfo *child = create_rule(400, 500, "child,");
    os_strdup("parent", child->if_group);

    // The limit stops the rule: no "group not found" warning is logged
    assert_int_equal(OS_AddChild(child, &tree, NULL, &build), RULE_TREE_LIMIT_REACHED);

    assert_null(tree->child);
    assert_null(tree->next->child);
    assert_int_equal(build.rule_node_count, 0);

    // No node references the child RuleInfo: the caller releases it
    os_remove_ruleinfo(child);
    os_remove_rules_list(tree);
}

void test_OS_AddChild_if_group_self_reference_doubles(void **state)
{
    w_rule_tree_build_t build = {0};
    RuleNode *tree = create_node(create_rule(100, 3, "loop,"));

    // Each rule is added under the root and under every node of the previous rules
    for (int i = 0; i < 5; i++) {
        build.rule_node_count = 0;
        assert_int_equal(OS_AddChild(create_loop_rule(101 + i), &tree, NULL, &build), 0);
        assert_int_equal(build.rule_node_count, 1 << i);
    }

    assert_int_equal(build.node_count, 31);

    os_remove_rules_list(tree);
}

void test_OS_AddChild_if_group_self_reference_limit_in_recursion(void **state)
{
    w_rule_tree_build_t build = {0};
    RuleNode *tree = create_node(create_rule(100, 3, "loop,"));

    for (int i = 0; i < 3; i++) {
        build.rule_node_count = 0;
        assert_int_equal(OS_AddChild(create_loop_rule(101 + i), &tree, NULL, &build), 0);
    }
    assert_int_equal(build.node_count, 7);

    // Rule 104 needs 8 nodes: the limit stops it three levels deep, under 100 > 101 > 102 > 103
    build.node_limit = 10;
    build.rule_node_count = 0;
    RuleInfo *rule = create_loop_rule(104);

    assert_int_equal(OS_AddChild(rule, &tree, NULL, &build), RULE_TREE_LIMIT_REACHED);

    assert_int_equal(build.node_count, 10);
    assert_int_equal(build.rule_node_count, 3);

    // Tree before rule 104: 100 > [101 > [102 > [103], 103], 102 > [103], 103]
    RuleNode *r101 = tree->child;
    RuleNode *r101_r102 = r101->child;
    RuleNode *r101_r102_r103 = r101_r102->child;
    RuleNode *r101_r103 = r101_r102->next;
    RuleNode *r102 = r101->next;

    // Rule 104 was added under 100, 100 > 101 and 100 > 101 > 102
    assert_ptr_equal(r102->next->next->ruleinfo, rule);
    assert_ptr_equal(r101_r103->next->ruleinfo, rule);
    assert_ptr_equal(r101_r102_r103->next->ruleinfo, rule);

    // The node under 100 > 101 > 102 > 103 was refused, and the rest of the tree was not visited
    assert_null(r101_r102_r103->child);
    assert_null(r101_r103->child);
    assert_null(r102->child->next);

    // The tree references rule 104: it is released with the tree
    os_remove_rules_list(tree);
}

/* os_mark_ruleinfo */
void test_os_mark_ruleinfo_counts_unique(void **state)
{
    RuleNode *tree = create_parents();
    RuleInfo *child = create_rule(400, 500, "child,");
    os_strdup("parent", child->if_group);
    assert_int_equal(OS_AddChild(child, &tree, NULL, NULL), 0);

    int marked = 0;
    int cleared = 0;

    // Six nodes, four unique RuleInfo
    os_mark_ruleinfo(tree, true, &marked);
    os_mark_ruleinfo(tree, false, &cleared);

    assert_int_equal(marked, 4);
    assert_int_equal(cleared, 4);
    assert_false(child->internal_saving);

    os_remove_rules_list(tree);
}

/* OS_MarkGroup */
static void init_matched_group_rule(RuleInfo *rule, const char *group, OSList *group_search) {
    os_calloc(1, sizeof(OSMatch), rule->if_matched_group);
    assert_true(OSMatch_Compile(group, rule->if_matched_group, 0));
    rule->group_search = group_search;
}

static void free_matched_group_rule(RuleInfo *rule) {
    __real_OSMatch_FreePattern(rule->if_matched_group);
    os_free(rule->if_matched_group);
}

void test_OS_MarkGroup_rule_with_two_parents(void **state)
{
    /* Rule 400 is a child of both 100 and 200, so the tree holds two nodes with the same RuleInfo.
     * Rule 500 only hangs from the second node of 400. */
    RuleNode *tree = create_parents();
    RuleInfo *multi_parent = create_rule(400, 5, "authentication_failed,");
    RuleInfo *grandchild = create_rule(500, 5, "authentication_failed,");

    tree->child = create_node(multi_parent);
    tree->next->child = create_node(multi_parent);
    tree->next->child->child = create_node(grandchild);

    OSList list_first = {0};
    OSList list_second = {0};
    RuleInfo first_correlation = {0};
    RuleInfo second_correlation = {0};
    init_matched_group_rule(&first_correlation, "authentication_failed", &list_first);
    init_matched_group_rule(&second_correlation, "authentication_failed", &list_second);

    assert_int_equal(OS_MarkGroup(tree, &first_correlation), 0);
    assert_int_equal(OS_MarkGroup(tree, &second_correlation), 0);

    // Each correlation list is registered once, even though rule 400 is reached twice
    assert_int_equal(multi_parent->group_prev_matched_sz, 2);
    assert_ptr_equal(multi_parent->group_prev_matched[0], &list_first);
    assert_ptr_equal(multi_parent->group_prev_matched[1], &list_second);
    assert_null(multi_parent->group_prev_matched[2]);

    // The children of the second node are still visited
    assert_int_equal(grandchild->group_prev_matched_sz, 2);
    assert_ptr_equal(grandchild->group_prev_matched[0], &list_first);
    assert_ptr_equal(grandchild->group_prev_matched[1], &list_second);
    assert_null(grandchild->group_prev_matched[2]);

    // Rules out of the group are not marked
    assert_null(tree->ruleinfo->group_prev_matched);

    free_matched_group_rule(&first_correlation);
    free_matched_group_rule(&second_correlation);
    os_remove_rules_list(tree);
}
/* w_rules_link_matched_groups. Levels are scaled by 100, as they are before _setlevels() */

/* An if_matched_group rule on `pattern`, in group `group`, with the given load order */
static RuleInfo *create_correlation(int sigid, int level, const char *group, const char *pattern, unsigned int order,
                                    bool implicit) {
    RuleInfo *rule = create_rule(sigid, level, group);
    os_calloc(1, sizeof(OSMatch), rule->if_matched_group);
    assert_true(OSMatch_Compile(pattern, rule->if_matched_group, 0));
    rule->group_search = OSList_Create();
    rule->matched_group_order = order;
    rule->implicit_if_group = implicit;
    return rule;
}

/* OSMatch_FreePattern is wrapped as a no-op in this binary: release the compiled pattern before the tree */
static void release_tree(RuleNode *tree, RuleInfo **correlations, size_t count) {
    for (size_t i = 0; i < count; i++) {
        __real_OSMatch_FreePattern(correlations[i]->if_matched_group);
    }
    os_remove_rules_list(tree);
}

static int count_nodes(const RuleNode *node) {
    int count = 0;
    for (; node != NULL; node = node->next) {
        count += 1 + count_nodes(node->child);
    }
    return count;
}

/* How many children of node point to rule */
static int count_children(const RuleNode *node, const RuleInfo *rule) {
    int count = 0;
    for (const RuleNode *child = node->child; child != NULL; child = child->next) {
        count += child->ruleinfo == rule;
    }
    return count;
}

/* The child of node that points to rule */
static RuleNode *find_child(const RuleNode *node, const RuleInfo *rule) {
    for (RuleNode *child = node->child; child != NULL; child = child->next) {
        if (child->ruleinfo == rule) {
            return child;
        }
    }
    return NULL;
}

static bool has_list(const RuleInfo *rule, const OSList *list) {
    for (unsigned int i = 0; i < rule->group_prev_matched_sz; i++) {
        if (rule->group_prev_matched[i] == list) {
            return true;
        }
    }
    return false;
}

/* A (group g) loaded before the correlation C, which hangs from it; B (group g) loaded after C */
static RuleNode *create_later_source_tree(RuleInfo **c, RuleInfo **b, bool implicit) {
    RuleInfo *a = create_rule(10, 300, "g,");
    *c = create_correlation(900, 1000, "corr,", "g", 1, implicit);
    *b = create_rule(20, 300, "g,");

    RuleNode *tree = create_node(a);
    tree->child = create_node(*c);
    tree->next = create_node(*b);
    return tree;
}

void test_w_rules_link_matched_groups_later_source(void **state)
{
    RuleInfo *c, *b;
    RuleNode *tree = create_later_source_tree(&c, &b, true);
    w_rule_tree_build_t build = {.node_limit = 100};

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    // C now hangs from B exactly once, and B feeds its list
    assert_int_equal(count_children(tree->next, c), 1);
    assert_true(has_list(b, c->group_search));
    assert_int_equal(count_children(tree, c), 1);
    assert_int_equal(build.node_count, 1);

    release_tree(tree, &c, 1);
}

void test_w_rules_link_matched_groups_idempotent(void **state)
{
    RuleInfo *c, *b;
    RuleNode *tree = create_later_source_tree(&c, &b, true);
    w_rule_tree_build_t build = {.node_limit = 100};

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);
    int nodes = count_nodes(tree);
    unsigned int lists = b->group_prev_matched_sz;

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);
    assert_int_equal(count_nodes(tree), nodes);
    assert_int_equal(b->group_prev_matched_sz, lists);
    assert_int_equal(count_children(tree->next, c), 1);

    release_tree(tree, &c, 1);
}

void test_w_rules_link_matched_groups_explicit_if_group(void **state)
{
    RuleInfo *c, *b;
    RuleNode *tree = create_later_source_tree(&c, &b, false);
    w_rule_tree_build_t build = {.node_limit = 100};

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    // An explicit if_group keeps its parents: B only feeds the list
    assert_true(has_list(b, c->group_search));
    assert_null(tree->next->child);
    assert_int_equal(build.node_count, 0);

    release_tree(tree, &c, 1);
}

void test_w_rules_link_matched_groups_two_parent_source(void **state)
{
    // B (group g) is a child of P1 and of P2: two nodes, one RuleInfo
    RuleInfo *a = create_rule(10, 300, "g,");
    RuleInfo *c = create_correlation(900, 1000, "corr,", "g", 1, true);
    RuleInfo *b = create_rule(20, 300, "g,");
    RuleNode *tree = create_node(a);
    tree->child = create_node(c);
    tree->next = create_node(create_rule(30, 300, "p,"));
    tree->next->child = create_node(b);
    tree->next->next = create_node(create_rule(40, 300, "p,"));
    tree->next->next->child = create_node(b);
    w_rule_tree_build_t build = {.node_limit = 100};

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    assert_int_equal(count_children(tree->next->child, c), 1);
    assert_int_equal(count_children(tree->next->next->child, c), 1);
    assert_int_equal(b->group_prev_matched_sz, 1);

    release_tree(tree, &c, 1);
}

void test_w_rules_link_matched_groups_self_and_descendants(void **state)
{
    // C is in group g itself and has a child D in group g
    RuleInfo *a = create_rule(10, 300, "g,");
    RuleInfo *c = create_correlation(900, 1000, "g,", "g", 1, true);
    RuleInfo *d = create_rule(910, 300, "g,");
    RuleNode *tree = create_node(a);
    tree->child = create_node(c);
    tree->child->child = create_node(d);
    w_rule_tree_build_t build = {.node_limit = 100};

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    // Nothing hangs from C nor from its descendants, and A keeps a single C
    assert_int_equal(count_children(tree->child, c), 0);
    assert_null(tree->child->child->child);
    assert_int_equal(count_children(tree, c), 1);
    assert_int_equal(build.node_count, 0);

    release_tree(tree, &c, 1);
}

void test_w_rules_link_matched_groups_limit_reached(void **state)
{
    /* C1 links B (one node), then C2 hits the limit: the message counts only the nodes added by C2 */
    RuleInfo *c1, *b;
    RuleNode *tree = create_later_source_tree(&c1, &b, true);
    RuleInfo *c2 = create_correlation(902, 1000, "corr2,", "g", 2, true);
    tree->child->next = create_node(c2);
    OSList list_msg = {0};
    w_rule_tree_build_t build = {.node_count = 5, .node_limit = 6};

    expect_value(__wrap__os_analysisd_add_logmsg, level, LOGLEVEL_ERROR);
    expect_value(__wrap__os_analysisd_add_logmsg, list, &list_msg);
    expect_string(__wrap__os_analysisd_add_logmsg, formatted_msg,
                  "(5108): Rule '902' in 'rules.xml' exceeds the rule tree node limit (6 nodes in the tree, 0 added by this "
                  "rule, limit 6). Ruleset loading aborted.");

    assert_int_equal(w_rules_link_matched_groups(tree, &build, &list_msg), RULE_TREE_LIMIT_REACHED);
    assert_int_equal(count_children(tree->next, c1), 1);
    assert_int_equal(count_children(tree->next, c2), 0);

    RuleInfo *correlations[] = {c1, c2};
    release_tree(tree, correlations, 2);
}

void test_w_rules_link_matched_groups_chained_correlations(void **state)
{
    /* C1 (load order 1, group g) and C2 (load order 2), both on g and with the same level. A was loaded before both,
     * so a load built A -> C1 -> C2 and A -> C2. B was loaded after both. Z is visited first, so the tree walk finds
     * C2 before C1: the load order must win. */
    RuleInfo *c1 = create_correlation(901, 1000, "g,", "g", 1, true);
    RuleInfo *c2 = create_correlation(902, 1000, "corr2,", "g", 2, true);
    RuleInfo *a = create_rule(10, 300, "g,");
    RuleInfo *b = create_rule(20, 300, "g,");
    RuleNode *tree = create_node(create_rule(5, 300, "z,"));
    tree->child = create_node(c2);
    tree->next = create_node(a);
    tree->next->child = create_node(c1);
    tree->next->child->next = create_node(c2);
    tree->next->child->child = create_node(c2);
    tree->next->next = create_node(b);
    RuleNode *b_node = tree->next->next;
    w_rule_tree_build_t build = {.node_limit = 100};

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    // B -> C1 -> C2 and B -> C2, with C1 first among the children of B
    assert_non_null(b_node->child);
    assert_ptr_equal(b_node->child->ruleinfo, c1);
    assert_non_null(b_node->child->next);
    assert_ptr_equal(b_node->child->next->ruleinfo, c2);
    assert_null(b_node->child->next->next);
    assert_int_equal(count_children(find_child(b_node, c1), c2), 1);

    // A second pass changes nothing
    int nodes = count_nodes(tree);
    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);
    assert_int_equal(count_nodes(tree), nodes);

    RuleInfo *correlations[] = {c1, c2};
    release_tree(tree, correlations, 2);
}

void test_w_rules_link_matched_groups_null_build(void **state)
{
    RuleInfo *c, *b;
    RuleNode *tree = create_later_source_tree(&c, &b, true);

    assert_int_equal(w_rules_link_matched_groups(tree, NULL, NULL), 0);

    assert_int_equal(count_children(tree->next, c), 1);
    assert_true(has_list(b, c->group_search));

    release_tree(tree, &c, 1);
}

void test_w_rules_link_matched_groups_mutually_matching(void **state)
{
    /* C1 (order 1) and C2 (order 2) are both in group g and correlate on g. S was loaded before both: a load built
     * S -> C1 -> C2 and S -> C2, and X (group g) is a child of C2. Nothing may be added: C1 never goes below C2. */
    RuleInfo *c1 = create_correlation(901, 1200, "g,", "g", 1, true);
    RuleInfo *c2 = create_correlation(902, 1400, "g,", "g", 2, true);
    RuleInfo *s_rule = create_rule(10, 300, "g,");
    RuleInfo *x = create_rule(920, 300, "g,");
    RuleNode *tree = create_node(s_rule);
    tree->child = create_node(c2);
    tree->child->child = create_node(x);
    tree->child->next = create_node(c1);
    tree->child->next->child = create_node(c2);
    w_rule_tree_build_t build = {.node_limit = 100};
    int nodes = count_nodes(tree);

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    assert_int_equal(count_nodes(tree), nodes);
    assert_null(tree->child->child->child);
    assert_int_equal(count_children(tree->child, c1), 0);

    RuleInfo *correlations[] = {c1, c2};
    release_tree(tree, correlations, 2);
}

void test_w_rules_link_matched_groups_mutually_matching_explicit_later(void **state)
{
    /* As above, but the later C2 links by level (explicit): its nodes and their subtrees are vetoed all the same */
    RuleInfo *c1 = create_correlation(901, 1200, "g,", "g", 1, true);
    RuleInfo *c2 = create_correlation(902, 1400, "g,", "g", 2, false);
    RuleInfo *s_rule = create_rule(10, 300, "g,");
    RuleInfo *x = create_rule(920, 300, "g,");
    RuleNode *tree = create_node(s_rule);
    tree->child = create_node(c2);
    tree->child->child = create_node(x);
    tree->child->next = create_node(c1);
    w_rule_tree_build_t build = {.node_limit = 100};
    int nodes = count_nodes(tree);

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    assert_int_equal(count_nodes(tree), nodes);
    assert_int_equal(count_children(tree->child, c1), 0);
    assert_null(tree->child->child->child);

    RuleInfo *correlations[] = {c1, c2};
    release_tree(tree, correlations, 2);
}

void test_w_rules_link_matched_groups_source_between_correlations(void **state)
{
    /* C1 (order 1) and C2 (order 2) have the same level. A was loaded before C1, S between C1 and C2: a load hung
     * C2 from S. The late C1 goes after the sibling of the same level that S already has. */
    RuleInfo *c1 = create_correlation(901, 1000, "corr1,", "g", 1, true);
    RuleInfo *c2 = create_correlation(902, 1000, "corr2,", "g", 2, true);
    RuleInfo *a = create_rule(10, 300, "g,");
    RuleInfo *s_rule = create_rule(20, 300, "g,");
    RuleNode *tree = create_node(a);
    tree->child = create_node(c1);
    tree->child->next = create_node(c2);
    tree->next = create_node(s_rule);
    tree->next->child = create_node(c2);
    w_rule_tree_build_t build = {.node_limit = 100};

    assert_int_equal(w_rules_link_matched_groups(tree, &build, NULL), 0);

    RuleNode *s_node = tree->next;
    assert_ptr_equal(s_node->child->ruleinfo, c2);
    assert_non_null(s_node->child->next);
    assert_ptr_equal(s_node->child->next->ruleinfo, c1);
    assert_null(s_node->child->next->next);

    RuleInfo *correlations[] = {c1, c2};
    release_tree(tree, correlations, 2);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_count_rules
        cmocka_unit_test(test_os_count_rules_no_child),
        cmocka_unit_test(test_os_count_rules_child),
        // Tests os_remove_rulenode
        cmocka_unit_test(test_os_remove_rulenode_no_child),
        cmocka_unit_test(test_os_remove_rulenode_child),
        // Tests os_remove_ruleinfo
        cmocka_unit_test(test_os_remove_ruleinfo_NULL),
        cmocka_unit_test_setup_teardown(test_os_remove_ruleinfo_OK, setup_AR, teardown_AR),
        // Tests os_remove_rules_list
        cmocka_unit_test_setup_teardown(test_os_remove_rules_list_OK, setup_AR, teardown_AR),
        // Tests w_rule_tree_add_node
        cmocka_unit_test(test_w_rule_tree_add_node_null_build),
        cmocka_unit_test(test_w_rule_tree_add_node_no_limit),
        cmocka_unit_test(test_w_rule_tree_add_node_limit),
        cmocka_unit_test(test_w_rule_tree_add_node_warning_on_crossing),
        cmocka_unit_test(test_w_rule_tree_add_node_warning_without_log_msg),
        // Tests _OS_AddRule
        cmocka_unit_test(test__OS_AddRule_limit_reached),
        // Tests OS_AddRule
        cmocka_unit_test(test_OS_AddRule_limit_reached),
        // Tests OS_AddChild
        cmocka_unit_test(test_OS_AddChild_if_group_no_build),
        cmocka_unit_test(test_OS_AddChild_if_group_limit_mid_rule),
        cmocka_unit_test(test_OS_AddChild_if_sid_limit_mid_rule),
        cmocka_unit_test(test_OS_AddChild_if_level_limit_mid_rule),
        cmocka_unit_test(test_OS_AddChild_warning_then_limit_in_same_rule),
        cmocka_unit_test(test_OS_AddChild_limit_before_first_node),
        cmocka_unit_test(test_OS_AddChild_if_group_self_reference_doubles),
        cmocka_unit_test(test_OS_AddChild_if_group_self_reference_limit_in_recursion),
        // Tests os_mark_ruleinfo
        cmocka_unit_test(test_os_mark_ruleinfo_counts_unique),
        // Tests OS_MarkGroup
        cmocka_unit_test(test_OS_MarkGroup_rule_with_two_parents),
        // Tests w_rules_link_matched_groups
        cmocka_unit_test(test_w_rules_link_matched_groups_later_source),
        cmocka_unit_test(test_w_rules_link_matched_groups_idempotent),
        cmocka_unit_test(test_w_rules_link_matched_groups_explicit_if_group),
        cmocka_unit_test(test_w_rules_link_matched_groups_two_parent_source),
        cmocka_unit_test(test_w_rules_link_matched_groups_self_and_descendants),
        cmocka_unit_test(test_w_rules_link_matched_groups_limit_reached),
        cmocka_unit_test(test_w_rules_link_matched_groups_chained_correlations),
        cmocka_unit_test(test_w_rules_link_matched_groups_null_build),
        cmocka_unit_test(test_w_rules_link_matched_groups_mutually_matching),
        cmocka_unit_test(test_w_rules_link_matched_groups_mutually_matching_explicit_later),
        cmocka_unit_test(test_w_rules_link_matched_groups_source_between_correlations),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
