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
        // Tests os_mark_ruleinfo
        cmocka_unit_test(test_os_mark_ruleinfo_counts_unique),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
