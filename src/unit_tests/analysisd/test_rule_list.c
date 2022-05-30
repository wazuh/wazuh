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

void os_count_rules(RuleNode *node, int *num_rules);
void os_remove_rulenode(RuleNode *node, RuleInfo **rules, int *pos, int *max_size);
void os_remove_ruleinfo(RuleInfo *ruleinfo);
void os_remove_rules_list(RuleNode *node);
int OS_AddChild(RuleInfo *read_rule, RuleNode **r_node, OSList* log_msg);

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
        cmocka_unit_test_setup_teardown(test_os_remove_rules_list_OK, setup_AR, teardown_AR)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
