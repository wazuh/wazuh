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

/* Free_Eventinfo against a wrapped OSList_DeleteThisNode, to check how the lists are blocked while the
 * nodes of an event are removed. test_eventinfo_free.c covers the same function on real lists. */

/* Wrappers */

void __wrap_OSList_DeleteThisNode(OSList *list, OSListNode *thisnode) {
    check_expected_ptr(list);
    check_expected_ptr(thisnode);

    /* No search may walk a list while one of its nodes is being removed */
    assert_int_equal(list->pending_remove, 1);
}

static void expect_delete_node(OSList *list, OSListNode *node) {
    expect_value(__wrap_OSList_DeleteThisNode, list, list);
    expect_value(__wrap_OSList_DeleteThisNode, thisnode, node);
}

static Eventinfo * new_event(RuleInfo *rule) {
    Eventinfo *lf = NULL;

    os_calloc(1, sizeof(Eventinfo), lf);
    lf->generated_rule = rule;

    return lf;
}

/* Tests */

void test_Free_Eventinfo_sid_and_group_nodes(void **state) {
    OSList sid_list = {0};
    OSList group_list_0 = {0};
    OSList group_list_1 = {0};
    OSList *group_lists[] = {&group_list_0, &group_list_1, NULL};
    OSListNode sid_node = {0};
    OSListNode group_node_0 = {0};
    OSListNode group_node_1 = {0};

    RuleInfo rule = {0};
    rule.sid_prev_matched = &sid_list;
    rule.group_prev_matched = group_lists;
    rule.group_prev_matched_sz = 2;

    Eventinfo *lf = new_event(&rule);
    lf->sid_node_to_delete = &sid_node;
    os_calloc(2, sizeof(OSListNode *), lf->group_node_to_delete);
    lf->group_node_to_delete[0] = &group_node_0;
    lf->group_node_to_delete[1] = &group_node_1;

    expect_delete_node(&sid_list, &sid_node);
    expect_delete_node(&group_list_0, &group_node_0);
    expect_delete_node(&group_list_1, &group_node_1);

    Free_Eventinfo(lf);

    assert_int_equal(sid_list.pending_remove, 0);
    assert_int_equal(group_list_0.pending_remove, 0);
    assert_int_equal(group_list_1.pending_remove, 0);
}

void test_Free_Eventinfo_group_rule_without_group_nodes(void **state) {
    OSList sid_list = {0};
    /* The event never reached the group lists: they must not be touched at all */
    OSList *group_lists[] = {NULL, NULL, NULL};
    OSListNode sid_node = {0};

    RuleInfo rule = {0};
    rule.sid_prev_matched = &sid_list;
    rule.group_prev_matched = group_lists;
    rule.group_prev_matched_sz = 2;

    Eventinfo *lf = new_event(&rule);
    lf->sid_node_to_delete = &sid_node;

    expect_delete_node(&sid_list, &sid_node);

    Free_Eventinfo(lf);

    assert_int_equal(sid_list.pending_remove, 0);
}

void test_Free_Eventinfo_repeated_group_list(void **state) {
    /* The same list twice: it must stay blocked until both nodes are removed */
    OSList group_list = {0};
    OSList *group_lists[] = {&group_list, &group_list, NULL};
    OSListNode group_node_0 = {0};
    OSListNode group_node_1 = {0};

    RuleInfo rule = {0};
    rule.group_prev_matched = group_lists;
    rule.group_prev_matched_sz = 2;

    Eventinfo *lf = new_event(&rule);
    os_calloc(2, sizeof(OSListNode *), lf->group_node_to_delete);
    lf->group_node_to_delete[0] = &group_node_0;
    lf->group_node_to_delete[1] = &group_node_1;

    expect_delete_node(&group_list, &group_node_0);
    expect_delete_node(&group_list, &group_node_1);

    Free_Eventinfo(lf);

    assert_int_equal(group_list.pending_remove, 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        // Tests Free_Eventinfo
        cmocka_unit_test(test_Free_Eventinfo_sid_and_group_nodes),
        cmocka_unit_test(test_Free_Eventinfo_group_rule_without_group_nodes),
        cmocka_unit_test(test_Free_Eventinfo_repeated_group_list),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
