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
#include "../../analysisd/rules.h"
#include "../../analysisd/cdb/cdb.h"
#include "../../analysisd/analysisd.h"
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

void os_remove_cdblist(ListNode **l_node);
void os_remove_cdbrules(ListRule **l_rule);
ListNode *OS_FindList(const char *listname, ListNode **l_node);
void OS_ListLoadRules(ListNode **l_node, ListRule **lrule);

/* setup/teardown */



/* wraps */

void __wrap_OSMatch_FreePattern(OSMatch *reg) {
    return;
}

/* tests */

/* os_remove_cdblist */
void test_os_remove_cdblist_OK(void **state)
{
    ListNode *l_node;
    os_calloc(1,sizeof(ListNode), l_node);
    os_calloc(1,sizeof(ListNode), l_node->cdb_filename);
    os_calloc(1,sizeof(char*), l_node->txt_filename);

    os_remove_cdblist(&l_node);

}

/* os_remove_cdbrules */
void test_os_remove_cdbrules_OK(void **state)
{
    ListRule *l_rule;
    os_calloc(1,sizeof(ListRule), l_rule);
    os_calloc(1,sizeof(ListRule), l_rule->matcher);
    os_calloc(1,sizeof(char*), l_rule->dfield);
    os_calloc(1,sizeof(char*), l_rule->filename);
    os_remove_cdbrules(&l_rule);

}

/* OS_FindList */
void test_OS_FindList_dont_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    ListNode * retval;

    os_calloc(1, sizeof(ListNode), node);
    node->next = NULL;
    node->txt_filename = "not_list_test.cbd";
    node->cdb_filename = "not_2_list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_null(retval);

    os_free(node);
}

void test_OS_FindList_empty_node(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node = NULL;
    ListNode * retval;

    retval = OS_FindList(list, &node);

    assert_null(retval);
}

void test_OS_FindList_txt_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);
    ListNode * retval;
    const ListNode * expect_retval = node;

    node->next = NULL;
    node->txt_filename = "list_test.cbd";
    node->cdb_filename = "not_2_list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_non_null(retval);
    assert_ptr_equal(retval, expect_retval);

    os_free(node);
}

void test_OS_FindList_cdb_match(void ** state) {

    const char list[] = "list_test.cbd";
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);
    ListNode * retval;
    const ListNode * expect_retval = node;

    node->next = NULL;
    node->txt_filename = "_not_list_test.cbd";
    node->cdb_filename = "list_test.cbd";

    retval = OS_FindList(list, &node);

    assert_non_null(retval);
    assert_ptr_equal(retval, expect_retval);

    os_free(node);
}

/* OS_ListLoadRules */
void test_OS_ListLoadRules_rule_null_check(void ** state) {
    ListNode * l_node = (ListNode *) 1;
    ListRule * lrule = NULL;

    OS_ListLoadRules(&l_node, &lrule);
}

void test_OS_ListLoadRules_list_checked(void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 0;
    lrule->filename = strdup("test_file");

    OS_ListLoadRules(&l_node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule->filename);
    os_free(firstrule);
}

void test_OS_ListLoadRules_list_checked_and_load (void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 0;
    lrule->filename = strdup("list_test.cbd");

    /* OS_FindList */
    ListNode * node;
    os_calloc(1, sizeof(ListNode), node);

    node->next = NULL;
    node->txt_filename = "_not_list_test.cbd";
    node->cdb_filename = "list_test.cbd";

    OS_ListLoadRules(&node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule->filename);
    os_free(firstrule);
    os_free(node);
}

void test_OS_ListLoadRules_already_load(void ** state) {
    ListRule * lrule;
    ListRule * firstrule;
    ListNode * l_node = NULL;

    os_calloc(1, sizeof(ListRule), lrule);
    firstrule = lrule;
    lrule->next = NULL;
    lrule->loaded = 1;

    OS_ListLoadRules(&l_node, &lrule);

    assert_int_equal(firstrule->loaded, 1);
    os_free(firstrule);
    os_free(lrule);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_remove_cdblist
        cmocka_unit_test(test_os_remove_cdblist_OK),
        // Tests os_remove_cdbrules
        cmocka_unit_test(test_os_remove_cdbrules_OK),
        // Tests OS_FindList
        cmocka_unit_test(test_OS_FindList_dont_match),
        cmocka_unit_test(test_OS_FindList_empty_node),
        cmocka_unit_test(test_OS_FindList_cdb_match),
        cmocka_unit_test(test_OS_FindList_txt_match),
        // Tests OS_ListLoadRules
        cmocka_unit_test(test_OS_ListLoadRules_rule_null_check),
        cmocka_unit_test(test_OS_ListLoadRules_list_checked),
        cmocka_unit_test(test_OS_ListLoadRules_list_checked_and_load),
        cmocka_unit_test(test_OS_ListLoadRules_already_load),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
