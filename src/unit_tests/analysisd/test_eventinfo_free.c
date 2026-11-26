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

/* Free_Eventinfo must take the event out of every if_matched_sid / if_matched_group list it was stored in,
 * otherwise those lists keep a node pointing to the freed event. These tests use the real list implementation. */

/* Not exercised: wrapped only so the link does not pull the whole configuration reader in */
int __wrap_ReadConfig(__attribute__((unused)) int modules,
                      __attribute__((unused)) const char *cfgfile,
                      __attribute__((unused)) void *d1,
                      __attribute__((unused)) void *d2) {
    return 0;
}

typedef struct {
    RuleInfo rule;
    OSList *sid_list;
    OSList *group_lists[2];
} test_lists_t;

static int setup_lists(void **state) {
    test_lists_t *data;
    os_calloc(1, sizeof(test_lists_t), data);

    data->sid_list = OSList_Create();
    data->group_lists[0] = OSList_Create();
    data->group_lists[1] = OSList_Create();

    if (!data->sid_list || !data->group_lists[0] || !data->group_lists[1]) {
        return -1;
    }

    *state = data;
    return 0;
}

static int teardown_lists(void **state) {
    test_lists_t *data = *state;

    OSList_Destroy(data->sid_list);
    OSList_Destroy(data->group_lists[0]);
    OSList_Destroy(data->group_lists[1]);
    os_free(data->rule.group_prev_matched);
    os_free(data);

    return 0;
}

static void store_in_sid_list(test_lists_t *data, Eventinfo *lf) {
    data->rule.sid_prev_matched = data->sid_list;
    lf->sid_node_to_delete = OSList_AddData(data->sid_list, lf);
    assert_non_null(lf->sid_node_to_delete);
}

static void store_in_group_lists(test_lists_t *data, Eventinfo *lf) {
    data->rule.group_prev_matched_sz = 2;
    os_calloc(2, sizeof(OSList *), data->rule.group_prev_matched);
    data->rule.group_prev_matched[0] = data->group_lists[0];
    data->rule.group_prev_matched[1] = data->group_lists[1];

    os_calloc(2, sizeof(OSListNode *), lf->group_node_to_delete);
    for (unsigned int i = 0; i < 2; i++) {
        lf->group_node_to_delete[i] = OSList_AddData(data->group_lists[i], lf);
        assert_non_null(lf->group_node_to_delete[i]);
    }
}

void test_Free_Eventinfo_sid_list_only(void **state) {
    test_lists_t *data = *state;
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    lf->generated_rule = &data->rule;

    store_in_sid_list(data, lf);
    assert_int_equal(data->sid_list->currently_size, 1);

    Free_Eventinfo(lf);

    assert_int_equal(data->sid_list->currently_size, 0);
    assert_null(data->sid_list->first_node);
}

void test_Free_Eventinfo_group_lists_only(void **state) {
    test_lists_t *data = *state;
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    lf->generated_rule = &data->rule;

    store_in_group_lists(data, lf);

    Free_Eventinfo(lf);

    assert_int_equal(data->group_lists[0]->currently_size, 0);
    assert_int_equal(data->group_lists[1]->currently_size, 0);
}

void test_Free_Eventinfo_sid_and_group_lists(void **state) {
    test_lists_t *data = *state;
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    lf->generated_rule = &data->rule;

    /* A rule referenced by both if_matched_sid and if_matched_group stores the event in both kinds of list */
    store_in_sid_list(data, lf);
    store_in_group_lists(data, lf);

    Free_Eventinfo(lf);

    assert_int_equal(data->sid_list->currently_size, 0);
    assert_int_equal(data->group_lists[0]->currently_size, 0);
    assert_int_equal(data->group_lists[1]->currently_size, 0);
    assert_null(data->group_lists[0]->first_node);
    assert_null(data->group_lists[1]->first_node);
}

void test_Free_Eventinfo_copy_keeps_lists(void **state) {
    test_lists_t *data = *state;
    Eventinfo *lf;
    os_calloc(1, sizeof(Eventinfo), lf);
    lf->generated_rule = &data->rule;

    store_in_sid_list(data, lf);
    store_in_group_lists(data, lf);

    /* A copy does not own the list nodes: freeing it must leave them in place */
    OSListNode **group_nodes = lf->group_node_to_delete;
    lf->is_a_copy = 1;
    Free_Eventinfo(lf);

    assert_int_equal(data->sid_list->currently_size, 1);
    assert_int_equal(data->group_lists[0]->currently_size, 1);
    assert_int_equal(data->group_lists[1]->currently_size, 1);

    OSList_DeleteThisNode(data->sid_list, data->sid_list->first_node);
    OSList_DeleteThisNode(data->group_lists[0], data->group_lists[0]->first_node);
    OSList_DeleteThisNode(data->group_lists[1], data->group_lists[1]->first_node);
    os_free(group_nodes);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_Free_Eventinfo_sid_list_only, setup_lists, teardown_lists),
        cmocka_unit_test_setup_teardown(test_Free_Eventinfo_group_lists_only, setup_lists, teardown_lists),
        cmocka_unit_test_setup_teardown(test_Free_Eventinfo_sid_and_group_lists, setup_lists, teardown_lists),
        cmocka_unit_test_setup_teardown(test_Free_Eventinfo_copy_keeps_lists, setup_lists, teardown_lists),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
