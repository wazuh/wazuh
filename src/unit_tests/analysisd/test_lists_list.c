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

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_remove_cdblist
        cmocka_unit_test(test_os_remove_cdblist_OK),
        // Tests os_remove_cdbrules
        cmocka_unit_test(test_os_remove_cdbrules_OK)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
