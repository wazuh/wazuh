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

void os_remove_eventlist(EventList *list);

/* setup/teardown */



/* wraps */

void __wrap_Free_Eventinfo(Eventinfo *lf) {
    return;
}

/* tests */

/* os_remove_eventlist */
void test_os_remove_eventlist_OK(void **state)
{
    EventList *list;
    os_calloc(1,sizeof(EventList), list);

    os_calloc(1,sizeof(EventNode), list->first_node);

    os_remove_eventlist(list);

}

int main(void)
{
    const struct CMUnitTest tests[] = {
        // Tests os_remove_eventlist
        cmocka_unit_test(test_os_remove_eventlist_OK)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}

