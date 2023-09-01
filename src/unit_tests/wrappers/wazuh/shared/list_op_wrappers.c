/* Copyright (C) 2023, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "list_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void *__wrap_OSList_AddData(__attribute__((unused))OSList *list, __attribute__((unused))void *data) {

    if(test_mode)
        os_free(data);
    return mock_type(void *);
}

void __wrap_OSList_DeleteThisNode(__attribute__((unused))OSList *list, __attribute__((unused))OSListNode *thisnode) {
    function_called();
    return;
}

OSListNode *__wrap_OSList_GetFirstNode(__attribute__((unused))OSList *list) {
    return mock_type(OSListNode *);
}