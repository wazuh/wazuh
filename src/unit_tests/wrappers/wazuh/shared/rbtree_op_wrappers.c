/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "rbtree_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void * __wrap_rbtree_insert(__attribute__((unused)) rb_tree * tree,
                            __attribute__((unused)) const char * key,
                            __attribute__((unused)) void * value) {
    return NULL;
}

char **__wrap_rbtree_keys(__attribute__((unused)) const rb_tree *tree) {
    return mock_type(char **);
}
