/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "test_fim.h"

int setup_os_list(void **state) {
    OSList *list = OSList_Create();

    if (list == NULL) {
        return -1;
    }

    *state = list;

    return 0;
}

int teardown_os_list(void **state) {
    OSList *list = *state;

    OSList_Destroy(list);

    return 0;
}

int setup_rb_tree(void **state) {
    rb_tree *tree = rbtree_init();

    if (tree == NULL) {
        return -1;
    }

    *state = tree;

    return 0;
}

int teardown_rb_tree(void **state) {
    rb_tree *tree = *state;

    rbtree_destroy(tree);

    return 0;
}
