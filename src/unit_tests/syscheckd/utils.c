/*
 * Copyright (C) 2015, Wazuh Inc.
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

#define BASE_WIN_ALLOWED_ACE "[" \
    "\"delete\"," \
    "\"read_control\"," \
    "\"write_dac\"," \
    "\"write_owner\"," \
    "\"synchronize\"," \
    "\"read_data\"," \
    "\"write_data\"," \
    "\"append_data\"," \
    "\"read_ea\"," \
    "\"write_ea\"," \
    "\"execute\"," \
    "\"read_attributes\"," \
    "\"write_attributes\"" \
"]"

#define BASE_WIN_DENIED_ACE "[" \
    "\"read_control\"," \
    "\"synchronize\"," \
    "\"read_data\"," \
    "\"read_ea\"," \
    "\"execute\"," \
    "\"read_attributes\"" \
"]"

#define BASE_WIN_ACE "{" \
    "\"name\": \"Users\"," \
    "\"allowed\": " BASE_WIN_ALLOWED_ACE "," \
    "\"denied\": " BASE_WIN_DENIED_ACE \
"}"

cJSON *create_win_permissions_object() {
    static const char * const BASE_WIN_PERMS = "{\"S-1-5-32-636\": " BASE_WIN_ACE "}";
    return cJSON_Parse(BASE_WIN_PERMS);
}
