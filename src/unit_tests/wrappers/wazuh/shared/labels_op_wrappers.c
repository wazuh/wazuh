/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "labels_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

wlabel_t* __wrap_labels_find(char* agent_id, __attribute__((unused)) int* sock) {
    check_expected(agent_id);

    return mock_type(wlabel_t*);
}

char* __wrap_labels_get(__attribute__((unused)) const wlabel_t* labels, const char* key) {
    check_expected(key);

    return mock_type(char*);
}

void __wrap_labels_free(__attribute__((unused)) wlabel_t *labels) {
    int i;

    if (labels) {
        for (i = 0; labels[i].key != NULL; i++) {
            free(labels[i].key);
            free(labels[i].value);
        }

        free(labels);
    }
}
