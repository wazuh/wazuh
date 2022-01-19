/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "external/libplist/include/plist/plist.h"
#include "../common.h"
#include "../headers/shared.h"

void wrap_plist_from_bin (char * bin, size_t size, plist_t *node) {
    if (test_mode) {
        check_expected(bin);
        *node = mock_type(plist_t);
        return;
    }
    
    plist_from_bin(bin, size, node);
}

void wrap_plist_to_xml (plist_t *node, char ** xml, uint32_t *size) {
    if (test_mode) {
        check_expected(node);
        char *tmp = mock_type(char*);
        w_strdup(tmp, *xml);
        *size = mock_type(uint32_t);
        return;
    }
    
    plist_to_xml(node, xml, size);
}

void wrap_plist_free(plist_t node) {
    if (test_mode) {
        check_expected(node);
        return;
    }
    
    plist_free(node);
}