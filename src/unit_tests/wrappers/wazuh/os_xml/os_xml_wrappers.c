/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_xml_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"


extern const char * __real_w_get_attr_val_by_name(xml_node * node, const char * name);
const char * __wrap_w_get_attr_val_by_name(xml_node * node, const char * name) {
    if (test_mode) {
        return mock_type(const char *);
    }

    return __real_w_get_attr_val_by_name(node, name);
}
