/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __WMODULES_SCHEDULING_HELPERS_H__
#define __WMODULES_SCHEDULING_HELPERS_H__

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include "shared.h"
#include "wazuh_modules/wmodules.h"

typedef struct test_structure {
    wmodule *module;
    OS_XML xml;
    XML_NODE nodes;
} test_structure;

const XML_NODE string_to_xml_node(const char * string, OS_XML *_lxml);
sched_scan_config init_config_from_string(const char* string);

/* Sets current simulation time */
void set_current_time(time_t _time);

#endif
