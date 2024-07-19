/* Copyright (C) 2015, Wazuh Inc.
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

#include <string.h>
#include <stdlib.h>


extern const char * __real_w_get_attr_val_by_name(xml_node * node, const char * name);
const char * __wrap_w_get_attr_val_by_name(xml_node * node, const char * name) {
    if (test_mode) {
        return mock_type(const char *);
    }

    return __real_w_get_attr_val_by_name(node, name);
}

xml_node ** __wrap_OS_GetElementsbyNode(__attribute__ ((__unused__)) const OS_XML * _lxml,
                                        __attribute__ ((__unused__)) const xml_node * node) {
     return mock_type(xml_node **);
}

void __wrap_OS_ClearNode(xml_node ** node) {

    function_called();
    if (node != NULL) {
        for (int i = 0; node[i]; i++) {
            if (node[i]->element) {
                free(node[i]->element);
            }
            free(node[i]);
        }
        free(node);
    }
}

int __wrap_OS_ReadXML(__attribute__ ((__unused__)) const char * file, OS_XML * _lxml) {
    int retval = mock_type(int);
    if (retval < 0) {
        char * buffer = mock_type(char *);
        strcpy(_lxml->err, buffer);
        _lxml->err_line = mock_type(int);
    }
    return retval;
}

int __wrap_OS_ReadXMLString(__attribute__ ((__unused__)) const char * file, OS_XML * _lxml) {
    int retval = mock_type(int);
    if (retval < 0) {
        char * buffer = mock_type(char *);
        strcpy(_lxml->err, buffer);
        _lxml->err_line = mock_type(int);
    }
    return retval;
}


void __wrap_OS_ClearXML(__attribute__ ((__unused__)) OS_XML * _lxml) { return; }
