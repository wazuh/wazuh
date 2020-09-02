/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "cJSON_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


cJSON_bool __wrap_cJSON_AddItemToArray(__attribute__ ((__unused__)) cJSON *array,
                                 __attribute__ ((__unused__)) cJSON *item) {
    function_called();
    return mock_type(cJSON_bool);
}

cJSON_bool __wrap_cJSON_AddItemToObject(__attribute__ ((__unused__)) cJSON *object,
                                  __attribute__ ((__unused__)) const char *string,
                                  __attribute__ ((__unused__)) cJSON *item) {
    function_called();
    return mock_type(cJSON_bool);
}

cJSON* __wrap_cJSON_AddStringToObject(__attribute__ ((__unused__)) cJSON * const object,
                                      const char * const name,
                                      const char * const string) {
    if (name) check_expected(name);
    if (string) check_expected(string);
    return mock_type(cJSON *);
}

#ifdef WIN32
cJSON * __stdcall __wrap_cJSON_CreateArray(void) {
    return mock_type(cJSON *);
}

cJSON * __stdcall __wrap_cJSON_CreateObject(void) {
    return mock_type(cJSON *);
}
#else
cJSON * __wrap_cJSON_CreateArray(void) {
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_CreateObject(void) {
    return mock_type(cJSON *);
}
#endif

cJSON * __wrap_cJSON_CreateNumber(double num) {
    check_expected(num);
    return mock_type(cJSON *);
}

cJSON * __wrap_cJSON_CreateString(const char *string) {
    check_expected(string);
    return mock_type(cJSON *);
}

void __wrap_cJSON_Delete(__attribute__ ((__unused__)) cJSON *item) {
    function_called();
    return;
}

cJSON * __wrap_cJSON_GetObjectItem(__attribute__ ((__unused__)) const cJSON * const object,
                                   __attribute__ ((__unused__)) const char * const string) {
    return mock_type(cJSON *);
}

char* __wrap_cJSON_GetStringValue(__attribute__ ((__unused__)) cJSON * item) {
    return mock_type(char*);
}

cJSON_bool __wrap_cJSON_IsNumber(__attribute__ ((__unused__)) cJSON * item) {
    return mock_type(cJSON_bool);
}

cJSON_bool __wrap_cJSON_IsObject(__attribute__ ((__unused__)) cJSON * item) {
    return mock_type(cJSON_bool);
}

cJSON * __wrap_cJSON_Parse(__attribute__ ((__unused__)) const char *value) {
    return mock_type(cJSON *);
}

char * __wrap_cJSON_PrintUnformatted(__attribute__ ((__unused__)) const cJSON *item) {
    return mock_type(char *);
}
