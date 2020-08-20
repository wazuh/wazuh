/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef CJSON_WRAPPERS_H
#define CJSON_WRAPPERS_H

#include <external/cJSON/cJSON.h>

cJSON_bool __wrap_cJSON_AddItemToArray(cJSON *array, cJSON *item);

extern cJSON_bool __real_cJSON_AddItemToArray(cJSON *array, cJSON *item);

cJSON_bool __wrap_cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);

extern cJSON_bool __real_cJSON_AddItemToObject(cJSON *object, const char *string, cJSON *item);

cJSON * __wrap_cJSON_AddStringToObject(cJSON * const object, const char * const name, const char * const string);

#ifdef WIN32
extern cJSON * __stdcall __real_cJSON_CreateArray(void);

cJSON * __stdcall __wrap_cJSON_CreateArray(void);

extern cJSON * __stdcall __real_cJSON_CreateObject(void);

cJSON * __stdcall __wrap_cJSON_CreateObject(void);
#else
extern cJSON * __real_cJSON_CreateArray(void);

cJSON * __wrap_cJSON_CreateArray(void);

extern cJSON * __real_cJSON_CreateObject(void);

cJSON * __wrap_cJSON_CreateObject(void);
#endif

cJSON * __wrap_cJSON_CreateNumber(double num);

cJSON * __wrap_cJSON_CreateString(const char *string);

extern cJSON * __real_cJSON_CreateString(const char *string);

void __wrap_cJSON_Delete(cJSON *item);

extern void __real_cJSON_Delete(cJSON *item);

cJSON * __wrap_cJSON_GetObjectItem(const cJSON * const object, const char * const string);

char* __wrap_cJSON_GetStringValue(cJSON * item);

cJSON_bool __wrap_cJSON_IsNumber(cJSON * item);

cJSON_bool __wrap_cJSON_IsObject(cJSON * item);

cJSON * __wrap_cJSON_Parse(const char *value);

extern cJSON * __real_cJSON_Parse(const char *value);

char * __wrap_cJSON_PrintUnformatted(const cJSON *item);

#endif
