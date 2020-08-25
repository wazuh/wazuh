/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "hash_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"


int __wrap_OSHash_Add(__attribute__((unused)) OSHash *self, const char *key,
                      __attribute__((unused)) void *data) {
    if (key) check_expected(key);
    return mock();
}

int __real_OSHash_Add_ex(OSHash *self, const char *key, void *data);
int __wrap_OSHash_Add_ex(OSHash *self, const char *key, void *data) {
    if (test_mode){
        check_expected(self);
        check_expected(key);
        if (OSHash_Add_ex_check_data) {
            check_expected(data);
        }
        return mock();
    }
    return __real_OSHash_Add_ex(self, key, data);
}

void *__wrap_OSHash_Begin(const OSHash *self, __attribute__((unused)) unsigned int *i) {
    check_expected_ptr(self);

    return mock_type(OSHashNode*);
}

void *__wrap_OSHash_Clean(__attribute__((unused)) OSHash *self,
                          __attribute__((unused)) void (*cleaner)(void*)) {
    return mock_type(void *);
}

OSHash *__real_OSHash_Create();
OSHash *__wrap_OSHash_Create() {
    if (test_mode){
        function_called();
        return mock_type(OSHash*);
    }
    return __real_OSHash_Create();
}

void *__real_OSHash_Delete_ex(OSHash *self, const char *key);
void *__wrap_OSHash_Delete_ex(OSHash *self, const char *key) {
    if (test_mode){
        check_expected(self);
        check_expected(key);
        return mock_type(void*);
    }
    return __real_OSHash_Delete_ex(self, key);
}

void *__real_OSHash_Get(const OSHash *self, const char *key);
void *__wrap_OSHash_Get(const OSHash *self, const char *key) {
    if (test_mode){
        check_expected(self);
        check_expected(key);
        return mock_type(void*);
    }
    return __real_OSHash_Get(self, key);
}

void *__wrap_OSHash_Get_ex(const OSHash *self, const char *key) {
    check_expected(self);
    check_expected(key);

    return mock_type(void*);
}

void *__wrap_OSHash_Next(const OSHash *self,
                         __attribute__((unused)) unsigned int *i,
                         __attribute__((unused)) OSHashNode *current) {
    check_expected_ptr(self);
    return mock_type(OSHashNode*);
}

int __wrap_OSHash_SetFreeDataPointer(__attribute__((unused)) OSHash *self,
                                     __attribute__((unused)) void (free_data_function)(void *)) {
    function_called();
    return mock();
}

int __wrap_OSHash_setSize(__attribute__((unused)) OSHash *self,
                          __attribute__((unused)) unsigned int new_size) {
    return mock();
}

int __wrap_OSHash_Update_ex(__attribute__((unused)) OSHash *self,
                            __attribute__((unused)) const char *key,
                            __attribute__((unused)) void *data) {
    return mock();
}
