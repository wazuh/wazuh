/* Copyright (C) 2015, Wazuh Inc.
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


OSHash *mock_hashmap = NULL;

OSHash *__real_OSHash_Create();

int setup_hashmap(__attribute__((unused)) void **state) {
    mock_hashmap = __real_OSHash_Create();

    if (mock_hashmap == NULL) {
        return -1;
    }

    return 0;
}

int teardown_hashmap(__attribute__((unused)) void **state) {
    if (mock_hashmap) {
        OSHash_Free(mock_hashmap);
        mock_hashmap = NULL;
    }

    return 0;
}

int __real_OSHash_Add(OSHash *self, const char *key, void *data);
int __wrap_OSHash_Add(__attribute__((unused)) OSHash *self, const char *key, void *data) {
    int retval;

    if (key) check_expected(key);

    retval = mock();

    if (mock_hashmap != NULL && retval != 0) {
        __real_OSHash_Add(mock_hashmap, key, data);
    }

    return retval;
}

int __real_OSHash_Add_ex(OSHash *self, const char *key, void *data);
int __wrap_OSHash_Add_ex(__attribute__((unused)) OSHash *self, const char *key, void *data) {
    int retval;

    if (test_mode){
        check_expected(self);
        check_expected(key);
        if (OSHash_Add_ex_check_data) {
            check_expected(data);
        }
        retval =  mock();

        if (mock_hashmap != NULL && retval != 0) {
            __real_OSHash_Add(mock_hashmap, key, data);
        }

        return retval;
    }
    return __real_OSHash_Add_ex(self, key, data);
}

void *__wrap_OSHash_Begin(const OSHash *self, __attribute__((unused)) unsigned int *i) {
    check_expected_ptr(self);

    return mock_type(OSHashNode*);
}

void * __real_OSHash_Begin_ex(const OSHash *self, unsigned int *i);
void * __wrap_OSHash_Begin_ex(const OSHash *self, __attribute__((unused)) unsigned int *i) {
    OSHashNode* retval;

    if (test_mode){
        check_expected(self);
        retval = mock_type(OSHashNode*);

        if (mock_hashmap != NULL) {
            __real_OSHash_Begin(mock_hashmap, i);
        }

        return retval;
    }
    return __real_OSHash_Begin_ex(self, i);
}

void *__real_OSHash_Clean(OSHash *self, void (*cleaner)(void*));
void *__wrap_OSHash_Clean(__attribute__((unused)) OSHash *self,
                          __attribute__((unused)) void (*cleaner)(void*)) {
    if (test_mode == 0) {
        return __real_OSHash_Clean(self, cleaner);
    }

    return mock_type(void *);
}

OSHash *__wrap_OSHash_Create() {
    if (test_mode == 0) {
        return __real_OSHash_Create();
    }

    function_called();

    return mock_type(OSHash *);
}

void *__real_OSHash_Delete_ex(OSHash *self, const char *key);
void *__wrap_OSHash_Delete_ex(OSHash *self, const char *key) {
    void *retval = NULL;
    if (test_mode == 0) {
        return __real_OSHash_Delete_ex(self, key);
    }

    check_expected(self);
    check_expected(key);
    retval = mock_type(void *);
    if (mock_hashmap != NULL) {
        void *aux = __real_OSHash_Delete(mock_hashmap, key);
        if (aux != NULL && mock_hashmap->free_data_function) {
            mock_hashmap->free_data_function(aux);
        }
    }

    return retval;
}

void *__wrap_OSHash_Delete(OSHash *self, const char *key) {
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

void *__wrap_OSHash_Get_ex_dup(const OSHash *self, const char *key, __attribute__((unused)) void*(*duplicator)(void*)) {
    check_expected(self);
    check_expected(key);
    return mock_type(void*);
}

void *__wrap_OSHash_Numeric_Get_ex(const OSHash *self, int key) {
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

int __wrap_OSHash_SetFreeDataPointer(__attribute__((unused)) OSHash *self, void (free_data_function)(void *)) {
    function_called();

    if (mock_hashmap != NULL && free_data_function != NULL) {
        __real_OSHash_SetFreeDataPointer(mock_hashmap, free_data_function);
    }

    return mock();
}

int __wrap_OSHash_setSize(__attribute__((unused)) OSHash *self,
                          __attribute__((unused)) unsigned int new_size) {
    return mock();
}

int __real_OSHash_Update(OSHash *self, const char *key, void *data);
int __wrap_OSHash_Update(__attribute__((unused)) OSHash *self,
                            __attribute__((unused)) const char *key,
                            __attribute__((unused)) void *data) {
    int retval = mock();

    if (mock_hashmap != NULL && retval != 0) {
        __real_OSHash_Update(mock_hashmap, key, data);
    }

    return retval;
}

int __wrap_OSHash_Update_ex(__attribute__((unused)) OSHash *self,
                            __attribute__((unused)) const char *key,
                            __attribute__((unused)) void *data) {
    int retval = mock();

    if (mock_hashmap != NULL && retval != 0) {
        __real_OSHash_Update(mock_hashmap, key, data);
    }

    return retval;
}

int __wrap_OSHash_Get_Elem_ex(OSHash *self) {
    check_expected_ptr(self);
    return mock();
}

int __wrap_OSHash_Set(OSHash *self, const char *key, void *data) {
    check_expected_ptr(self);
    check_expected_ptr(key);
    check_expected_ptr(data);
    return mock();
}
