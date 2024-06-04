/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef HASH_OP_WRAPPERS_H
#define HASH_OP_WRAPPERS_H

#include "hash_op.h"

extern OSHash *mock_hashmap;

int setup_hashmap(void **state);
int teardown_hashmap(void **state);

int __wrap_OSHash_Add(OSHash *self, const char *key, void *data);
int __real_OSHash_Add(OSHash *hash, const char *key, void *data);

int __real_OSHash_Add_ex(OSHash *self, const char *key, void *data);
int __wrap_OSHash_Add_ex(__attribute__((unused)) OSHash *self, const char *key, void *data);

void *__real_OSHash_Begin(const OSHash *self, unsigned int *i);
void *__wrap_OSHash_Begin(const OSHash *self, unsigned int *i);

void *__real_OSHash_Begin_ex(const OSHash *self, unsigned int *i);
void *__wrap_OSHash_Begin_ex(const OSHash *self, __attribute__((unused)) unsigned int *i);

void *__real_OSHash_Clean(OSHash *self, void (*cleaner)(void*));
void *__wrap_OSHash_Clean(OSHash *self, void (*cleaner)(void*));

OSHash *__wrap_OSHash_Create();
OSHash * __real_OSHash_Create();

void *__wrap_OSHash_Delete_ex(OSHash *self, const char *key);

void *__real_OSHash_Delete(OSHash *self, const char *key);
void *__wrap_OSHash_Delete(OSHash *self, const char *key);

void *__wrap_OSHash_Get(const OSHash *self, const char *key);
void *__real_OSHash_Get(const OSHash *self, const char *key);

void *__real_OSHash_Get_ex(const OSHash *self, const char *key);
void *__wrap_OSHash_Get_ex(const OSHash *self, const char *key);

void *__wrap_OSHash_Get_ex_dup(const OSHash *self, const char *key, void*(*duplicator)(void*));

void *__real_OSHash_Numeric_Get_ex(const OSHash *self, int key);
void *__wrap_OSHash_Numeric_Get_ex(const OSHash *self, int key);

void *__wrap_OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current);

int __real_OSHash_SetFreeDataPointer(OSHash *self, void (free_data_function)(void *));
int __wrap_OSHash_SetFreeDataPointer(OSHash *self, void (free_data_function)(void *));

int __wrap_OSHash_setSize(OSHash *self, unsigned int new_size);

int __wrap_OSHash_Update_ex(OSHash *self, const char *key, void *data);

int __wrap_OSHash_Update(OSHash *self, const char *key, void *data);

extern int OSHash_Add_ex_check_data;

int __wrap_OSHash_Get_Elem_ex(OSHash *self);

int __wrap_OSHash_Set(OSHash *self, const char *key, void *data);

#endif
