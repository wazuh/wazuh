/* Copyright (C) 2015-2020, Wazuh Inc.
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

int __wrap_OSHash_Add(OSHash *self, const char *key, void *data);

int __real_OSHash_Add_ex(OSHash *self, const char *key, void *data);
int __wrap_OSHash_Add_ex(OSHash *self, const char *key, void *data);

void *__real_OSHash_Begin(const OSHash *self, unsigned int *i);
void *__wrap_OSHash_Begin(const OSHash *self, unsigned int *i);

void *__wrap_OSHash_Clean(OSHash *self, void (*cleaner)(void*));

OSHash *__wrap_OSHash_Create();

void *__wrap_OSHash_Delete_ex(OSHash *self, const char *key);

void *__wrap_OSHash_Get(const OSHash *self, const char *key);

void *__real_OSHash_Get_ex(const OSHash *self, const char *key);
void *__wrap_OSHash_Get_ex(const OSHash *self, const char *key);

void *__wrap_OSHash_Next(const OSHash *self, unsigned int *i, OSHashNode *current);

int __wrap_OSHash_SetFreeDataPointer(OSHash *self, void (free_data_function)(void *));

int __wrap_OSHash_setSize(OSHash *self, unsigned int new_size);

int __wrap_OSHash_Update_ex(OSHash *self, const char *key, void *data);

extern int OSHash_Add_ex_check_data;

#endif
