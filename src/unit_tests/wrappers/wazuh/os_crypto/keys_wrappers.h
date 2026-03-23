/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef KEYS_WRAPPERS_H
#define KEYS_WRAPPERS_H


int __wrap_OS_IsAllowedDynamicID(__attribute__((unused)) keystore *keys, const char *id, const char *srcip);

int __wrap_OS_DeleteSocket(__attribute__((unused)) keystore * keys, int sock);

int __wrap_OS_IsAllowedIP(__attribute__((unused)) keystore *keys, const char *srcip);

int __wrap_OS_IsAllowedID(__attribute__((unused)) keystore *keys, const char *id);

keyentry * __wrap_OS_DupKeyEntry(const keyentry * key);

int __wrap_OS_AddSocket(keystore * keys, unsigned int i, int sock);

void __wrap_OS_FreeKey(keyentry *key);

#endif
