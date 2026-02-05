/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_AUTH_WRAPPERS_H
#define OS_AUTH_WRAPPERS_H

#include "sec.h"
#include "shared.h"

w_err_t __wrap_w_auth_validate_data(
    char* response, const char* ip, const char* agentname, const char* groups, const char* hash_key);

void __wrap_add_insert(const keyentry* entry, const char* group);

void __wrap_add_remove(const keyentry* entry);

cJSON* __wrap_local_add(const char* id,
                        const char* name,
                        const char* ip,
                        __attribute__((unused)) const char* groups,
                        const char* key,
                        __attribute__((unused)) const char* key_hash,
                        __attribute__((unused)) int force_options);

#endif
