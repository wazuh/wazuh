/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "os_auth_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

w_err_t __wrap_w_auth_validate_data(__attribute__((unused)) char *response, const char *ip, const char *agentname,
                                    __attribute__((unused)) const char *groups, const char *hash_key) {
    check_expected(ip);
    check_expected(agentname);
    check_expected(hash_key);
    return mock_type(w_err_t);
}

void __wrap_add_insert(__attribute__((unused)) const keyentry *entry, __attribute__((unused)) const char *group) {
    // Empty wrapper
}

void __wrap_add_remove(__attribute__((unused)) const keyentry *entry) {
    // Empty wrapper
}

cJSON* __wrap_local_add(const char *id,
                        const char *name,
                        const char *ip,
                        __attribute__((unused)) const char *groups,
                        const char *key,
                        __attribute__((unused)) const char *key_hash,
                        __attribute__((unused)) int force_options) {
    check_expected(id);
    check_expected(name);
    check_expected(ip);
    check_expected(key);
    return mock_type(cJSON *);
} 

