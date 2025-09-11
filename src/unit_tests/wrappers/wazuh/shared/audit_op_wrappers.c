/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "audit_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_audit_add_rule(__attribute__((unused)) const char *path,
                          __attribute__((unused)) int perms,
                          __attribute__((unused)) const char *key) {
    return mock();
}

int __wrap_audit_get_rule_list(__attribute__((unused)) int fd) {
    return mock();
}

int __wrap_audit_restart() {
    return mock();
}

int __wrap_audit_set_db_consistency() {
    return 1;
}

int __wrap_search_audit_rule(__attribute__((unused)) const char *path,
                             __attribute__((unused)) int perms,
                             __attribute__((unused)) const char *key) {
    return mock();
}

int __wrap_audit_delete_rule(const char *path, int perms, const char *key) {
    check_expected_ptr(path);
    check_expected(perms);
    check_expected_ptr(key);
    return mock_type(int);
}
