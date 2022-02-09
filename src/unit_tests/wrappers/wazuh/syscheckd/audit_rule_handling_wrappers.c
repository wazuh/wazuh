/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "audit_rule_handling_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


void __wrap_fim_rules_initial_load() {
    function_called();
}

void __wrap_add_whodata_directory(const char *path) {
    check_expected_ptr(path);
}

void __wrap_remove_audit_rule_syscheck(const char *path) {
    check_expected_ptr(path);
}

void __wrap_fim_audit_reload_rules() {
    function_called();
}

int __wrap_fim_manipulated_audit_rules() {
    return mock_type(int);
}
