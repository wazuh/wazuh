/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef AUDIT_RULE_HANDLING_WRAPPERS
#define AUDIT_RULE_HANDLING_WRAPPERS

void __wrap_fim_rules_initial_load();

void __wrap_add_whodata_directory(const char *path);

void __wrap_remove_audit_rule_syscheck(const char *path);

void __wrap_fim_audit_reload_rules();

int __wrap_fim_manipulated_audit_rules();

#endif // AUDIT_RULE_HANDLING_WRAPPERS
