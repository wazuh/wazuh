/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef AUDIT_OP_WRAPPERS_H
#define AUDIT_OP_WRAPPERS_H

int __wrap_audit_add_rule(const char *path, const char *key);

int __wrap_audit_get_rule_list(int fd);

int __wrap_audit_restart();

int __wrap_audit_set_db_consistency();

int __wrap_search_audit_rule(const char *path, const char *perms, const char *key);

#endif
