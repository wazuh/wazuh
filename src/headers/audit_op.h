/*
 * Copyright (C) 2018 Wazuh Inc.
 * December 18, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef __AUDIT_OP_H
#define __AUDIT_OP_H

#ifdef ENABLE_AUDIT
#include <linux/audit.h>
#include <libaudit.h>
#include <private.h>

#define ADD_RULE 1
#define DELETE_RULE 2

int audit_send(int fd, int type, const void *data, unsigned int size);

int audit_get_rule_list(int fd);

void get_reply(int fd);

int audit_print_reply(struct audit_reply *rep);

// Converts Audit relative paths into absolute paths
char *audit_clean_path(char *cwd, char *path);

// Restart Auditd service
int audit_restart(void);

// Add / delete rules
int audit_manage_rules(int action, const char *path, const char *key);

// Add rule into Auditd rules list
int audit_add_rule(const char *path, const char *key);

// Delete rule
int audit_delete_rule(const char *path, const char *key);

// Check if exists rule '-a task,never'
int audit_check_lock_output(void);

#endif
#endif
