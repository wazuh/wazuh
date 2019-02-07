/*
 * Copyright (C) 2015-2019, Wazuh Inc.
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
#define DEF_LIST_SIZE 50

typedef struct {
    char *path;
    char *perm;
    char *key;
} w_audit_rule;

typedef struct {
    w_audit_rule **list;
    int used;
    int size;
} w_audit_rules_list;


// Init loaded rules list. Use before audit_get_rule_list()
w_audit_rules_list *audit_rules_list_init(int initialSize);

// Checks if the audit rule is loaded.
int search_audit_rule(const char *path, const char *perms, const char *key);

// Adds rule to loaded rules list.
void audit_rules_list_append(w_audit_rules_list *wlist, w_audit_rule *element);

// Sends commands to audit kernel.
int audit_send(int fd, int type, const void *data, unsigned int size);

// Get audit loaded rules list. audit_free_list() must be called to free memory used.
int audit_get_rule_list(int fd);

// Clean audit loaded rules list.
void audit_free_list(void);
void audit_rules_list_free(w_audit_rules_list *wlist);

// Read reply from Audit kernel.
void get_reply(int fd);

// Process audit reply of loaded rules.
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
