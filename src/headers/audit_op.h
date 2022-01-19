/*
 * Copyright (C) 2015, Wazuh Inc.
 * December 18, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef AUDIT_OP_H
#define AUDIT_OP_H

#ifdef ENABLE_AUDIT
#include <linux/audit.h>
#include <libaudit.h>
#include <private.h>

#define ADD_RULE 1
#define DELETE_RULE 2

/**
 * @struct w_audit_rule
 * @brief Stores the specification of an Audit rule.
 */
typedef struct {
    char *path; ///< Path of the folder.
    int perm; ///< Permission access type.
    char *key;  ///< Filter key.
} w_audit_rule;


typedef enum _audit_mode {
    AUDIT_ERROR = -1,
    AUDIT_DISABLED,
    AUDIT_ENABLED,
    AUDIT_IMMUTABLE
} audit_mode;


/**
 * @brief Allocate the memory for the rule_list and set it's free function.
 */
void init_audit_rule_list();


/**
 * @brief Adds a rule to loaded rules list.
 *
 * @param element Struct w_audit_rule to be added.
 */
void audit_rules_list_append(w_audit_rule *element);


/**
 * @brief Checks if the audit rule is loaded.
 *
 * @param path Path of the folder.
 * @param perms Permission access type.
 * @param key Filter key.
 * @retval -1 If error.
 * @retval 0 Rule not loaded.
 * @retval 1 Rule loaded.
 */
int search_audit_rule(const char *path, int perms, const char *key);


/**
 * @brief Deallocates the memory used by a rules list.
 *
 */
void audit_rules_list_free();


/**
 * @brief Get loaded rules list from audit kernel. audit_free_list() must be called to free memory used.
 *
 * @param fd Audit netlink socket.
 * @return -1 on error and 1 on success.
 */
int audit_get_rule_list(int fd);


/**
 * @brief Read reply from Audit kernel.
 *
 * @param fd Audit netlink socket.
 */
void kernel_get_reply(int fd);


/**
 * @brief Process audit reply of loaded rules.
 *
 * @param rep Pointer to audit_reply struct.
 * @return 0 on invalid response and 1 on success.
 */
int audit_print_reply(struct audit_reply *rep);


/**
 * @brief Converts Audit relative paths into absolute paths.
 *
 * @param cwd Current directory.
 * @param path Relative path of the file.
 * @return Absolute path.
 */
char *audit_clean_path(char *cwd, char *path);


/**
 * @brief Restart Auditd service.
 *
 * @return Returns -1 on error and 0 if the service was restarted.
 */
int audit_restart(void);


/**
 * @brief Add or delete rules.
 *
 * @param action Values `#ADD_RULE` or `#DELETE_RULE`
 * @param path Path of the folder.
 * @param permissions Permission access type.
 * @param key Filter key.
 * @return The return value is <= 0 on error,
 *         otherwise it is the netlink sequence id number.
 */
int audit_manage_rules(int action, const char *path, int permissions, const char *key);


/**
 * @brief Adds an Audit rule.
 *
 * @param path Path of the folder.
 * @param perms Permission access type.
 * @param key Filter key.
 * @return The return value is <= 0 on error,
 *         otherwise it is the netlink sequence id number.
 */
int audit_add_rule(const char *path, int perms, const char *key);


/**
 * @brief Deletes an Audit rule.
 *
 * @param path Path of the folder.
 * @param perms Permission access type.
 * @param key Filter key.
 * @return The return value is <= 0 on error,
 *         otherwise it is the netlink sequence id number.
 */
int audit_delete_rule(const char *path, int perms, const char *key);

/**
 * @brief Function that frees the data memory of a node in the list.
 *
 * @param rule Data of a node in a list (OSListNode.data)
 */
void clear_audit_rule(w_audit_rule *rule);

#endif /* ENABLE_AUDIT */
#endif /* AUDIT_OP_H */
