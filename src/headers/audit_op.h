/*
 * Copyright (C) 2015-2020, Wazuh Inc.
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
    char *perm; ///< Permission access type.
    char *key;  ///< Filter key.
} w_audit_rule;

/**
 * @struct w_audit_rules_list
 * @brief Stores the list of the Audit loaded rules.
 */
typedef struct {
    w_audit_rule **list; ///< List of loaded rules.
    int used;            ///< Number of loaded rules.
    int size;            ///< Size of the rules list.
} w_audit_rules_list;


typedef enum _audit_status {
    AUDIT_ERROR = -1,
    AUDIT_DISABLED = 0,
    AUDIT_ENABLED = 1,
    AUDIT_IMMUTABLE = 2
} audit_status;


/**
 * @brief Init loaded rules list.
 *
 * @param initialSize Initial size of the list.
 * @return Pointer to w_audit_rules_list struct.
 */
w_audit_rules_list* audit_rules_list_init(int initialSize);


/**
 * @brief Adds a rule to loaded rules list.
 *
 * @param wlist Loaded rules list. This list must be initialized.
 * @param element Struct w_audit_rule to be added.
 */
void audit_rules_list_append(w_audit_rules_list *wlist, w_audit_rule *element);


/**
 * @brief Get loaded rules list from audit kernel. audit_free_list() must be called to free memory used.
 *
 * @param fd Audit netlink socket.
 * @return -1 on error and 1 on success.
 */
int audit_get_rule_list(int fd);


/**
 * @brief Checks if the audit rule is loaded. audit_get_rule_list() must be called before.
 *
 * @param path Path of the folder.
 * @param perms Permission access type.
 * @param key Filter key.
 * @retval -1 If error.
 * @retval 0 Rule not loaded.
 * @retval 1 Rule loaded.
 */
int search_audit_rule(const char *path, const char *perms, const char *key);


/**
 * @brief Deallocates the memory used by the loaded rules list.
 *
 */
void audit_free_list(void);


/**
 * @brief Deallocates the memory used by a rules list.
 *
 * @param wlist Pointer to the rule list to be deallocated.
 */
void audit_rules_list_free(w_audit_rules_list *wlist);


/**
 * @brief Read reply from Audit kernel.
 *
 * @param fd Audit netlink socket.
 */
void kernel_get_reply(int fd);


/**
 * @brief Get mode from audit.
 *
 * @return AUDIT_ERROR, AUDIT_DISABLED, AUDIT_ENABLED or AUDIT_IMMUTABLE.
*/
int audit_get_mode();


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
 * @param key Filter key.
 * @return The return value is <= 0 on error,
 *         otherwise it is the netlink sequence id number.
 */
int audit_manage_rules(int action, const char *path, const char *key);


/**
 * @brief Adds an Audit rule.
 *
 * @param path Path of the folder.
 * @param key Filter key.
 * @return The return value is <= 0 on error,
 *         otherwise it is the netlink sequence id number.
 */
int audit_add_rule(const char *path, const char *key);


/**
 * @brief Deletes an Audit rule.
 *
 * @param path Path of the folder.
 * @param key Filter key.
 * @return The return value is <= 0 on error,
 *         otherwise it is the netlink sequence id number.
 */
int audit_delete_rule(const char *path, const char *key);

#endif /* ENABLE_AUDIT */
#endif /* AUDIT_OP_H */
