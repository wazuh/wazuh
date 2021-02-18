/*
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef __linux__
#include "syscheck_audit.h"
#include "list_op.h"

#define RELOAD_RULES_INTERVAL 30 // Seconds to re-add Audit rules

#ifdef ENABLE_AUDIT

typedef struct {
    char *path;
    int pending_removal;
} whodata_directory_t;

static OSList *whodata_directories;

static void free_whodata_directory(whodata_directory_t *directory) {
    os_free(directory->path);
    os_free(directory);
}

static void add_whodata_directory(const char *path) {
    whodata_directory_t *directory;

    os_malloc(sizeof(whodata_directory_t), directory);

    os_strdup(path, directory->path);
    directory->pending_removal = 0;

    if (OSList_AddData(whodata_directories, directory) == NULL) {
        free_whodata_directory(directory);
    }
}


int add_audit_rules_syscheck(bool first_time) {
    unsigned int i = 0;
    int found;
    int retval;
    char *directory = NULL;
    int rules_added = 0;
    static bool reported = 0;
    int auditd_fd = audit_open();
    int res = audit_get_rule_list(auditd_fd);

    audit_close(auditd_fd);

    if (!res) {
        merror(FIM_ERROR_WHODATA_READ_RULE);
    }

    for (i = 0; syscheck.dir[i]; i++) {
        // Check if dir[i] is set in whodata mode
        if ((syscheck.opts[i] & WHODATA_ACTIVE) == 0) {
            continue;
        }

        directory = fim_get_real_path(i);
        if (*directory == '\0') {
            free(directory);
            continue;
        }
        // Add whodata directories until max_audit_entries is reached.
        if (rules_added >= syscheck.max_audit_entries) {
            if (first_time || !reported) {
                merror(FIM_ERROR_WHODATA_MAXNUM_WATCHES, directory, syscheck.max_audit_entries);
            } else {
                mdebug1(FIM_ERROR_WHODATA_MAXNUM_WATCHES, directory, syscheck.max_audit_entries);
            }
            reported = 1;
            free(directory);
            break;
        }

        found = search_audit_rule(directory, WHODATA_PERMS, AUDIT_KEY);

        switch (found) {
        // The rule is not in audit_rule_list
        case 0:
            if (retval = audit_add_rule(directory, WHODATA_PERMS, AUDIT_KEY), retval > 0) {
                mdebug1(FIM_AUDIT_NEWRULE, directory);
                add_whodata_directory(directory);
                rules_added++;
            } else if (retval != -EEXIST) {
                if (first_time) {
                    mwarn(FIM_WARN_WHODATA_ADD_RULE, directory);
                } else {
                    mdebug1(FIM_WARN_WHODATA_ADD_RULE, directory);
                }
            } else {
                mdebug1(FIM_AUDIT_ALREADY_ADDED, directory);
            }
            break;

        case 1:
            mdebug1(FIM_AUDIT_RULEDUP, directory);
            break;

        default:
            merror(FIM_ERROR_WHODATA_CHECK_RULE);
            break;
        }
        // real_path can't be NULL
        free(directory);
    }

    return rules_added;
}


// LCOV_EXCL_START
void audit_reload_rules(void) {
    mdebug1(FIM_AUDIT_RELOADING_RULES);
    int rules_added = add_audit_rules_syscheck(false);
    mdebug1(FIM_AUDIT_RELOADED_RULES, rules_added);
}

void remove_audit_rule_syscheck(const char *path) {
    w_mutex_lock(&audit_mutex);
    // audit_rule_pending_removal(path, "wa", AUDIT_KEY);

    // Add one rule to be removed.
    audit_rule_manipulation++;
    w_mutex_unlock(&audit_mutex);
}
// LCOV_EXCL_STOP

void clean_rules(void) {
    char *real_path = NULL;
    int i;

    w_mutex_lock(&audit_mutex);

    audit_thread_active = 0;
    mdebug2(FIM_AUDIT_DELETE_RULE);

    for (i = 0; syscheck.dir[i]; i++) {
        if (syscheck.opts[i] & WHODATA_ACTIVE) {
            real_path = fim_get_real_path(i);
            audit_delete_rule(real_path, WHODATA_PERMS, AUDIT_KEY);
            free(real_path);
        }
    }
    audit_rules_list_free();
    w_mutex_unlock(&audit_mutex);
}

int audit_rules_init() {
    whodata_directories = OSList_Create();
    if (whodata_directories == NULL) {
        return -1;
    }

    OSList_SetFreeDataPointer(whodata_directories, (void (*)(void *))free_whodata_directory);
}

// LCOV_EXCL_START
void *audit_reload_thread() {
    sleep(RELOAD_RULES_INTERVAL);
    while (audit_thread_active) {
        w_mutex_lock(&audit_mutex);

        // Remove any pending rules
        // audit_cleanup_rules();

        // Reload rules
        audit_reload_rules();

        w_mutex_unlock(&audit_mutex);

        sleep(RELOAD_RULES_INTERVAL);
    }

    return NULL;
}
// LCOV_EXCL_STOP

#endif // ENABLE_AUDIT
#endif // __linux__
