/*
 * Copyright (C) 2018 Wazuh Inc.
 * December 18, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "audit_op.h"


int audit_send(int fd, int type, const void *data, unsigned int size) {
    int rc;
    int seq;

    rc = __audit_send(fd, type, data, size, &seq);
    if (rc == 0)
        rc = seq;
    return rc;
}


int audit_get_rule_list(int fd) {

    int rc = audit_send(fd, AUDIT_LIST_RULES, NULL, 0);
    if (rc < 0 && rc != -EINVAL) {
        merror("Error sending rule list data request (%s)",strerror(-rc));
        return -1;
    }

    get_reply(fd);
    return 1;
}


int audit_print_reply(struct audit_reply *rep) {
    char *key;
    char *path;
    char perms[5] = {0};
    unsigned int i, offset = 0;
    if (rep->type == AUDIT_LIST_RULES) {
        for (i = 0; i < rep->ruledata->field_count; i++) {
            int field = rep->ruledata->fields[i] & ~AUDIT_OPERATORS;
            if (field == AUDIT_DIR || field == AUDIT_WATCH) {
                path = strndup(rep->ruledata->buf + offset, rep->ruledata->values[i]);
                offset += rep->ruledata->values[i];
            } else if (field == AUDIT_FILTERKEY) {
                if (rep->ruledata->values[i]) {
                    key = strndup(rep->ruledata->buf + offset, rep->ruledata->values[i]);
                    offset += rep->ruledata->values[i];
                } else {
                    key = strdup("");
                }
            } else if (field == AUDIT_PERM) {
                int val=rep->ruledata->values[i];
                perms[0] = 0;
                if (val & AUDIT_PERM_READ)
                    strcat(perms, "r");
                if (val & AUDIT_PERM_WRITE)
                    strcat(perms, "w");
                if (val & AUDIT_PERM_EXEC)
                    strcat(perms, "x");
                if (val & AUDIT_PERM_ATTR)
                    strcat(perms, "a");
            }
        }
        if (path && key) {
            minfo("(Audit) -w %s -p %s -k %s",path, perms, key);
            free(key);
            free(path);
        }
        return 1;
    }
    return 0;
}


void get_reply(int fd) {
    int i, retval;
    int timeout = 40;
    struct audit_reply rep;
    fd_set read_mask;
    FD_ZERO(&read_mask);
    FD_SET(fd, &read_mask);

    for (i = 0; i < timeout; i++) {
        struct timeval t;

        t.tv_sec  = 0;
        t.tv_usec = 100000;
        do {
            retval=select(fd+1, &read_mask, NULL, NULL, &t);
        } while (retval < 0 && errno == EINTR);

        retval = audit_get_reply(fd, &rep, GET_REPLY_NONBLOCKING, 0);
        if (retval > 0) {
            if (rep.type == NLMSG_ERROR && rep.error->error == 0) {
                i = 0;
                continue;
            }

            if ((retval = audit_print_reply(&rep)) == 0) {
                break;
            } else {
                i = 0;
            }
        }
    }
}


// Converts Audit relative paths into absolute paths
char *audit_clean_path(char *cwd, char *path) {

    char *file_ptr = path;
    char *cwd_ptr = strdup(cwd);

    int j, ptr = 0;

    while (file_ptr[ptr] != '\0' && strlen(file_ptr) >= 3) {
        if (file_ptr[ptr] == '.' && file_ptr[ptr + 1] == '.' && file_ptr[ptr + 2] == '/') {
            file_ptr += 3;
            ptr = 0;
            for(j = strlen(cwd_ptr); cwd_ptr[j] != '/' && j >= 0; j--);
            cwd_ptr[j] = '\0';
        } else
            ptr++;
    }

    char *full_path = malloc(strlen(cwd) + strlen(path) + 2);
    snprintf(full_path, strlen(cwd) + strlen(path) + 2, "%s/%s", cwd_ptr, file_ptr);

    free(cwd_ptr);

    return full_path;
}


// Restart Auditd service
int audit_restart(void) {

    wfd_t * wfd;
    int status;
    char buffer[4096];
    char * command[] = { "service", "auditd", "restart", NULL };

    if (wfd = wpopenv(*command, command, W_BIND_STDERR), !wfd) {
        merror("Could not launch command to restart Auditd: %s (%d)", strerror(errno), errno);
        return -1;
    }

    // Print stderr
    while (fgets(buffer, sizeof(buffer), wfd->file)) {
        mdebug1("auditd: %s", buffer);
    }

    switch (status = wpclose(wfd), WEXITSTATUS(status)) {
    case 0:
        return 0;
    case 127:
        // exec error
        merror("Could not launch command to restart Auditd.");
        return -1;
    default:
        merror("Could not restart Auditd service.");
        return -1;
    }
}


// Add / delete rules
int audit_manage_rules(int action, const char *path, const char *key) {

    int retval, output;
    int type;
    struct stat buf;
    int audit_handler;

    audit_handler = audit_open();
    if (audit_handler < 0) {
        return (-1);
    }

    struct audit_rule_data *myrule = NULL;
    myrule = malloc(sizeof(struct audit_rule_data));
    memset(myrule, 0, sizeof(struct audit_rule_data));

    // Check path
    if (stat(path, &buf) == 0) {
        if (S_ISDIR(buf.st_mode)){
            type = AUDIT_DIR;
        }
        else {
            type = AUDIT_WATCH;
        }
    } else {
        mdebug2("audit_manage_rules(): Cannot stat %s", path);
        retval = -1;
        goto end;
    }

    // Set watcher
    output = audit_add_watch_dir(type, &myrule, path);
    if (output) {
        mdebug2("audit_add_watch_dir = (%d) %s", output, audit_errno_to_name(abs(output)));
        retval = -1;
        goto end;
    }

    // Set permisions
    int permisions = 0;
    permisions |= AUDIT_PERM_WRITE;
    permisions |= AUDIT_PERM_ATTR;
    output = audit_update_watch_perms(myrule, permisions);
    if (output) {
        mdebug2("audit_update_watch_perms = (%d) %s", output, audit_errno_to_name(abs(output)));
        retval = -1;
        goto end;
    }

    // Set key
    int flags = AUDIT_FILTER_EXIT & AUDIT_FILTER_MASK;

    if (strlen(key) > (AUDIT_MAX_KEY_LEN - 5)) {
        retval = -1;
        goto end;
    }

    char *cmd = malloc(sizeof(char) * AUDIT_MAX_KEY_LEN + 1);

    if (snprintf(cmd, AUDIT_MAX_KEY_LEN, "key=%s", key) < 0) {
        free(cmd);
        retval = -1;
        goto end;
    } else {
        output = audit_rule_fieldpair_data(&myrule, cmd, flags);
        if (output) {
            mdebug2("audit_rule_fieldpair_data = (%d) %s", output, audit_errno_to_name(abs(output)));
            free(cmd);
            retval = -1;
            goto end;
        }
        free(cmd);
    }

    // Add/Delete rule
    if (action == ADD_RULE) {
        retval = audit_add_rule_data(audit_handler, myrule, flags, AUDIT_ALWAYS);
    } else if (action == DELETE_RULE){
        retval = audit_delete_rule_data(audit_handler, myrule, flags, AUDIT_ALWAYS);
    } else {
        retval = -1;
        goto end;
    }

    if (retval <= 0) {
        mdebug2("audit_manage_rules(): Error adding/deleting rule (%d) = %s", retval, audit_errno_to_name(abs(retval)));
    }

end:
    audit_rule_free_data(myrule);
    audit_close(audit_handler);
    return retval;
}


// Add rule into Auditd rules list
int audit_add_rule(const char *path, const char *key) {
    return audit_manage_rules(ADD_RULE, path, key);
}


// Delete rule
int audit_delete_rule(const char *path, const char *key) {
    return audit_manage_rules(DELETE_RULE, path, key);
}


// Check if exists rule '-a task,never'
int audit_check_lock_output(void) {
    int retval;
    int audit_handler;

    int flags = AUDIT_FILTER_TASK;

    audit_handler = audit_open();
    if (audit_handler < 0) {
        return (-1);
    }

    struct audit_rule_data *myrule = NULL;
    myrule = malloc(sizeof(struct audit_rule_data));
    memset(myrule, 0, sizeof(struct audit_rule_data));

    retval = audit_add_rule_data(audit_handler, myrule, flags, AUDIT_NEVER);

    if (retval == -17) {
        audit_rule_free_data(myrule);
        audit_close(audit_handler);
        return 1;
    } else {
        // Delete if it was inserted
        retval = audit_delete_rule_data(audit_handler, myrule, flags, AUDIT_NEVER);
        audit_rule_free_data(myrule);
        audit_close(audit_handler);
        if (retval < 0) {
            mdebug2("audit_delete_rule_data = (%i) %s", retval, audit_errno_to_name(abs(retval)));
            merror("Error removing test rule. Audit output is blocked.");
            return 1;
        }
        return 0;
    }
}
