/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * December 18, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef ENABLE_AUDIT

#include "shared.h"
#include "audit_op.h"

#ifdef WAZUH_UNIT_TESTING
#define static
#endif

static w_audit_rules_list *_audit_rules_list;


int audit_get_rule_list(int fd) {

    // Clean rules list
    audit_free_list();
    _audit_rules_list = audit_rules_list_init(25);

    int rc = audit_send(fd, AUDIT_LIST_RULES, NULL, 0);
    if (rc < 0 && rc != -EINVAL) {
        merror("Error sending rule list data request (%s)",strerror(-rc));
        return -1;
    }

    kernel_get_reply(fd);
    return 1;
}


int audit_print_reply(struct audit_reply *rep) {
    char *key = NULL;
    char *path = NULL;
    char perms[5] = {0};
    unsigned int i, offset = 0;
    if (rep->type == AUDIT_LIST_RULES) {
        for (i = 0; i < rep->ruledata->field_count; i++) {
            int field = rep->ruledata->fields[i] & ~AUDIT_OPERATORS;
            if (field == AUDIT_DIR || field == AUDIT_WATCH) {
                free(path);
                path = strndup(rep->ruledata->buf + offset, rep->ruledata->values[i]);
                offset += rep->ruledata->values[i];
            } else if (field == AUDIT_FILTERKEY) {
                free(key);
                if (rep->ruledata->values[i]) {
                    key = strndup(rep->ruledata->buf + offset, rep->ruledata->values[i]); //LCOV_EXCL_LINE
                    offset += rep->ruledata->values[i]; //LCOV_EXCL_LINE
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
            mdebug2("Audit rule loaded: -w %s -p %s -k %s",path, perms, key);
            if (_audit_rules_list) {
                w_audit_rule *rule;
                os_calloc(1, sizeof(w_audit_rule), rule);
                rule->path = strdup(path);
                rule->perm = strdup(perms);
                rule->key = strdup(key);
                audit_rules_list_append(_audit_rules_list, rule);
            }
        }

        free(key);
        free(path);
        return 1;
    }
    return 0;
}


void kernel_get_reply(int fd) {
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

            if (retval = audit_print_reply(&rep), retval == 0) {
                break;
            } else {
                i = 0;
            }
        }
    }
}


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

    char *full_path;
    os_malloc(strlen(cwd) + strlen(path) + 2, full_path);
    snprintf(full_path, strlen(cwd) + strlen(path) + 2, "%s/%s", cwd_ptr, file_ptr);

    free(cwd_ptr);

    return full_path;
}


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
    os_malloc(sizeof(struct audit_rule_data), myrule);
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
        mdebug2(FIM_STAT_FAILED, path, errno, strerror(errno));
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

    char *cmd;
    os_malloc(sizeof(char) * AUDIT_MAX_KEY_LEN + 1, cmd);

    if (snprintf(cmd, AUDIT_MAX_KEY_LEN, "key=%s", key) < 0) {
        //LCOV_EXCL_START
        free(cmd);
        retval = -1;
        goto end;
        //LCOV_EXCL_STOP
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
        mdebug2("Can't add or delete a rule (%d) = %s", retval, audit_errno_to_name(abs(retval)));
    }

end:
    audit_rule_free_data(myrule);
    audit_close(audit_handler);
    return retval;
}


int audit_add_rule(const char *path, const char *key) {
    return audit_manage_rules(ADD_RULE, path, key);
}


int audit_delete_rule(const char *path, const char *key) {
    return audit_manage_rules(DELETE_RULE, path, key);
}


w_audit_rules_list *audit_rules_list_init(int initialSize) {
    w_audit_rules_list *wlist;
    os_malloc(sizeof(w_audit_rules_list), wlist);
    wlist->list = (w_audit_rule **)malloc(initialSize * sizeof(w_audit_rule *));
    wlist->used = 0;
    wlist->size = initialSize;
    return wlist;
}


void audit_rules_list_append(w_audit_rules_list *wlist, w_audit_rule *element) {
    if (wlist) {
        if (wlist->used == wlist->size) {
            wlist->size *= 2;
            wlist->list = (w_audit_rule **)realloc(wlist->list, wlist->size * sizeof(w_audit_rule *));
            if (!wlist->list) {
                merror_exit(MEM_ERROR, errno, strerror(errno)); //LCOV_EXCL_LINE
            }
        }
        wlist->list[wlist->used++] = element;
    }
}


void audit_rules_list_free(w_audit_rules_list *wlist) {
    int i;

    if (wlist) {
        for (i=0; i < wlist->used; i++) {
            free(wlist->list[i]->path);
            free(wlist->list[i]->perm);
            free(wlist->list[i]->key);
            free(wlist->list[i]);
        }
        os_free(wlist->list);
        os_free(wlist);
    }
}


void audit_free_list(void) {
    if (_audit_rules_list) {
        audit_rules_list_free(_audit_rules_list);
    }
}


int search_audit_rule(const char *path, const char *perms, const char *key) {
    int found = 0;
    int i = 0;

    if (!(path && perms && key && _audit_rules_list)) {
        return -1;
    }

    while (!found && i < _audit_rules_list->used) {
        if (_audit_rules_list->list[i] && strcmp(_audit_rules_list->list[i]->path, path) == 0
            && strcmp(_audit_rules_list->list[i]->perm, perms) == 0
            && strcmp(_audit_rules_list->list[i]->key, key) == 0) {
                found = 1;
        }
        i++;
    }

    return found;
}

#endif
