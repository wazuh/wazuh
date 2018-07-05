/*
 * Copyright (C) 2018 Wazuh Inc.
 * June 13, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WIN32
#include "shared.h"
#include "external/procps/readproc.h"
#include <linux/audit.h>
#include <libaudit.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "syscheck.h"
#include <os_net/os_net.h>
#include "syscheck_op.h"

#define ADD_RULE 1
#define DELETE_RULE 2
#define AUDIT_CONF_FILE DEFAULTDIR "/etc/af_wazuh.conf"
#define AUDIT_CONF_LINK "/etc/audisp/plugins.d/af_wazuh.conf"
#define AUDIT_SOCKET DEFAULTDIR "/queue/ossec/audit"
#define BUF_SIZE 4096

// Global variables
W_Vector *audit_added_rules;
W_Vector *audit_added_dirs;
static regex_t regexCompiled_uid;
static regex_t regexCompiled_pid;
static regex_t regexCompiled_ppid;
static regex_t regexCompiled_gid;
static regex_t regexCompiled_auid;
static regex_t regexCompiled_euid;
static regex_t regexCompiled_cwd;
static regex_t regexCompiled_pname;
static regex_t regexCompiled_path0;
static regex_t regexCompiled_path1;
static regex_t regexCompiled_path2;
static regex_t regexCompiled_path3;
static regex_t regexCompiled_items;
pthread_mutex_t audit_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t audit_rules_mutex = PTHREAD_MUTEX_INITIALIZER;

// Convert audit relative paths into absolute paths
char *clean_audit_path(char *cwd, char *path) {

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


// Check if auditd is installed and running
int check_auditd_enabled(void) {

    PROCTAB *proc = openproc(PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLCOM );
    proc_t *proc_info;
    int auditd_pid = -1;

    while (proc_info = readproc(proc, NULL), proc_info != NULL) {
        if(strcmp(proc_info->cmd,"auditd") == 0) {
            auditd_pid = proc_info->tid;
            break;
        }
    }

    freeproc(proc_info);

    return auditd_pid;
}

int audit_restart() {
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

// Set audit socket configuration
int set_auditd_config(void) {
    FILE *fp;

    // Check that the plugin file is installed

    if (!IsLink(AUDIT_CONF_LINK) && !IsFile(AUDIT_CONF_LINK)) {
        // Check that the socket exists

        if (!IsSocket(AUDIT_SOCKET)) {
            return 0;
        }

        if (syscheck.restart_audit) {
            minfo("No socket found at '%s'. Restarting Auditd service.", AUDIT_SOCKET);
            return audit_restart();
        } else {
            mwarn("Audit socket (%s) does not exist. You need to restart Auditd. Who-data will be disabled.", AUDIT_SOCKET);
            return 1;
        }
    }

    minfo("Generating Auditd socket configuration file: %s", AUDIT_CONF_FILE);

    fp = fopen(AUDIT_CONF_FILE, "w");
    if (!fp) {
        merror(FOPEN_ERROR, AUDIT_CONF_FILE, errno, strerror(errno));
        return -1;
    }

    fprintf(fp, "active = yes\n");
    fprintf(fp, "direction = out\n");
    fprintf(fp, "path = builtin_af_unix\n");
    fprintf(fp, "type = builtin\n");
    fprintf(fp, "args = 0640 %s\n", AUDIT_SOCKET);
    fprintf(fp, "format = string\n");

    if (fclose(fp)) {
        merror(FCLOSE_ERROR, AUDIT_CONF_FILE, errno, strerror(errno));
        return -1;
    }

    if (symlink(AUDIT_CONF_FILE, AUDIT_CONF_LINK) < 0) {
        switch (errno) {
        case EEXIST:
            if (unlink(AUDIT_CONF_LINK) < 0) {
                merror(UNLINK_ERROR, AUDIT_CONF_LINK, errno, strerror(errno));
                return -1;
            }

            if (symlink(AUDIT_CONF_FILE, AUDIT_CONF_LINK) == 0) {
                break;
            }

            break;

        default: // Fallthrough
            merror(LINK_ERROR, AUDIT_CONF_LINK, AUDIT_CONF_FILE, errno, strerror(errno));
            return -1;
        }
    }

    if (syscheck.restart_audit) {
        minfo("Audisp configuration (%s) was modified. Restarting Auditd service.", AUDIT_CONF_FILE);
        return audit_restart();
    } else {
        mwarn("Audisp configuration was modified. You need to restart Auditd. Who-data will be disabled.");
        return 1;
    }
}


// Init audit socket
int init_auditd_socket(void) {
    int sfd;

    if (sfd = OS_ConnectUnixDomain(AUDIT_SOCKET, SOCK_STREAM, OS_MAXSTR), sfd < 0) {
        merror("Cannot connect to socket %s", AUDIT_SOCKET);
        return (-1);
    }

    return sfd;
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
        merror("audit_manage_rules(): Cannot stat %s", path);
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
        retval = abs(audit_add_rule_data(audit_handler, myrule, flags, AUDIT_ALWAYS));
    } else if (action == DELETE_RULE){
        retval = abs(audit_delete_rule_data(audit_handler, myrule, flags, AUDIT_ALWAYS));
    } else {
        retval = -1;
        goto end;
    }

    if (retval != 1) {
        mdebug2("audit_manage_rules(): Error adding/deleting rule (%d) = %s", retval, audit_errno_to_name(retval));
    }

end:
    audit_rule_free_data(myrule);
    audit_close(audit_handler);
    return retval;
}


// Add rule
int audit_add_rule(const char *path, const char *key) {
    int retval = 0;

    // Save dir into saved rules list
    w_mutex_lock(&audit_mutex);

    if (W_Vector_length(audit_added_rules) < syscheck.max_audit_entries) {
        if (retval = audit_manage_rules(ADD_RULE, path, key), retval >= 0) {
            W_Vector_insert(audit_added_rules, path);
        }
    } else {
        retval = -2;
    }

    w_mutex_unlock(&audit_mutex);
    return retval;
}


// Delete rule
int audit_delete_rule(const char *path, const char *key) {
    return audit_manage_rules(DELETE_RULE, path, key);
}


int audit_init(void) {

    // Check if auditd is installed and running.
    int aupid = check_auditd_enabled();
    if (aupid <= 0) {
        mdebug1("Auditd is not running.");
        return (-1);
    }

    // Check audit socket configuration
    switch (set_auditd_config()) {
    case -1:
        mdebug1("Cannot apply Audit config.");
        return (-1);
    case 0:
        break;
    default:
        return (-1);
    }

    // Initialize regular expressions

    static const char *pattern_uid = " uid=([0-9]*) ";
    if (regcomp(&regexCompiled_uid, pattern_uid, REG_EXTENDED)) {
        merror("Cannot compile uid regular expression.");
        return -1;
    }
    static const char *pattern_gid = " gid=([0-9]*) ";
    if (regcomp(&regexCompiled_gid, pattern_gid, REG_EXTENDED)) {
        merror("Cannot compile gid regular expression.");
        return -1;
    }
    static const char *pattern_auid = " auid=([0-9]*) ";
    if (regcomp(&regexCompiled_auid, pattern_auid, REG_EXTENDED)) {
        merror("Cannot compile auid regular expression.");
        return -1;
    }
    static const char *pattern_euid = " euid=([0-9]*) ";
    if (regcomp(&regexCompiled_euid, pattern_euid, REG_EXTENDED)) {
        merror("Cannot compile euid regular expression.");
        return -1;
    }
    static const char *pattern_pid = " pid=([0-9]*) ";
    if (regcomp(&regexCompiled_pid, pattern_pid, REG_EXTENDED)) {
        merror("Cannot compile pid regular expression.");
        return -1;
    }
    static const char *pattern_ppid = " ppid=([0-9]*) ";
    if (regcomp(&regexCompiled_ppid, pattern_ppid, REG_EXTENDED)) {
        merror("Cannot compile ppid regular expression.");
        return -1;
    }
    static const char *pattern_pname = " exe=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_pname, pattern_pname, REG_EXTENDED)) {
        merror("Cannot compile pname regular expression.");
        return -1;
    }
    static const char *pattern_cwd = " cwd=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_cwd, pattern_cwd, REG_EXTENDED)) {
        merror("Cannot compile cwd regular expression.");
        return -1;
    }
    static const char *pattern_path0 = " item=0 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path0, pattern_path0, REG_EXTENDED)) {
        merror("Cannot compile path0 regular expression.");
        return -1;
    }
    static const char *pattern_path1 = " item=1 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path1, pattern_path1, REG_EXTENDED)) {
        merror("Cannot compile path1 regular expression.");
        return -1;
    }
    static const char *pattern_path2 = " item=2 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path2, pattern_path2, REG_EXTENDED)) {
        merror("Cannot compile path2 regular expression.");
        return -1;
    }
    static const char *pattern_path3 = " item=3 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path3, pattern_path3, REG_EXTENDED)) {
        merror("Cannot compile path3 regular expression.");
        return -1;
    }
    static const char *pattern_items = " items=([0-9]*) ";
    if (regcomp(&regexCompiled_items, pattern_items, REG_EXTENDED)) {
        merror("Cannot compile items regular expression.");
        return -1;
    }

    return init_auditd_socket();
}

// Extract id: node=... type=CWD msg=audit(1529332881.955:3867): cwd="..."

char * audit_get_id(const char * event) {
    char * begin;
    char * end;
    char * id;
    size_t len;

    if (begin = strstr(event, "msg=audit("), !begin) {
        return NULL;
    }

    begin += 10;

    if (end = strchr(begin, ')'), !end) {
        return NULL;
    }

    len = end - begin;
    os_malloc(len + 1, id);
    memcpy(id, begin, len);
    id[len] = '\0';
    return id;
}


char *gen_audit_path(char *cwd, char *path0, char *path1) {

    char *gen_path = NULL;

    if (path0 && cwd) {
        if (path1) {
            if (path1[0] == '/') {
                gen_path = strdup(path1);
            } else if (path1[0] == '.' && path1[1] == '/') {
                char *full_path = malloc(strlen(cwd) + strlen(path1) + 2);
                snprintf(full_path, strlen(cwd) + strlen(path1) + 2, "%s/%s", cwd, (path1+2));
                gen_path = strdup(full_path);
                free(full_path);
            } else if (path1[0] == '.' && path1[1] == '.' && path1[2] == '/') {
                gen_path = clean_audit_path(cwd, path1);
            } else if (strncmp(path0, path1, strlen(path0)) == 0) {
                gen_path = malloc(strlen(cwd) + strlen(path1) + 2);
                snprintf(gen_path, strlen(cwd) + strlen(path1) + 2, "%s/%s", cwd, path1);
            } else {
                char *full_path = malloc(strlen(path0) + strlen(path1) + 2);
                snprintf(full_path, strlen(path0) + strlen(path1) + 2, "%s/%s", path0, path1);
                gen_path = strdup(full_path);
                free(full_path);
            }
        } else {
            if (path0[0] == '/') {
                gen_path = strdup(path0);
            } else if (path0[0] == '.' && path0[1] == '/') {
                char *full_path = malloc(strlen(cwd) + strlen(path0) + 2);
                snprintf(full_path, strlen(cwd) + strlen(path0) + 2, "%s/%s", cwd, (path0+2));
                gen_path = strdup(full_path);
                free(full_path);
            } else if (path0[0] == '.' && path0[1] == '.' && path0[2] == '/') {
                gen_path = clean_audit_path(cwd, path0);
            } else {
                gen_path = malloc(strlen(cwd) + strlen(path0) + 2);
                snprintf(gen_path, strlen(cwd) + strlen(path0) + 2, "%s/%s", cwd, path0);
            }
        }
    }
    return gen_path;
}

void audit_parse(char * buffer) {
    char *pkey;
    char *psuccess;
    char *pconfig;
    char *pdelete;
    regmatch_t match[2];
    int match_size;
    char *uid = NULL;
    char *gid = NULL;
    char *auid = NULL;
    char *euid = NULL;
    char *pid = NULL;
    char *ppid = NULL;
    char *pname = NULL;
    char *path0 = NULL;
    char *path1 = NULL;
    char *path2 = NULL;
    char *path3 = NULL;
    char *cwd = NULL;
    char *file_path = NULL;
    whodata_evt *w_evt;
    unsigned int items = 0;

    if (pkey = strstr(buffer,"key=\"wazuh_fim\""), pkey) { // Parse only 'wazuh_fim' events.

        if ((pconfig = strstr(buffer,"type=CONFIG_CHANGE"), pconfig)
        && ((pdelete = strstr(buffer,"op=remove_rule"), pdelete) ||
            (pdelete = strstr(buffer,"op=\"remove_rule\""), pdelete))) { // Detect rules modification.
            audit_thread_active = 0;
            mwarn("Detected Audit rules manipulation: Rule removed.");
            // Send alert
            char msg_alert[512 + 1];
            snprintf(msg_alert, 512, "ossec: Audit: Detected rules manipulation: Rule removed");
            SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);

        } else if (psuccess = strstr(buffer,"success=yes"), psuccess) {

            os_calloc(1, sizeof(whodata_evt), w_evt);

            // Items
            if(regexec(&regexCompiled_items, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *chr_item = malloc(match_size + 1);
                snprintf (chr_item, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                items = atoi(chr_item);
                free(chr_item);
            }
            // user_name & user_id
            if(regexec(&regexCompiled_uid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                uid = malloc(match_size + 1);
                snprintf (uid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                const char *user = get_user("",atoi(uid), NULL);
                w_evt->user_name = strdup(user);
                w_evt->user_id = strdup(uid);
                free(uid);
            }
            // audit_name & audit_uid
            if(regexec(&regexCompiled_auid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                auid = malloc(match_size + 1);
                snprintf (auid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                const char *user = get_user("",atoi(auid), NULL);
                w_evt->audit_name = strdup(user);
                w_evt->audit_uid = strdup(auid);
                free(auid);
            }
            // effective_name && effective_uid
            if(regexec(&regexCompiled_euid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                euid = malloc(match_size + 1);
                snprintf (euid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                const char *user = get_user("",atoi(euid), NULL);
                w_evt->effective_name = strdup(user);
                w_evt->effective_uid = strdup(euid);
                free(euid);
            }
            // group_name & group_id
            if(regexec(&regexCompiled_gid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                gid = malloc(match_size + 1);
                snprintf (gid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->group_name = strdup(get_group(atoi(gid)));
                w_evt->group_id = strdup(gid);
                free(gid);
            }
            // process_id
            if(regexec(&regexCompiled_pid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                pid = malloc(match_size + 1);
                snprintf (pid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->process_id = atoi(pid);
                free(pid);
            }
            // ppid
            if(regexec(&regexCompiled_ppid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                ppid = malloc(match_size + 1);
                snprintf (ppid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->ppid = atoi(ppid);
                free(ppid);
            }
            // process_name
            if(regexec(&regexCompiled_pname, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                pname = malloc(match_size + 1);
                snprintf (pname, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->process_name = strdup(pname);
                free(pname);
            }
            // cwd
            if(regexec(&regexCompiled_cwd, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                cwd = malloc(match_size + 1);
                snprintf (cwd, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            }
            // path0
            if(regexec(&regexCompiled_path0, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                path0 = malloc(match_size + 1);
                snprintf (path0, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            }
            // path1
            if(regexec(&regexCompiled_path1, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                path1 = malloc(match_size + 1);
                snprintf (path1, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            }

            switch(items) {

                case 1:
                case 2:
                    if (file_path = gen_audit_path(cwd, path0, path1), file_path) {
                        w_evt->path = file_path;
                        mdebug1("audit_event: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, path=%s, pname=%s",
                            w_evt->user_name,
                            w_evt->audit_name,
                            w_evt->effective_name,
                            w_evt->group_name,
                            w_evt->process_id,
                            w_evt->ppid,
                            w_evt->path,
                            w_evt->process_name);
                        realtime_checksumfile(w_evt->path, w_evt);
                    }
                    break;

                case 4:
                    // path2
                    if(regexec(&regexCompiled_path2, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        path2 = malloc(match_size + 1);
                        snprintf (path2, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                    }
                    // path3
                    if(regexec(&regexCompiled_path3, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        path3 = malloc(match_size + 1);
                        snprintf (path3, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                    }

                    // Send event 1/2
                    char *file_path1;
                    if (file_path1 = gen_audit_path(cwd, path0, path2), file_path1) {
                        w_evt->path = file_path1;
                        mdebug1("audit_event_1/2: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, path=%s, pname=%s",
                            w_evt->user_name,
                            w_evt->audit_name,
                            w_evt->effective_name,
                            w_evt->group_name,
                            w_evt->process_id,
                            w_evt->ppid,
                            w_evt->path,
                            w_evt->process_name);

                        realtime_checksumfile(w_evt->path, w_evt);
                        free(file_path1);
                    }

                    // Send event 2/2
                    char *file_path2;
                    if (file_path2 = gen_audit_path(cwd, path1, path3), file_path2) {
                        w_evt->path = file_path2;
                        mdebug1("audit_event_2/2: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, path=%s, pname=%s",
                            w_evt->user_name,
                            w_evt->audit_name,
                            w_evt->effective_name,
                            w_evt->group_name,
                            w_evt->process_id,
                            w_evt->ppid,
                            w_evt->path,
                            w_evt->process_name);

                        realtime_checksumfile(w_evt->path, w_evt);
                    }
                    free(path2);
                    free(path3);
                    break;
            }
            free(cwd);
            free(path0);
            free(path1);

            free_whodata_event(w_evt);
        }
    }
}


void * audit_main(int * audit_sock) {
    size_t byteRead;
    char * cache;
    char * cache_id = NULL;
    char * line;
    char * endline;
    size_t cache_i = 0;
    size_t buffer_i = 0; // Buffer offset
    size_t len;
    fd_set fdset;
    struct timeval timeout;

    char *buffer;
    buffer = malloc(BUF_SIZE * sizeof(char));
    os_malloc(BUF_SIZE, cache);

    mdebug1("Reading events from Audit socket...");
    w_mutex_lock(&audit_mutex);
    audit_thread_active = 1;
    pthread_cond_signal(&audit_thread_started);
    w_mutex_unlock(&audit_mutex);

    while (audit_thread_active) {
        FD_ZERO(&fdset);
        FD_SET(*audit_sock, &fdset);

        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(*audit_sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            merror(SELECT_ERROR, errno, strerror(errno));
            sleep(1);
            continue;

        case 0:
            if (cache_i) {
                // Flush cache
                audit_parse(cache);
                cache_i = 0;
            }

            continue;

        default:
            if (!audit_thread_active) {
                continue;
            }

            break;
        }

        if (byteRead = recv(*audit_sock, buffer + buffer_i, BUF_SIZE - buffer_i - 1, 0), !byteRead) {
            // Connection closed
            minfo("Audit: connection closed.");
            // Send alert
            char msg_alert[512 + 1];
            snprintf(msg_alert, 512, "ossec: Audit: Connection closed");
            SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);
            break;
        }

        buffer[buffer_i += byteRead] = '\0';

        // Find first endline

        if (endline = strchr(buffer, '\n'), !endline) {
            // No complete line yet.
            continue;
        }

        // Get all the lines
        line = buffer;

        char * id;

        do {
            *endline = '\0';

            if (id = audit_get_id(line), id) {
                // If there was cached data and the ID is different, parse cache first

                if (cache_id && strcmp(cache_id, id) && cache_i) {
                    audit_parse(cache);
                    cache_i = 0;
                }

                // Append to cache
                len = endline - line;
                if (cache_i + len + 1 > sizeof(cache)) {
                    strncpy(cache + cache_i, line, len);
                    cache_i += len;
                    cache[cache_i++] = '\n';
                    cache[cache_i] = '\0';
                } else {
                    merror("Caching Audit message: event too long.");
                }

                free(cache_id);
                cache_id = id;
            } else {
                merror("Couldn't get event ID from Audit message.");
                mdebug1("Line: '%s'", line);
            }

            line = endline + 1;
        } while (*line && (endline = strchr(line, '\n'), endline));

        // If some data remains in the buffer, move it to the beginning

        if (*line) {
            buffer_i = strlen(line);
            memmove(buffer, line, buffer_i);
        } else {
            buffer_i = 0;
        }
    }

    // Auditd is not runnig or socket closed.
    merror("Audit thread finished.");
    free(buffer);
    close(*audit_sock);

    regfree(&regexCompiled_uid);
    regfree(&regexCompiled_auid);
    regfree(&regexCompiled_euid);
    regfree(&regexCompiled_gid);
    regfree(&regexCompiled_pid);
    regfree(&regexCompiled_ppid);
    regfree(&regexCompiled_cwd);
    regfree(&regexCompiled_path0);
    regfree(&regexCompiled_path1);
    regfree(&regexCompiled_pname);
    regfree(&regexCompiled_items);
    // Change Audit monitored folders to Inotify.
    int i;
    w_mutex_lock(&audit_rules_mutex);
    if (audit_added_dirs) {
        for (i = 0; i < W_Vector_length(audit_added_dirs); i++) {
            realtime_adddir(W_Vector_get(audit_added_dirs, i), 0);
        }
        W_Vector_free(audit_added_dirs);
    }
    w_mutex_unlock(&audit_rules_mutex);

    // Clean Audit added rules.
    clean_rules();

    return NULL;
}


void clean_rules(void) {
    int i;
    w_mutex_lock(&audit_mutex);
    audit_thread_active = 0;

    if (audit_added_rules) {
        mdebug2("Deleting Audit rules...");
        for (i = 0; i < W_Vector_length(audit_added_rules); i++) {
            audit_delete_rule(W_Vector_get(audit_added_rules, i), AUDIT_KEY);
        }
        W_Vector_free(audit_added_rules);
    }
    w_mutex_unlock(&audit_mutex);
}
#endif
