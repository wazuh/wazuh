/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 13, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef __linux__
#include "shared.h"
#include "external/procps/readproc.h"

#include <sys/socket.h>
#include <sys/un.h>
#include "syscheck.h"
#include <os_net/os_net.h>
#include "syscheck_op.h"
#include "audit_op.h"

#define AUDIT_CONF_FILE DEFAULTDIR "/etc/af_wazuh.conf"
#define PLUGINS_DIR_AUDIT_2 "/etc/audisp/plugins.d"
#define PLUGINS_DIR_AUDIT_3 "/etc/audit/plugins.d"
#define AUDIT_CONF_LINK "af_wazuh.conf"
#define AUDIT_SOCKET DEFAULTDIR "/queue/ossec/audit"
#define BUF_SIZE 6144
#define AUDIT_KEY "wazuh_fim"
#define AUDIT_LOAD_RETRIES 5 // Max retries to reload Audit rules
#define MAX_CONN_RETRIES 5 // Max retries to reconnect to Audit socket
#define RELOAD_RULES_INTERVAL 30 // Seconds to re-add Audit rules

#define AUDIT_HEALTHCHECK_DIR DEFAULTDIR "/tmp"
#define AUDIT_HEALTHCHECK_KEY "wazuh_hc"
#define AUDIT_HEALTHCHECK_FILE AUDIT_HEALTHCHECK_DIR "/audit_hc"

// Global variables
W_Vector *audit_added_rules;
W_Vector *audit_added_dirs;
W_Vector *audit_loaded_rules;
pthread_mutex_t audit_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t audit_hc_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t audit_rules_mutex = PTHREAD_MUTEX_INITIALIZER;
int auid_err_reported;
volatile int hc_thread_active;

volatile int audit_health_check_creation;
volatile int audit_health_check_deletion;

static unsigned int count_reload_retries;

#ifdef ENABLE_AUDIT

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
static regex_t regexCompiled_path4;
static regex_t regexCompiled_items;
static regex_t regexCompiled_inode;
static regex_t regexCompiled_dir;
static regex_t regexCompiled_syscall;


// Check if Auditd is installed and running
int check_auditd_enabled(void) {

    PROCTAB *proc = openproc(PROC_FILLSTAT | PROC_FILLSTATUS | PROC_FILLCOM );
    proc_t *proc_info;
    int auditd_pid = -1;

    if (!proc) {
        return -1;
    }

    while (proc_info = readproc(proc, NULL), proc_info != NULL) {
        if(strcmp(proc_info->cmd,"auditd") == 0) {
            auditd_pid = proc_info->tid;
            freeproc(proc_info);
            break;
        }

        freeproc(proc_info);
    }

    closeproc(proc);
    return auditd_pid;
}


// Set Auditd socket configuration
int set_auditd_config(void) {

    FILE *fp;
    char audit_path[50] = {0};

    // Check audisp version
    if (IsDir(PLUGINS_DIR_AUDIT_3) == 0) {
        // Audit 3.X
        snprintf(audit_path, sizeof(audit_path) - 1, "%s/%s", PLUGINS_DIR_AUDIT_3, AUDIT_CONF_LINK);
    } else if (IsDir(PLUGINS_DIR_AUDIT_2) == 0) {
        // Audit 2.X
        snprintf(audit_path, sizeof(audit_path) - 1, "%s/%s", PLUGINS_DIR_AUDIT_2, AUDIT_CONF_LINK);
    } else {
        return 0;
    }

    // Check that the plugin file is installed

    if (!IsLink(audit_path) && !IsFile(audit_path)) {
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

    if (symlink(AUDIT_CONF_FILE, audit_path) < 0) {
        switch (errno) {
        case EEXIST:
            if (unlink(audit_path) < 0) {
                merror(UNLINK_ERROR, audit_path, errno, strerror(errno));
                return -1;
            }

            if (symlink(AUDIT_CONF_FILE, audit_path) == 0) {
                break;
            }

            break;

        default: // Fallthrough
            merror(LINK_ERROR, audit_path, AUDIT_CONF_FILE, errno, strerror(errno));
            return -1;
        }
    }

    if (syscheck.restart_audit) {
        minfo("Audit plugin configuration (%s) was modified. Restarting Auditd service.", AUDIT_CONF_FILE);
        return audit_restart();
    } else {
        mwarn("Audit plugin configuration was modified. You need to restart Auditd. Who-data will be disabled.");
        return 1;
    }
}


// Init Audit events socket
int init_auditd_socket(void) {
    int sfd;

    if (sfd = OS_ConnectUnixDomain(AUDIT_SOCKET, SOCK_STREAM, OS_MAXSTR), sfd < 0) {
        merror("Cannot connect to socket %s", AUDIT_SOCKET);
        return (-1);
    }

    return sfd;
}


int add_audit_rules_syscheck(void) {
    unsigned int i = 0;
    unsigned int rules_added = 0;

    int fd = audit_open();
    int res = audit_get_rule_list(fd);
    audit_close(fd);

    if (!res) {
        merror("Could not read audit loaded rules.");
    }

    while (syscheck.dir[i] != NULL) {
        if (syscheck.opts[i] & CHECK_WHODATA) {
            int retval;
            if (W_Vector_length(audit_added_rules) < syscheck.max_audit_entries) {
                int found = search_audit_rule(syscheck.dir[i], "wa", AUDIT_KEY);
                if (found == 0) {
                    if (retval = audit_add_rule(syscheck.dir[i], AUDIT_KEY), retval > 0) {
                        mdebug1("Added audit rule for monitoring directory: '%s'.", syscheck.dir[i]);
                        w_mutex_lock(&audit_rules_mutex);
                        W_Vector_insert_unique(audit_added_rules, syscheck.dir[i]);
                        w_mutex_unlock(&audit_rules_mutex);
                        rules_added++;
                    } else {
                        merror("Error adding audit rule for directory (%i): %s .",retval, syscheck.dir[i]);
                    }
                } else if (found == 1) {
                    mdebug1("Audit rule for monitoring directory '%s' already added.", syscheck.dir[i]);
                    w_mutex_lock(&audit_rules_mutex);
                    W_Vector_insert_unique(audit_added_rules, syscheck.dir[i]);
                    w_mutex_unlock(&audit_rules_mutex);
                    rules_added++;
                } else {
                    merror("Error checking Audit rules list.");
                }
            } else {
                merror("Unable to monitor who-data for directory: '%s' - Maximum size permitted (%d).", syscheck.dir[i], syscheck.max_audit_entries);
            }
        }
        i++;
    }

    return rules_added;
}


// Initialize regular expressions
int init_regex(void) {

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
    static const char *pattern_inode = " item=[0-9] name=.* inode=([0-9]*)";
    if (regcomp(&regexCompiled_inode, pattern_inode, REG_EXTENDED)) {
        merror("Cannot compile inode regular expression.");
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
    static const char *pattern_path4 = " item=4 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path4, pattern_path4, REG_EXTENDED)) {
        merror("Cannot compile path4 regular expression.");
        return -1;
    }
    static const char *pattern_items = " items=([0-9]*) ";
    if (regcomp(&regexCompiled_items, pattern_items, REG_EXTENDED)) {
        merror("Cannot compile items regular expression.");
        return -1;
    }
    static const char *pattern_dir = " dir=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_dir, pattern_dir, REG_EXTENDED)) {
        merror("Cannot compile dir regular expression.");
        return -1;
    }
    static const char *pattern_syscall = " syscall=([0-9]*)";
    if (regcomp(&regexCompiled_syscall, pattern_syscall, REG_EXTENDED)) {
        merror("Cannot compile syscall regular expression.");
        return -1;
    }
    return 0;
}


// Init Audit events reader thread
int audit_init(void) {

    audit_health_check_creation = 0;
    audit_health_check_deletion = 0;

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

    // Add Audit rules
    audit_added_rules = W_Vector_init(10);
    audit_added_dirs = W_Vector_init(20);
    int rules_added = add_audit_rules_syscheck();
    if (rules_added < 1){
        mdebug1("No rules added. Audit events reader thread will not start.");
        return (-1);
    }

    // Initialize Audit socket
    static int audit_socket;
    audit_socket = init_auditd_socket();
    if (audit_socket < 0) {
        return -1;
    }

    int regex_comp = init_regex();
    if (regex_comp < 0) {
        return -1;
    }

    // Perform Audit healthcheck
    if(audit_health_check(audit_socket)) {
        merror("Audit health check couldn't be completed correctly.");
        return -1;
    }

    // Start reading thread
    mdebug1("Starting Auditd events reader thread...");

    atexit(clean_rules);
    auid_err_reported = 0;

    // Start audit thread
    minfo("Starting FIM Whodata engine...");
    w_cond_init(&audit_thread_started, NULL);
    w_cond_init(&audit_db_consistency, NULL);
    w_create_thread(audit_main, &audit_socket);
    w_mutex_lock(&audit_mutex);
    while (!audit_thread_active)
        w_cond_wait(&audit_thread_started, &audit_mutex);
    w_mutex_unlock(&audit_mutex);
    return 1;

}

void audit_set_db_consistency(void) {
    w_mutex_lock(&audit_mutex);
    audit_db_consistency_flag = 1;
    w_cond_signal(&audit_db_consistency);
    w_mutex_unlock(&audit_mutex);
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
                char *full_path;
                os_malloc(strlen(cwd) + strlen(path1) + 2, full_path);
                snprintf(full_path, strlen(cwd) + strlen(path1) + 2, "%s/%s", cwd, (path1+2));
                gen_path = strdup(full_path);
                free(full_path);
            } else if (path1[0] == '.' && path1[1] == '.' && path1[2] == '/') {
                gen_path = audit_clean_path(cwd, path1);
            } else if (strncmp(path0, path1, strlen(path0)) == 0) {
                os_malloc(strlen(cwd) + strlen(path1) + 2, gen_path);
                snprintf(gen_path, strlen(cwd) + strlen(path1) + 2, "%s/%s", cwd, path1);
            } else {
                char *full_path;
                os_malloc(strlen(path0) + strlen(path1) + 2, full_path);
                snprintf(full_path, strlen(path0) + strlen(path1) + 2, "%s/%s", path0, path1);
                gen_path = strdup(full_path);
                free(full_path);
            }
        } else {
            if (path0[0] == '/') {
                gen_path = strdup(path0);
            } else if (path0[0] == '.' && path0[1] == '/') {
                char *full_path;
                os_malloc(strlen(cwd) + strlen(path0) + 2, full_path);
                snprintf(full_path, strlen(cwd) + strlen(path0) + 2, "%s/%s", cwd, (path0+2));
                gen_path = strdup(full_path);
                free(full_path);
            } else if (path0[0] == '.' && path0[1] == '.' && path0[2] == '/') {
                gen_path = audit_clean_path(cwd, path0);
            } else {
                os_malloc(strlen(cwd) + strlen(path0) + 2, gen_path);
                snprintf(gen_path, strlen(cwd) + strlen(path0) + 2, "%s/%s", cwd, path0);
            }
        }
    }
    return gen_path;
}


void audit_parse(char *buffer) {
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
    char *path4 = NULL;
    char *cwd = NULL;
    char *file_path = NULL;
    char *syscall = NULL;
    char *inode = NULL;
    whodata_evt *w_evt;
    unsigned int items = 0;
    char *inode_temp;
    unsigned int filter_key;

    // Checks if the key obtained is one of those configured to monitor
    filter_key = filterkey_audit_events(buffer);

    switch (filter_key) {
    case 1: // "wazuh_fim"
        if ((pconfig = strstr(buffer,"type=CONFIG_CHANGE"), pconfig)
            && ((pdelete = strstr(buffer,"op=remove_rule"), pdelete) ||
            (pdelete = strstr(buffer,"op=\"remove_rule\""), pdelete))) { // Detect rules modification.

            // Filter rule removed
            char *p_dir = NULL;
            if(regexec(&regexCompiled_dir, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_calloc(1, match_size + 1, p_dir);
                snprintf (p_dir, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            }

            if (p_dir && *p_dir != '\0') {
                minfo("Monitored directory '%s' was removed: Audit rule removed.", p_dir);
                // Send alert
                char msg_alert[512 + 1];
                snprintf(msg_alert, 512, "ossec: Audit: Monitored directory was removed: Audit rule removed");
                SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);
            } else {
                mwarn("Detected Audit rules manipulation: Audit rules removed.");
                // Send alert
                char msg_alert[512 + 1];
                snprintf(msg_alert, 512, "ossec: Audit: Detected rules manipulation: Audit rules removed");
                SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);

                count_reload_retries++;

                if (count_reload_retries < AUDIT_LOAD_RETRIES) {
                    // Reload rules
                    audit_reload_rules();
                } else {
                    // Send alert
                    char msg_alert[512 + 1];
                    snprintf(msg_alert, 512, "ossec: Audit: Detected rules manipulation: Max rules reload retries");
                    SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);
                    // Stop thread
                    audit_thread_active = 0;
                }
            }

            free(p_dir);
        }
        // Fallthrough
    case 2:
        if (psuccess = strstr(buffer,"success=yes"), psuccess) {

            os_calloc(1, sizeof(whodata_evt), w_evt);

            // Items
            if(regexec(&regexCompiled_items, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *chr_item;
                os_malloc(match_size + 1, chr_item);
                snprintf (chr_item, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                items = atoi(chr_item);
                free(chr_item);
            }
            // user_name & user_id
            if(regexec(&regexCompiled_uid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, uid);
                snprintf (uid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                const char *user = get_user("",atoi(uid), NULL);
                w_evt->user_name = strdup(user);
                w_evt->user_id = strdup(uid);
                free(uid);
            }
            // audit_name & audit_uid
            if(regexec(&regexCompiled_auid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, auid);
                snprintf (auid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                if (strcmp(auid, "4294967295") == 0) { // Invalid auid (-1)
                    if (!auid_err_reported) {
                        minfo("Audit: Invalid 'auid' value readed. Check Audit configuration (PAM).");
                        auid_err_reported = 1;
                    }
                    w_evt->audit_name = NULL;
                    w_evt->audit_uid = NULL;
                } else {
                    const char *user = get_user("",atoi(auid), NULL);
                    w_evt->audit_name = strdup(user);
                    w_evt->audit_uid = strdup(auid);
                }
                free(auid);
            }
            // effective_name && effective_uid
            if(regexec(&regexCompiled_euid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, euid);
                snprintf (euid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                const char *user = get_user("",atoi(euid), NULL);
                w_evt->effective_name = strdup(user);
                w_evt->effective_uid = strdup(euid);
                free(euid);
            }
            // group_name & group_id
            if(regexec(&regexCompiled_gid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, gid);
                snprintf (gid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->group_name = strdup(get_group(atoi(gid)));
                w_evt->group_id = strdup(gid);
                free(gid);
            }
            // process_id
            if(regexec(&regexCompiled_pid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, pid);
                snprintf (pid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->process_id = atoi(pid);
                free(pid);
            }
            // ppid
            if(regexec(&regexCompiled_ppid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, ppid);
                snprintf (ppid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->ppid = atoi(ppid);
                free(ppid);
            }
            // process_name
            if(regexec(&regexCompiled_pname, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, pname);
                snprintf (pname, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->process_name = strdup(pname);
                free(pname);
            }
            // cwd
            if(regexec(&regexCompiled_cwd, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, cwd);
                snprintf (cwd, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            }
            // path0
            if(regexec(&regexCompiled_path0, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, path0);
                snprintf (path0, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            }
            // path1
            if(regexec(&regexCompiled_path1, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, path1);
                snprintf (path1, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            }
            // inode
            if(regexec(&regexCompiled_inode, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, inode);
                snprintf (inode, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->inode = strdup(inode);
                free(inode);
            }

            switch(items) {

                case 1:
                    if (cwd && path0) {
                        if (file_path = gen_audit_path(cwd, path0, NULL), file_path) {
                            w_evt->path = file_path;
                            mdebug2("audit_event: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, inode=%s, path=%s, pname=%s",
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (filterpath_audit_events(w_evt->path)) {
                                realtime_checksumfile(w_evt->path, w_evt);
                            } else if (w_evt->inode) {
                                if (inode_temp = OSHash_Get_ex(syscheck.inode_hash, w_evt->inode), inode_temp) {
                                    realtime_checksumfile(inode_temp, w_evt);
                                } else {
                                    realtime_checksumfile(w_evt->path, w_evt);
                                }
                            }
                        }
                    }
                    break;
                case 2:
                    if (cwd && path0 && path1) {
                        if (file_path = gen_audit_path(cwd, path0, path1), file_path) {
                            w_evt->path = file_path;
                            mdebug2("audit_event: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, inode=%s, path=%s, pname=%s",
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (filterpath_audit_events(w_evt->path)) {
                                realtime_checksumfile(w_evt->path, w_evt);
                            } else if (w_evt->inode) {
                                if (inode_temp = OSHash_Get_ex(syscheck.inode_hash, w_evt->inode), inode_temp) {
                                    realtime_checksumfile(inode_temp, w_evt);
                                } else {
                                    realtime_checksumfile(w_evt->path, w_evt);
                                }
                            }
                        }
                    }
                    break;
                case 4:
                    // path2
                    if(regexec(&regexCompiled_path2, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_malloc(match_size + 1, path2);
                        snprintf (path2, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                    }
                    // path3
                    if(regexec(&regexCompiled_path3, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_malloc(match_size + 1, path3);
                        snprintf (path3, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                    }
                    if (cwd && path0 && path1 && path2 && path3) {
                        // Send event 1/2
                        char *file_path1;
                        if (file_path1 = gen_audit_path(cwd, path0, path2), file_path1) {
                            w_evt->path = file_path1;
                            mdebug2("audit_event_1/2: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, inode=%s, path=%s, pname=%s",
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (filterpath_audit_events(w_evt->path)) {
                                realtime_checksumfile(w_evt->path, w_evt);
                            } else if (w_evt->inode) {
                                if (inode_temp = OSHash_Get_ex(syscheck.inode_hash, w_evt->inode), inode_temp) {
                                    realtime_checksumfile(inode_temp, w_evt);
                                } else {
                                    realtime_checksumfile(w_evt->path, w_evt);
                                }
                            }
                            free(file_path1);
                            w_evt->path = NULL;
                        }

                        // Send event 2/2
                        char *file_path2;
                        if (file_path2 = gen_audit_path(cwd, path1, path3), file_path2) {
                            w_evt->path = file_path2;
                            mdebug2("audit_event_2/2: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, inode=%s, path=%s, pname=%s",
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (filterpath_audit_events(w_evt->path)) {
                                realtime_checksumfile(w_evt->path, w_evt);
                            } else if (w_evt->inode) {
                                if (inode_temp = OSHash_Get_ex(syscheck.inode_hash, w_evt->inode), inode_temp) {
                                    realtime_checksumfile(inode_temp, w_evt);
                                } else {
                                    realtime_checksumfile(w_evt->path, w_evt);
                                }
                            }
                        }
                    }
                    free(path2);
                    free(path3);
                    break;
                case 5:
                    // path4
                    if(regexec(&regexCompiled_path4, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_malloc(match_size + 1, path4);
                        snprintf (path4, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                    }
                    if (cwd && path1 && path4) {
                        char *file_path;
                        if (file_path = gen_audit_path(cwd, path1, path4), file_path) {
                            w_evt->path = file_path;
                            mdebug2("audit_event: uid=%s, auid=%s, euid=%s, gid=%s, pid=%i, ppid=%i, inode=%s, path=%s, pname=%s",
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (filterpath_audit_events(w_evt->path)) {
                                realtime_checksumfile(w_evt->path, w_evt);
                            } else if (w_evt->inode) {
                                if (inode_temp = OSHash_Get_ex(syscheck.inode_hash, w_evt->inode), inode_temp) {
                                    realtime_checksumfile(inode_temp, w_evt);
                                } else {
                                    realtime_checksumfile(w_evt->path, w_evt);
                                }
                            }
                        }
                    }
                    free(path4);
                    break;
            }
            free(cwd);
            free(path0);
            free(path1);
            free_whodata_event(w_evt);
        }
        break;
    case 3:
        if(regexec(&regexCompiled_syscall, buffer, 2, match, 0) == 0) {
            match_size = match[1].rm_eo - match[1].rm_so;
            os_malloc(match_size + 1, syscall);
            snprintf (syscall, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            if(!strcmp(syscall, "2") || !strcmp(syscall, "257")
                || !strcmp(syscall, "5") || !strcmp(syscall, "295")) {
                // x86_64: 2 open
                // x86_64: 257 openat
                // i686: 5 open
                // i686: 295 openat
                mdebug2("Whodata health-check: Detected file creation event (%s).", syscall);
                audit_health_check_creation = 1;
            } else if(!strcmp(syscall, "87") || !strcmp(syscall, "263")
                || !strcmp(syscall, "10") || !strcmp(syscall, "301")) {
                // x86_64: 87 unlink
                // x86_64: 263 unlinkat
                // i686: 10 unlink
                // i686: 301 unlinkat
                mdebug2("Whodata health-check: Detected file deletion event (%s).", syscall);
                audit_health_check_deletion = 1;
            } else {
                mdebug2("Whodata health-check: Unrecognized event (%s)", syscall);
            }
            free(syscall);
        }
    }
}


void audit_reload_rules(void) {
    mdebug1("Reloading Audit rules...");
    int rules_added = add_audit_rules_syscheck();
    mdebug1("Audit rules reloaded: %i", rules_added);
}


void *audit_reload_thread(void) {

    sleep(RELOAD_RULES_INTERVAL);
    while (audit_thread_active) {
        // Reload rules
        audit_reload_rules();
        sleep(RELOAD_RULES_INTERVAL);
    }

    return NULL;
}


void *audit_healthcheck_thread(int *audit_sock) {

    w_mutex_lock(&audit_hc_mutex);
    hc_thread_active = 1;
    w_cond_signal(&audit_hc_started);
    w_mutex_unlock(&audit_hc_mutex);

    mdebug2("Whodata health-check: Reading thread active.");

    audit_read_events(audit_sock, HEALTHCHECK_MODE);

    mdebug2("Whodata health-check: Reading thread finished.");

    return NULL;
}


void * audit_main(int *audit_sock) {
    count_reload_retries = 0;

    w_mutex_lock(&audit_mutex);
    audit_thread_active = 1;
    w_cond_signal(&audit_thread_started);

    while (!audit_db_consistency_flag) {
        w_cond_wait(&audit_db_consistency, &audit_mutex);
    }

    w_mutex_unlock(&audit_mutex);

    // Start rules reloading thread
    w_create_thread(audit_reload_thread, NULL);

    minfo("FIM Whodata engine started.");

    // Read events
    audit_read_events(audit_sock, READING_MODE);

    // Auditd is not runnig or socket closed.
    mdebug1("Audit thread finished.");
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
    regfree(&regexCompiled_path2);
    regfree(&regexCompiled_path3);
    regfree(&regexCompiled_path4);
    regfree(&regexCompiled_pname);
    regfree(&regexCompiled_items);
    regfree(&regexCompiled_inode);
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


void audit_read_events(int *audit_sock, int mode) {
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
    count_reload_retries = 0;
    int conn_retries;

    char *buffer;
    os_malloc(BUF_SIZE * sizeof(char), buffer);
    os_malloc(BUF_SIZE, cache);

    while ((mode == READING_MODE && audit_thread_active)
       || (mode == HEALTHCHECK_MODE && hc_thread_active)) {
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
            if ((mode == READING_MODE && !audit_thread_active) ||
                (mode == HEALTHCHECK_MODE && !hc_thread_active)) {
                continue;
            }

            break;
        }

        if (byteRead = recv(*audit_sock, buffer + buffer_i, BUF_SIZE - buffer_i - 1, 0), !byteRead) {
            // Connection closed
            mwarn("Audit: connection closed.");
            // Reconnect
            conn_retries = 0;
            sleep(1);
            minfo("Audit: reconnecting... (%i)", ++conn_retries);
            *audit_sock = init_auditd_socket();
            while (conn_retries < MAX_CONN_RETRIES && *audit_sock < 0) {
                minfo("Audit: reconnecting... (%i)", ++conn_retries);
                sleep(1);
                *audit_sock = init_auditd_socket();
            }
            if (*audit_sock >= 0) {
                minfo("Audit: connected.");
                // Reload rules
                audit_reload_rules();
                continue;
            }
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

    free(cache);
    free(buffer);
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
        audit_added_rules = NULL;
    }
    w_mutex_unlock(&audit_mutex);
}


int filterkey_audit_events(char *buffer) {
    int i = 0;
    char logkey1[OS_SIZE_256] = {0};
    char logkey2[OS_SIZE_256] = {0};

    snprintf(logkey1, OS_SIZE_256, "key=\"%s\"", AUDIT_KEY);
    if (strstr(buffer, logkey1)) {
        mdebug2("Match audit_key: '%s'", logkey1);
        return 1;
    }

    snprintf(logkey1, OS_SIZE_256, "key=\"%s\"", AUDIT_HEALTHCHECK_KEY);
    if (strstr(buffer, logkey1)) {
        mdebug2("Match audit_key: '%s'", logkey1);
        return 3;
    }

    while (syscheck.audit_key[i]) {
        snprintf(logkey1, OS_SIZE_256, "key=\"%s\"", syscheck.audit_key[i]);
        snprintf(logkey2, OS_SIZE_256, "key=%s", syscheck.audit_key[i]);
        if (strstr(buffer, logkey1) || strstr(buffer, logkey2)) {
            mdebug2("Match audit_key: '%s'", logkey1);
            return 2;
        }
        i++;
    }
    return 0;
}


// Audit healthcheck before starting the main thread
int audit_health_check(int audit_socket) {
    int retval;
    FILE *fp;
    audit_health_check_creation = 0;
    audit_health_check_deletion = 0;
    unsigned int timer = 10;

    if(retval = audit_add_rule(AUDIT_HEALTHCHECK_DIR, AUDIT_HEALTHCHECK_KEY), retval <= 0){
        mdebug1("Couldn't add audit health check rule.");
        goto exit_err;
    }

    mdebug1("Whodata health-check: Starting...");

    w_cond_init(&audit_hc_started, NULL);

    // Start reading thread
    w_create_thread(audit_healthcheck_thread, &audit_socket);

    w_mutex_lock(&audit_hc_mutex);
    while (!hc_thread_active)
        w_cond_wait(&audit_hc_started, &audit_hc_mutex);
    w_mutex_unlock(&audit_hc_mutex);

    // Create a file
    fp = fopen(AUDIT_HEALTHCHECK_FILE, "w");

    if(!fp) {
        mdebug1("Couldn't create audit health check file.");
        goto exit_err;
    }

    fclose(fp);
    mdebug2("Whodata health-check: Waiting creation event...");

    while (!audit_health_check_creation && timer > 0) {
        sleep(1);
        timer--;
    }
    if (!audit_health_check_creation) {
        goto exit_err;
    }

    mdebug2("Whodata health-check: Creation event received.");
    mdebug2("Whodata health-check: Waiting deletion event...");

    // Delete that file
    unlink(AUDIT_HEALTHCHECK_FILE);

    timer = 10;
    while (!audit_health_check_deletion && timer > 0) {
        sleep(1);
        timer--;
    }
    if (!audit_health_check_deletion) {
        goto exit_err;
    }

    mdebug2("Whodata health-check: Deletion event received.");

    if(retval = audit_delete_rule(AUDIT_HEALTHCHECK_DIR, AUDIT_HEALTHCHECK_KEY), retval <= 0){
        mdebug1("Couldn't delete audit health check rule.");
    }
    hc_thread_active = 0;

    mdebug2("Whodata health-check: Success.");

    return 0;

exit_err:
    if(retval = audit_delete_rule(AUDIT_HEALTHCHECK_DIR, AUDIT_HEALTHCHECK_KEY), retval <= 0){
        mdebug1("Couldn't delete audit health check rule.");
    }
    hc_thread_active = 0;
    return -1;

}


int filterpath_audit_events(char *path) {
    int i = 0;

    for(i = 0; i < W_Vector_length(audit_added_dirs); i++) {
        if (strstr(path, W_Vector_get(audit_added_dirs, i))) {
            mdebug2("Found '%s' in '%s'", W_Vector_get(audit_added_dirs, i), path);
            return 1;
        }
    }
    return 0;
}

#endif
#endif
