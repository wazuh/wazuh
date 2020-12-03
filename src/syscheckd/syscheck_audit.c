/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 13, 2018.
 *
 * This program is free software; you can redistribute it
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
#include "string_op.h"

#define AUDIT_CONF_FILE DEFAULTDIR "/etc/af_wazuh.conf"
#define PLUGINS_DIR_AUDIT_2 "/etc/audisp/plugins.d"
#define PLUGINS_DIR_AUDIT_3 "/etc/audit/plugins.d"
#define AUDIT_CONF_LINK "af_wazuh.conf"
#define AUDIT_SOCKET DEFAULTDIR "/queue/ossec/audit"
#define BUF_SIZE OS_MAXSTR
#define AUDIT_KEY "wazuh_fim"
#define AUDIT_LOAD_RETRIES 5 // Max retries to reload Audit rules
#define MAX_CONN_RETRIES 5 // Max retries to reconnect to Audit socket
#define RELOAD_RULES_INTERVAL 30 // Seconds to re-add Audit rules

#define AUDIT_HEALTHCHECK_DIR DEFAULTDIR "/tmp"
#define AUDIT_HEALTHCHECK_KEY "wazuh_hc"
#define AUDIT_HEALTHCHECK_FILE AUDIT_HEALTHCHECK_DIR "/audit_hc"

#ifndef WAZUH_UNIT_TESTING
#define audit_thread_status() ((mode == READING_MODE && audit_thread_active) || \
                                (mode == HEALTHCHECK_MODE && hc_thread_active))
#else
#define audit_thread_status() FOREVER()
#endif

// Global variables
W_Vector *audit_added_rules;
W_Vector *audit_added_dirs;
W_Vector *audit_loaded_rules;
pthread_mutex_t audit_mutex;
pthread_mutex_t audit_hc_mutex;
pthread_mutex_t audit_rules_mutex;
int auid_err_reported;
volatile int hc_thread_active;

volatile int audit_health_check_creation;

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

static regex_t regexCompiled_cwd_hex;
static regex_t regexCompiled_pname_hex;
static regex_t regexCompiled_path0_hex;
static regex_t regexCompiled_path1_hex;
static regex_t regexCompiled_path2_hex;
static regex_t regexCompiled_path3_hex;
static regex_t regexCompiled_path4_hex;

static regex_t regexCompiled_items;
static regex_t regexCompiled_inode;
static regex_t regexCompiled_dir;
static regex_t regexCompiled_dir_hex;
static regex_t regexCompiled_syscall;
static regex_t regexCompiled_dev;


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
            minfo(FIM_AUDIT_NOSOCKET, AUDIT_SOCKET);
            return audit_restart();
        } else {
            mwarn(FIM_WARN_AUDIT_SOCKET_NOEXIST, AUDIT_SOCKET);
            return 1;
        }
    }

    minfo(FIM_AUDIT_SOCKET, AUDIT_CONF_FILE);

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

        // Fallthrough
        default:
            merror(LINK_ERROR, audit_path, AUDIT_CONF_FILE, errno, strerror(errno));
            return -1;
        }
    }

    if (syscheck.restart_audit) {
        minfo(FIM_AUDIT_RESTARTING, AUDIT_CONF_FILE);
        return audit_restart();
    } else {
        mwarn(FIM_WARN_AUDIT_CONFIGURATION_MODIFIED);
        return 1;
    }
}


// Init Audit events socket
int init_auditd_socket(void) {
    int sfd;

    if (sfd = OS_ConnectUnixDomain(AUDIT_SOCKET, SOCK_STREAM, OS_MAXSTR), sfd < 0) {
        merror(FIM_ERROR_WHODATA_SOCKET_CONNECT, AUDIT_SOCKET);
        return (-1);
    }

    return sfd;
}

int add_audit_rules_syscheck(bool first_time) {
    unsigned int i = 0;
    unsigned int rules_added = 0;

    int fd = audit_open();
    int res = audit_get_rule_list(fd);
    audit_close(fd);

    if (!res) {
        merror(FIM_ERROR_WHODATA_READ_RULE);
    }

    while (syscheck.dir[i] != NULL) {
        // Check if dir[i] is set in whodata mode
        if (syscheck.opts[i] & WHODATA_ACTIVE) {
            int retval;
            if (W_Vector_length(audit_added_rules) < syscheck.max_audit_entries) {
                int found = search_audit_rule(fim_get_real_path(i), "wa", AUDIT_KEY);
                if (found == 0) {
                    if (retval = audit_add_rule(fim_get_real_path(i), AUDIT_KEY), retval > 0) {
                        w_mutex_lock(&audit_rules_mutex);
                        if(!W_Vector_insert_unique(audit_added_rules, fim_get_real_path(i))) {
                            mdebug1(FIM_AUDIT_NEWRULE, fim_get_real_path(i));
                        } else {
                            mdebug1(FIM_AUDIT_RELOADED, fim_get_real_path(i));
                        }
                        w_mutex_unlock(&audit_rules_mutex);
                        rules_added++;
                    } else {
                        if (first_time) {
                            mwarn(FIM_WARN_WHODATA_ADD_RULE, fim_get_real_path(i));
                        } else {
                            mdebug1(FIM_WARN_WHODATA_ADD_RULE, fim_get_real_path(i));
                        }
                    }
                } else if (found == 1) {
                    w_mutex_lock(&audit_rules_mutex);
                    if(!W_Vector_insert_unique(audit_added_rules, fim_get_real_path(i))) {
                        mdebug1(FIM_AUDIT_RULEDUP, fim_get_real_path(i));
                    }
                    w_mutex_unlock(&audit_rules_mutex);
                    rules_added++;
                } else {
                    merror(FIM_ERROR_WHODATA_CHECK_RULE);
                }
            } else {
                static bool reported = false;

                if (first_time || !reported) {
                    merror(FIM_ERROR_WHODATA_MAXNUM_WATCHES, fim_get_real_path(i), syscheck.max_audit_entries);
                } else {
                    mdebug1(FIM_ERROR_WHODATA_MAXNUM_WATCHES, fim_get_real_path(i), syscheck.max_audit_entries);
                }

                reported = true;
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
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "uid"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_gid = " gid=([0-9]*) ";
    if (regcomp(&regexCompiled_gid, pattern_gid, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "gid"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_auid = " auid=([0-9]*) ";
    if (regcomp(&regexCompiled_auid, pattern_auid, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "auid"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_euid = " euid=([0-9]*) ";
    if (regcomp(&regexCompiled_euid, pattern_euid, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "euid"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_pid = " pid=([0-9]*) ";
    if (regcomp(&regexCompiled_pid, pattern_pid, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "pid"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_ppid = " ppid=([0-9]*) ";
    if (regcomp(&regexCompiled_ppid, pattern_ppid, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "ppid"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_inode = " item=[0-9] name=.* inode=([0-9]*)";
    if (regcomp(&regexCompiled_inode, pattern_inode, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "inode"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_items = " items=([0-9]*) ";
    if (regcomp(&regexCompiled_items, pattern_items, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "items"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_syscall = " syscall=([0-9]*)";
    if (regcomp(&regexCompiled_syscall, pattern_syscall, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "syscall"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_pname = " exe=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_pname, pattern_pname, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "pname"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_cwd = " cwd=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_cwd, pattern_cwd, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "cwd"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_dir = " dir=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_dir, pattern_dir, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "dir"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_path0 = " item=0 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path0, pattern_path0, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path0"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_path1 = " item=1 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path1, pattern_path1, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path1"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_path2 = " item=2 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path2, pattern_path2, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path2"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_path3 = " item=3 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path3, pattern_path3, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path3"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_path4 = " item=4 name=\"([^ ]*)\"";
    if (regcomp(&regexCompiled_path4, pattern_path4, REG_EXTENDED)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path4"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_pname_hex = " exe=([A-F0-9]*)";
    if (regcomp(&regexCompiled_pname_hex, pattern_pname_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "pname_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_cwd_hex = " cwd=([A-F0-9]*)";
    if (regcomp(&regexCompiled_cwd_hex, pattern_cwd_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "cwd_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_dir_hex = " dir=([A-F0-9]*)";
    if (regcomp(&regexCompiled_dir_hex, pattern_dir_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "dir_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_path0_hex = " item=0 name=([A-F0-9]*)";
    if (regcomp(&regexCompiled_path0_hex, pattern_path0_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path0_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_path1_hex = " item=1 name=([A-F0-9]*)";
    if (regcomp(&regexCompiled_path1_hex, pattern_path1_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path1_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_path2_hex = " item=2 name=([A-F0-9]*)";
    if (regcomp(&regexCompiled_path2_hex, pattern_path2_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path2_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_path3_hex = " item=3 name=([A-F0-9]*)";
    if (regcomp(&regexCompiled_path3_hex, pattern_path3_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path3_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }

    static const char *pattern_path4_hex = " item=4 name=([A-F0-9]*)";
    if (regcomp(&regexCompiled_path4_hex, pattern_path4_hex, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "path4_hex"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    static const char *pattern_dev = " dev=([A-F0-9]*:[A-F0-9]*)";
    if (regcomp(&regexCompiled_dev, pattern_dev, REG_EXTENDED | REG_ICASE)) {
        merror(FIM_ERROR_WHODATA_COMPILE_REGEX, "dev"); // LCOV_EXCL_LINE
        return -1; // LCOV_EXCL_LINE
    }
    return 0;
}


// LCOV_EXCL_START
int audit_init(void) {
    audit_health_check_creation = 0;

    w_mutex_init(&audit_mutex, NULL);
    w_mutex_init(&audit_hc_mutex, NULL);
    w_mutex_init(&audit_rules_mutex, NULL);

    // Check if auditd is installed and running.
    int aupid = check_auditd_enabled();
    if (aupid <= 0) {
        mwarn(FIM_AUDIT_NORUNNING);
        return (-1);
    }

    // Check audit socket configuration
    switch (set_auditd_config()) {
    case -1:
        mdebug1(FIM_AUDIT_NOCONF);
        return (-1);
    case 0:
        break;
    default:
        return (-1);
    }

    // Initialize Audit socket
    static int audit_socket;
    audit_socket = init_auditd_socket();
    if (audit_socket < 0) {
        merror("Can't init auditd socket in 'init_auditd_socket()'");
        return -1;
    }

    int regex_comp = init_regex();
    if (regex_comp < 0) {
        merror("Can't init regex in 'init_regex()'");
        return -1;
    }

    // Perform Audit healthcheck
    if (syscheck.audit_healthcheck) {
        if(audit_health_check(audit_socket)) {
            merror(FIM_ERROR_WHODATA_HEALTHCHECK_START);
            return -1;
        }
    } else {
        minfo(FIM_AUDIT_HEALTHCHECK_DISABLE);
    }

    // Add Audit rules
    audit_added_rules = W_Vector_init(10);
    audit_added_dirs = W_Vector_init(20);

    add_audit_rules_syscheck(true);
    atexit(clean_rules);
    auid_err_reported = 0;

    // Start audit thread
    w_cond_init(&audit_thread_started, NULL);
    w_cond_init(&audit_db_consistency, NULL);
    w_create_thread(audit_main, &audit_socket);
    w_mutex_lock(&audit_mutex);
    while (!audit_thread_active)
        w_cond_wait(&audit_thread_started, &audit_mutex);
    w_mutex_unlock(&audit_mutex);
    return 1;

}
// LCOV_EXCL_STOP


// LCOV_EXCL_START
void audit_set_db_consistency(void) {
    w_mutex_lock(&audit_mutex);
    audit_db_consistency_flag = 1;
    w_cond_signal(&audit_db_consistency);
    w_mutex_unlock(&audit_mutex);
}
// LCOV_EXCL_STOP


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
            } else if (strlen(cwd) == 1) {
                os_malloc(strlen(cwd) + strlen(path1) + 2, gen_path);
                snprintf(gen_path, strlen(cwd) + strlen(path1) + 2, "%s%s", cwd, path1);
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

void get_parent_process_info(char *ppid, char ** const parent_name, char ** const parent_cwd) {

    char *slinkexe = NULL;
    char *slinkcwd = NULL;
    int tam_slink = strlen(ppid) + 11;
    int tam_ppname = 0;
    int tam_pcwd = 0;

    os_malloc(tam_slink, slinkexe);
    os_malloc(tam_slink, slinkcwd);

    snprintf(slinkexe, tam_slink, "/proc/%s/exe", ppid);
    snprintf(slinkcwd, tam_slink, "/proc/%s/cwd", ppid);

    if(tam_ppname = readlink(slinkexe, *parent_name, OS_FLSIZE), tam_ppname < 0) {
        mdebug1("Failure to obtain the name of the process: '%s'. Error: %s", ppid, strerror(errno));
        parent_name[0][0] = '\0';
    } else {
        parent_name[0][tam_ppname] = '\0';
    }

    if(tam_pcwd = readlink(slinkcwd, *parent_cwd, OS_FLSIZE), tam_pcwd < 0) {
        mdebug1("Failure to obtain the cwd of the process: '%s'. Error: %s", ppid, strerror(errno));
        parent_cwd[0][0] = '\0';
    } else {
        parent_cwd[0][tam_pcwd] = '\0';
    }

    os_free(slinkexe);
    os_free(slinkcwd);
}

void audit_parse(char *buffer) {
    char *psuccess;
    char *pconfig;
    char *pdelete;
    regmatch_t match[2];
    int match_size;
    char *path0 = NULL;
    char *path1 = NULL;
    char *path2 = NULL;
    char *path3 = NULL;
    char *path4 = NULL;
    char *file_path = NULL;
    char *dev = NULL;
    whodata_evt *w_evt;
    unsigned int items = 0;
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


            else if (regexec(&regexCompiled_dir_hex, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                if (decoded_buffer) {
                    const int decoded_length = match_size / 2;
                    os_malloc(decoded_length + 1, p_dir);
                    snprintf (p_dir, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                    os_free(decoded_buffer);
                } else {
                    merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                }

            }

            if (p_dir && *p_dir != '\0') {
                minfo(FIM_AUDIT_REMOVE_RULE, p_dir);
                // Send alert
                char msg_alert[512 + 1];
                snprintf(msg_alert, 512, "ossec: Audit: Monitored directory was removed: Audit rule removed");
                SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);
            } else {
                mwarn(FIM_WARN_AUDIT_RULES_MODIFIED);
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
                os_malloc(match_size + 1, w_evt->user_id);
                snprintf (w_evt->user_id, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->user_name = get_user(atoi(w_evt->user_id));
            }
            // audit_name & audit_uid
            if(regexec(&regexCompiled_auid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *auid = NULL;
                os_malloc(match_size + 1, auid);
                snprintf (auid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                if (strcmp(auid, "4294967295") == 0) { // Invalid auid (-1)
                    if (!auid_err_reported) {
                        mdebug1(FIM_AUDIT_INVALID_AUID);
                        auid_err_reported = 1;
                    }
                    w_evt->audit_name = NULL;
                    w_evt->audit_uid = NULL;
                } else {
                    w_evt->audit_name = get_user(atoi(auid));
                    w_evt->audit_uid = strdup(auid);
                }
                os_free(auid);
            }
            // effective_name && effective_uid
            if(regexec(&regexCompiled_euid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->effective_uid);
                snprintf (w_evt->effective_uid, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->effective_name = get_user(atoi(w_evt->effective_uid));
            }
            // group_name & group_id
            if(regexec(&regexCompiled_gid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->group_id);
                snprintf (w_evt->group_id, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->group_name = (char*)get_group(atoi(w_evt->group_id));
            }
            // process_id
            if(regexec(&regexCompiled_pid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *pid = NULL;
                os_malloc(match_size + 1, pid);
                snprintf (pid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->process_id = atoi(pid);
                free(pid);
            }
            // ppid
            if(regexec(&regexCompiled_ppid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *ppid = NULL;
                os_malloc(OS_FLSIZE, w_evt->parent_name);
                os_malloc(OS_FLSIZE, w_evt->parent_cwd);
                os_malloc(match_size + 1, ppid);
                snprintf (ppid, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                get_parent_process_info(ppid , &w_evt->parent_name, &w_evt->parent_cwd);
                w_evt->ppid = atoi(ppid);
                free(ppid);
            }
            // process_name
            if(regexec(&regexCompiled_pname, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->process_name);
                snprintf (w_evt->process_name, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            } else if (regexec(&regexCompiled_pname_hex, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                if (decoded_buffer) {
                    const int decoded_length = match_size / 2;
                    os_malloc(decoded_length + 1, w_evt->process_name);
                    snprintf(w_evt->process_name, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                    os_free(decoded_buffer);
                } else {
                    merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                }

            }

            // cwd
            if(regexec(&regexCompiled_cwd, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->cwd);
                snprintf (w_evt->cwd, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            } else if (regexec(&regexCompiled_cwd_hex, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                if (decoded_buffer) {
                    const int decoded_length = match_size / 2;
                    os_malloc(decoded_length + 1, w_evt->cwd);
                    snprintf(w_evt->cwd, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                    os_free(decoded_buffer);
                } else {
                    merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                }
            }

            // path0
            if(regexec(&regexCompiled_path0, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, path0);
                snprintf (path0, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            } else if (regexec(&regexCompiled_path0_hex, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                if (decoded_buffer) {
                    const int decoded_length = match_size / 2;
                    os_malloc(decoded_length + 1, path0);
                    snprintf(path0, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                    os_free(decoded_buffer);
                } else {
                    merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                }
            }

            // path1
            if(regexec(&regexCompiled_path1, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, path1);
                snprintf (path1, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            } else if (regexec(&regexCompiled_path1_hex, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                if (decoded_buffer) {
                    const int decoded_length = match_size / 2;
                    os_malloc(decoded_length + 1, path1);
                    snprintf(path1, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                    os_free(decoded_buffer);
                } else {
                    merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                }
            }

            // inode
            if(regexec(&regexCompiled_inode, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->inode);
                snprintf (w_evt->inode, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
            }
            // dev
            if(regexec(&regexCompiled_dev, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, dev);
                snprintf (dev, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);

                char *aux = wstr_chr(dev, ':');

                if (aux) {
                    *(aux++) = '\0';

                    os_calloc(OS_SIZE_64, sizeof(char), w_evt->dev);
                    snprintf(w_evt->dev, OS_SIZE_64, "%s%s", dev, aux);
                    snprintf(w_evt->dev, OS_SIZE_64, "%ld", strtol(w_evt->dev, NULL, 16));
                } else {
                    merror("Couldn't decode device chunk of audit log: colon not found in this string: \"%s\".", dev); // LCOV_EXCL_LINE
                }

                free(dev);
            }

            // TODO: Verify all case events
            // TODO: Should we consider the w_evt->path if !w_evt->inode?
            switch(items) {

                case 1:
                    if (w_evt->cwd && path0) {
                        if (file_path = gen_audit_path(w_evt->cwd, path0, NULL), file_path) {
                            w_evt->path = file_path;
                            mdebug2(FIM_AUDIT_EVENT
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (w_evt->inode) {
                                fim_whodata_event(w_evt);
                            }
                        }
                    }
                    break;
                case 2:
                    if (w_evt->cwd && path0 && path1) {
                        if (file_path = gen_audit_path(w_evt->cwd, path0, path1), file_path) {
                            w_evt->path = file_path;
                            mdebug2(FIM_AUDIT_EVENT
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            char *real_path = NULL;
                            os_calloc(PATH_MAX + 2, sizeof(char), real_path);
                            if (realpath(w_evt->path, real_path), !real_path) {
                                mdebug1(FIM_CHECK_LINK_REALPATH, w_evt->path); // LCOV_EXCL_LINE
                                break; // LCOV_EXCL_LINE
                            }

                            free(file_path);
                            w_evt->path = real_path;

                            if (w_evt->inode) {
                                fim_whodata_event(w_evt);
                            }
                        }
                    }
                    break;
                case 3:
                    // path2
                    if(regexec(&regexCompiled_path2, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_malloc(match_size + 1, path2);
                        snprintf (path2, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                    } else if (regexec(&regexCompiled_path2_hex, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        char * decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                        if (decoded_buffer) {
                            const int decoded_length = match_size / 2;
                            os_malloc(decoded_length + 1, path2);
                            snprintf (path2, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                            os_free(decoded_buffer);
                        } else {
                            merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                        }
                    }

                    if (w_evt->cwd && path1 && path2) {
                        if (file_path = gen_audit_path(w_evt->cwd, path1, path2), file_path) {
                            w_evt->path = file_path;
                            mdebug2(FIM_AUDIT_EVENT
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (w_evt->inode) {
                                fim_whodata_event(w_evt);
                            }
                        }
                    }
                    free(path2);
                    break;
                case 4:
                    // path2
                    if(regexec(&regexCompiled_path2, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_malloc(match_size + 1, path2);
                        snprintf (path2, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                    } else if (regexec(&regexCompiled_path2_hex, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                        if (decoded_buffer) {
                            const int decoded_length = match_size / 2;
                            os_malloc(decoded_length + 1, path2);
                            snprintf (path2, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                            os_free(decoded_buffer);
                        } else {
                            merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                        }
                    }

                    // path3
                    if(regexec(&regexCompiled_path3, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        os_malloc(match_size + 1, path3);
                        snprintf (path3, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
                    } else if (regexec(&regexCompiled_path3_hex, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                        if (decoded_buffer) {
                            const int decoded_length = match_size / 2;
                            os_malloc(decoded_length + 1, path3);
                            snprintf (path3, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                            os_free(decoded_buffer);
                        } else {
                            merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                        }
                    }

                    if (w_evt->cwd && path0 && path1 && path2 && path3) {
                        // Send event 1/2
                        char *file_path1;
                        if (file_path1 = gen_audit_path(w_evt->cwd, path0, path2), file_path1) {
                            w_evt->path = file_path1;
                            mdebug2(FIM_AUDIT_EVENT1
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (w_evt->inode) {
                                fim_whodata_event(w_evt);
                            }
                            free(file_path1);
                            w_evt->path = NULL;
                        }

                        // Send event 2/2
                        char *file_path2;
                        if (file_path2 = gen_audit_path(w_evt->cwd, path1, path3), file_path2) {
                            w_evt->path = file_path2;
                            mdebug2(FIM_AUDIT_EVENT2
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (w_evt->inode) {
                                fim_whodata_event(w_evt);
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
                        snprintf (path4, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                    }  else if (regexec(&regexCompiled_path4_hex, buffer, 2, match, 0) == 0) {
                        match_size = match[1].rm_eo - match[1].rm_so;
                        char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                        if (decoded_buffer) {
                            const int decoded_length = match_size / 2;
                            os_malloc(decoded_length + 1, path4);
                            snprintf (path4, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                            os_free(decoded_buffer);
                        } else {
                            merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                        }
                    }

                    if (w_evt->cwd && path1 && path4) {
                        char *file_path;
                        if (file_path = gen_audit_path(w_evt->cwd, path1, path4), file_path) {
                            w_evt->path = file_path;
                            mdebug2(FIM_AUDIT_EVENT
                                (w_evt->user_name)?w_evt->user_name:"",
                                (w_evt->audit_name)?w_evt->audit_name:"",
                                (w_evt->effective_name)?w_evt->effective_name:"",
                                (w_evt->group_name)?w_evt->group_name:"",
                                w_evt->process_id,
                                w_evt->ppid,
                                (w_evt->inode)?w_evt->inode:"",
                                (w_evt->path)?w_evt->path:"",
                                (w_evt->process_name)?w_evt->process_name:"");

                            if (w_evt->inode) {
                                fim_whodata_event(w_evt);
                            }
                        }
                    }
                    free(path4);
                    break;
            }

            free(path0);
            free(path1);
            free_whodata_event(w_evt);
        }
        break;
    case 3:
        if(regexec(&regexCompiled_syscall, buffer, 2, match, 0) == 0) {
            match_size = match[1].rm_eo - match[1].rm_so;
            char *syscall = NULL;
            os_malloc(match_size + 1, syscall);
            snprintf (syscall, match_size +1, "%.*s", match_size, buffer + match[1].rm_so);
            if(!strcmp(syscall, "2") || !strcmp(syscall, "257")
                || !strcmp(syscall, "5") || !strcmp(syscall, "295")) {
                // x86_64: 2 open
                // x86_64: 257 openat
                // i686: 5 open
                // i686: 295 openat
                mdebug2(FIM_HEALTHCHECK_CREATE, syscall);
                audit_health_check_creation = 1;
            } else if(!strcmp(syscall, "87") || !strcmp(syscall, "263")
                || !strcmp(syscall, "10") || !strcmp(syscall, "301")) {
                // x86_64: 87 unlink
                // x86_64: 263 unlinkat
                // i686: 10 unlink
                // i686: 301 unlinkat
                mdebug2(FIM_HEALTHCHECK_DELETE, syscall);
            } else {
                mdebug2(FIM_HEALTHCHECK_UNRECOGNIZED_EVENT, syscall);
            }
            os_free(syscall);
        }
    }
}


// LCOV_EXCL_START
void audit_reload_rules(void) {
    mdebug1(FIM_AUDIT_RELOADING_RULES);
    int rules_added = add_audit_rules_syscheck(false);
    mdebug1(FIM_AUDIT_RELOADED_RULES, rules_added);
}
// LCOV_EXCL_STOP


// LCOV_EXCL_START
void *audit_reload_thread() {

    sleep(RELOAD_RULES_INTERVAL);
    while (audit_thread_active) {
        // Reload rules
        audit_reload_rules();
        sleep(RELOAD_RULES_INTERVAL);
    }

    return NULL;
}
// LCOV_EXCL_STOP


// LCOV_EXCL_START
void *audit_healthcheck_thread(int *audit_sock) {

    w_mutex_lock(&audit_hc_mutex);
    hc_thread_active = 1;
    w_cond_signal(&audit_hc_started);
    w_mutex_unlock(&audit_hc_mutex);

    mdebug2(FIM_HEALTHCHECK_THREAD_ACTIVE);

    audit_read_events(audit_sock, HEALTHCHECK_MODE);

    mdebug2(FIM_HEALTHCHECK_THREAD_FINISHED);

    return NULL;
}
// LCOV_EXCL_STOP


// LCOV_EXCL_START
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

    minfo(FIM_WHODATA_STARTED);

    // Read events
    audit_read_events(audit_sock, READING_MODE);

    // Auditd is not runnig or socket closed.
    mdebug1(FIM_AUDIT_THREAD_STOPED);
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

    regfree(&regexCompiled_cwd_hex);
    regfree(&regexCompiled_pname_hex);
    regfree(&regexCompiled_path0_hex);
    regfree(&regexCompiled_path1_hex);
    regfree(&regexCompiled_path2_hex);
    regfree(&regexCompiled_path3_hex);
    regfree(&regexCompiled_path4_hex);

    // Change Audit monitored folders to Inotify.
    int i;
    w_mutex_lock(&audit_rules_mutex);
    if (audit_added_dirs) {
        for (i = 0; i < W_Vector_length(audit_added_dirs); i++) {
            char *path;
            os_strdup(W_Vector_get(audit_added_dirs, i), path);
            int pos = fim_configuration_directory(path, "file");

            if (pos >= 0) {
                syscheck.opts[pos] &= ~ WHODATA_ACTIVE;
                syscheck.opts[pos] |= REALTIME_ACTIVE;

                realtime_adddir(path, 0, (syscheck.opts[pos] & CHECK_FOLLOW) ? 1 : 0);
            }
            os_free(path);
        }
        W_Vector_free(audit_added_dirs);
    }
    w_mutex_unlock(&audit_rules_mutex);

    // Clean Audit added rules.
    clean_rules();

    return NULL;
}
// LCOV_EXCL_STOP


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
    char * eoe_found = false;

    char *buffer;
    os_malloc(BUF_SIZE * sizeof(char), buffer);
    os_malloc(BUF_SIZE, cache);

    while (audit_thread_status()) {
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
            mwarn(FIM_WARN_AUDIT_CONNECTION_CLOSED);
            // Reconnect
            conn_retries = 0;
            sleep(1);
            minfo(FIM_AUDIT_RECONNECT, ++conn_retries);
            *audit_sock = init_auditd_socket();
            while (conn_retries < MAX_CONN_RETRIES && *audit_sock < 0) {
                minfo(FIM_AUDIT_RECONNECT, ++conn_retries);
                sleep(1);
                *audit_sock = init_auditd_socket();
            }
            if (*audit_sock >= 0) {
                minfo(FIM_AUDIT_CONNECT);
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
        char *event_too_long_id = NULL;

        do {
            *endline = '\0';

            if (id = audit_get_id(line), id) {
                // If there was cached data and the ID is different, parse cache first

                if (cache_id && strcmp(cache_id, id) && cache_i) {
                    if (!event_too_long_id) {
                        audit_parse(cache);
                    }
                    cache_i = 0;
                }

                // Append to cache
                len = endline - line;
                if (cache_i + len + 1 <= BUF_SIZE) {
                    strncpy(cache + cache_i, line, len);
                    cache_i += len;
                    cache[cache_i++] = '\n';
                    cache[cache_i] = '\0';
                } else if (!event_too_long_id){
                    mwarn(FIM_WARN_WHODATA_EVENT_TOOLONG, id);
                    os_strdup(id, event_too_long_id);
                }
                eoe_found = strstr(line, "type=EOE");

                free(cache_id);
                cache_id = id;
            } else {
                mwarn(FIM_WARN_WHODATA_GETID, line);
            }

            line = endline + 1;
        } while (*line && (endline = strchr(line, '\n'), endline));

        // If some audit log remains in the cache and it is complet (line "end of event" is found), flush cache
        if (eoe_found && !event_too_long_id){
            audit_parse(cache);
            cache_i = 0;
        }

        // If some data remains in the buffer, move it to the beginning
        if (*line) {
            buffer_i = strlen(line);
            memmove(buffer, line, buffer_i);
        } else {
            buffer_i = 0;
        }

        if (event_too_long_id) os_free(event_too_long_id);
    }

    free(cache_id);
    free(cache);
    free(buffer);
}


void clean_rules(void) {
    int i;
    w_mutex_lock(&audit_mutex);
    audit_thread_active = 0;

    if (audit_added_rules) {
        mdebug2(FIM_AUDIT_DELETE_RULE);
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
        mdebug2(FIM_AUDIT_MATCH_KEY, logkey1);
        return 1;
    }

    snprintf(logkey1, OS_SIZE_256, "key=\"%s\"", AUDIT_HEALTHCHECK_KEY);
    if (strstr(buffer, logkey1)) {
        mdebug2(FIM_AUDIT_MATCH_KEY, logkey1);
        return 3;
    }

    while (syscheck.audit_key[i]) {
        snprintf(logkey1, OS_SIZE_256, "key=\"%s\"", syscheck.audit_key[i]);
        snprintf(logkey2, OS_SIZE_256, "key=%s", syscheck.audit_key[i]);
        if (strstr(buffer, logkey1) || strstr(buffer, logkey2)) {
            mdebug2(FIM_AUDIT_MATCH_KEY, logkey1);
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
    unsigned int timer = 10;

    if(retval = audit_add_rule(AUDIT_HEALTHCHECK_DIR, AUDIT_HEALTHCHECK_KEY), retval <= 0 && retval != -17) { // -17 Means audit rule exist EEXIST
        mdebug1(FIM_AUDIT_HEALTHCHECK_RULE);
        return -1;
    }

    mdebug1(FIM_AUDIT_HEALTHCHECK_START);

    w_cond_init(&audit_hc_started, NULL);

    // Start reading thread
    w_create_thread(audit_healthcheck_thread, &audit_socket);

    w_mutex_lock(&audit_hc_mutex);
    while (!hc_thread_active)
        w_cond_wait(&audit_hc_started, &audit_hc_mutex);
    w_mutex_unlock(&audit_hc_mutex);

    // Generate open events until they get picked up
    do {
        fp = fopen(AUDIT_HEALTHCHECK_FILE, "w");

        if(!fp) {
            mdebug1(FIM_AUDIT_HEALTHCHECK_FILE);
        } else {
            fclose(fp);
        }

        sleep(1);
    } while (!audit_health_check_creation && --timer > 0);

    if (!audit_health_check_creation) {
        mdebug1(FIM_HEALTHCHECK_CREATE_ERROR);
        retval = -1;
    } else {
        mdebug1(FIM_HEALTHCHECK_SUCCESS);
        retval = 0;
    }

    // Delete that file
    unlink(AUDIT_HEALTHCHECK_FILE);

    if(audit_delete_rule(AUDIT_HEALTHCHECK_DIR, AUDIT_HEALTHCHECK_KEY) <= 0){
        mdebug1(FIM_HEALTHCHECK_CHECK_RULE);    // LCOV_EXCL_LINE
    }
    hc_thread_active = 0;

    return retval;
}

#endif
#endif
