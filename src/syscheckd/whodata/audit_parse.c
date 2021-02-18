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

#define AUDIT_LOAD_RETRIES 5 // Max retries to reload Audit rules

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

void clean_regex() {
    static int freed = 0;

    if (freed) { // Prevent double free
        return;
    }

    regfree(&regexCompiled_uid);
    regfree(&regexCompiled_gid);
    regfree(&regexCompiled_auid);
    regfree(&regexCompiled_euid);
    regfree(&regexCompiled_pid);
    regfree(&regexCompiled_ppid);
    regfree(&regexCompiled_inode);
    regfree(&regexCompiled_items);
    regfree(&regexCompiled_syscall);
    regfree(&regexCompiled_pname);
    regfree(&regexCompiled_cwd);
    regfree(&regexCompiled_dir);
    regfree(&regexCompiled_path0);
    regfree(&regexCompiled_path1);
    regfree(&regexCompiled_path2);
    regfree(&regexCompiled_path3);
    regfree(&regexCompiled_path4);

    regfree(&regexCompiled_pname_hex);
    regfree(&regexCompiled_cwd_hex);
    regfree(&regexCompiled_dir_hex);
    regfree(&regexCompiled_path0_hex);
    regfree(&regexCompiled_path1_hex);
    regfree(&regexCompiled_path2_hex);
    regfree(&regexCompiled_path3_hex);
    regfree(&regexCompiled_path4_hex);
    regfree(&regexCompiled_dev);

    freed = 1;
}


int filterkey_audit_events(char *buffer) {
    int i = 0;
    char logkey1[OS_SIZE_256] = { 0 };
    char logkey2[OS_SIZE_256] = { 0 };

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


char *gen_audit_path(char *cwd, char *path0, char *path1) {

    char *gen_path = NULL;

    if (path0 && cwd) {
        if (path1) {
            if (path1[0] == '/') {
                gen_path = strdup(path1);
            } else if (path1[0] == '.' && path1[1] == '/') {
                char *full_path;
                os_malloc(strlen(cwd) + strlen(path1) + 2, full_path);
                snprintf(full_path, strlen(cwd) + strlen(path1) + 2, "%s/%s", cwd, (path1 + 2));
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
                snprintf(full_path, strlen(cwd) + strlen(path0) + 2, "%s/%s", cwd, (path0 + 2));
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


void get_parent_process_info(char *ppid, char **const parent_name, char **const parent_cwd) {

    char *slinkexe = NULL;
    char *slinkcwd = NULL;
    int tam_slink = strlen(ppid) + 11;
    int tam_ppname = 0;
    int tam_pcwd = 0;

    os_malloc(tam_slink, slinkexe);
    os_malloc(tam_slink, slinkcwd);

    snprintf(slinkexe, tam_slink, "/proc/%s/exe", ppid);
    snprintf(slinkcwd, tam_slink, "/proc/%s/cwd", ppid);

    if (tam_ppname = readlink(slinkexe, *parent_name, OS_FLSIZE), tam_ppname < 0) {
        mdebug1("Failure to obtain the name of the process: '%s'. Error: %s", ppid, strerror(errno));
        parent_name[0][0] = '\0';
    } else {
        parent_name[0][tam_ppname] = '\0';
    }

    if (tam_pcwd = readlink(slinkcwd, *parent_cwd, OS_FLSIZE), tam_pcwd < 0) {
        mdebug1("Failure to obtain the cwd of the process: '%s'. Error: %s", ppid, strerror(errno));
        parent_cwd[0][0] = '\0';
    } else {
        parent_cwd[0][tam_pcwd] = '\0';
    }

    os_free(slinkexe);
    os_free(slinkcwd);
}


// Extract id: node=... type=CWD msg=audit(1529332881.955:3867): cwd="..."
char *audit_get_id(const char *event) {
    char *begin;
    char *end;
    char *id;
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


void audit_parse(char *buffer) {
    static int auid_err_reported = 0;
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
        if ((pconfig = strstr(buffer, "type=CONFIG_CHANGE"), pconfig) &&
            ((pdelete = strstr(buffer, "op=remove_rule"), pdelete) ||
             (pdelete = strstr(buffer, "op=\"remove_rule\""), pdelete))) { // Detect rules modification.

            // Filter rule removed
            char *p_dir = NULL;
            if (regexec(&regexCompiled_dir, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_calloc(1, match_size + 1, p_dir);
                snprintf(p_dir, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
            }


            else if (regexec(&regexCompiled_dir_hex, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                if (decoded_buffer) {
                    const int decoded_length = match_size / 2;
                    os_malloc(decoded_length + 1, p_dir);
                    snprintf(p_dir, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
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
            } else if (fim_manipulated_audit_rules()) {
                // If the manipulation wasn't done by syscheck, increase the number of retries
                mwarn(FIM_WARN_AUDIT_RULES_MODIFIED);
                // Send alert
                char msg_alert[512 + 1];
                snprintf(msg_alert, 512, "ossec: Audit: Detected rules manipulation: Audit rules removed");
                SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);

                count_reload_retries++;

                if (count_reload_retries < AUDIT_LOAD_RETRIES) {
                    // Reload rules
                    fim_audit_reload_rules();
                } else {
                    // Send alert
                    char msg_alert[512 + 1];
                    snprintf(msg_alert, 512, "ossec: Audit: Detected rules manipulation: Max rules reload retries");
                    SendMSG(syscheck.queue, msg_alert, "syscheck", LOCALFILE_MQ);
                    // Stop thread
                    audit_thread_active = 0;
                }
            }
            os_free(p_dir);
        }
        // Fallthrough
    case 2:
        if (psuccess = strstr(buffer, "success=yes"), psuccess) {

            os_calloc(1, sizeof(whodata_evt), w_evt);

            // Items
            if (regexec(&regexCompiled_items, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *chr_item;
                os_malloc(match_size + 1, chr_item);
                snprintf(chr_item, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                items = atoi(chr_item);
                free(chr_item);
            }
            // user_name & user_id
            if (regexec(&regexCompiled_uid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->user_id);
                snprintf(w_evt->user_id, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->user_name = get_user(atoi(w_evt->user_id));
            }
            // audit_name & audit_uid
            if (regexec(&regexCompiled_auid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *auid = NULL;
                os_malloc(match_size + 1, auid);
                snprintf(auid, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
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
            if (regexec(&regexCompiled_euid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->effective_uid);
                snprintf(w_evt->effective_uid, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->effective_name = get_user(atoi(w_evt->effective_uid));
            }
            // group_name & group_id
            if (regexec(&regexCompiled_gid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->group_id);
                snprintf(w_evt->group_id, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->group_name = (char *)get_group(atoi(w_evt->group_id));
            }
            // process_id
            if (regexec(&regexCompiled_pid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *pid = NULL;
                os_malloc(match_size + 1, pid);
                snprintf(pid, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                w_evt->process_id = atoi(pid);
                free(pid);
            }
            // ppid
            if (regexec(&regexCompiled_ppid, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                char *ppid = NULL;
                os_malloc(OS_FLSIZE, w_evt->parent_name);
                os_malloc(OS_FLSIZE, w_evt->parent_cwd);
                os_malloc(match_size + 1, ppid);
                snprintf(ppid, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                get_parent_process_info(ppid, &w_evt->parent_name, &w_evt->parent_cwd);
                w_evt->ppid = atoi(ppid);
                free(ppid);
            }
            // process_name
            if (regexec(&regexCompiled_pname, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->process_name);
                snprintf(w_evt->process_name, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
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
            if (regexec(&regexCompiled_cwd, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->cwd);
                snprintf(w_evt->cwd, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
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
            if (regexec(&regexCompiled_path0, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, path0);
                snprintf(path0, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
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
            if (regexec(&regexCompiled_path1, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, path1);
                snprintf(path1, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
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
            if (regexec(&regexCompiled_inode, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, w_evt->inode);
                snprintf(w_evt->inode, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
            }
            // dev
            if (regexec(&regexCompiled_dev, buffer, 2, match, 0) == 0) {
                match_size = match[1].rm_eo - match[1].rm_so;
                os_malloc(match_size + 1, dev);
                snprintf(dev, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);

                char *aux = wstr_chr(dev, ':');

                if (aux) {
                    *(aux++) = '\0';

                    os_calloc(OS_SIZE_64, sizeof(char), w_evt->dev);
                    snprintf(w_evt->dev, OS_SIZE_64, "%s%s", dev, aux);
                    snprintf(w_evt->dev, OS_SIZE_64, "%ld", strtol(w_evt->dev, NULL, 16));
                } else {
                    merror("Couldn't decode device chunk of audit log: colon not found in this string: \"%s\".",
                           dev); // LCOV_EXCL_LINE
                }

                free(dev);
            }

            // TODO: Verify all case events
            // TODO: Should we consider the w_evt->path if !w_evt->inode?
            switch (items) {

            case 1:
                if (w_evt->cwd && path0) {
                    if (file_path = gen_audit_path(w_evt->cwd, path0, NULL), file_path) {
                        w_evt->path = file_path;
                        mdebug2(FIM_AUDIT_EVENT(w_evt->user_name) ? w_evt->user_name : "",
                                (w_evt->audit_name) ? w_evt->audit_name : "",
                                (w_evt->effective_name) ? w_evt->effective_name : "",
                                (w_evt->group_name) ? w_evt->group_name : "", w_evt->process_id, w_evt->ppid,
                                (w_evt->inode) ? w_evt->inode : "", (w_evt->path) ? w_evt->path : "",
                                (w_evt->process_name) ? w_evt->process_name : "");

                        if (w_evt->inode) {
                            fim_whodata_event(w_evt);
                        }
                    }
                }
                break;
            case 2:
                if (w_evt->cwd && path0 && path1) {
                    if (file_path = gen_audit_path(w_evt->cwd, path0, path1), file_path) {
                        mdebug2(FIM_AUDIT_EVENT(w_evt->user_name) ? w_evt->user_name : "",
                                (w_evt->audit_name) ? w_evt->audit_name : "",
                                (w_evt->effective_name) ? w_evt->effective_name : "",
                                (w_evt->group_name) ? w_evt->group_name : "", w_evt->process_id, w_evt->ppid,
                                (w_evt->inode) ? w_evt->inode : "", (file_path) ? file_path : "",
                                (w_evt->process_name) ? w_evt->process_name : "");

                        w_evt->path = realpath(file_path, NULL);
                        if (w_evt->path == NULL) {
                            os_strdup(file_path, w_evt->path);
                            mdebug1(FIM_CHECK_LINK_REALPATH, w_evt->path); // LCOV_EXCL_LINE
                        }

                        free(file_path);

                        if (w_evt->inode) {
                            fim_whodata_event(w_evt);
                        }
                    }
                }
                break;
            case 3:
                // path2
                if (regexec(&regexCompiled_path2, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, path2);
                    snprintf(path2, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                } else if (regexec(&regexCompiled_path2_hex, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                    if (decoded_buffer) {
                        const int decoded_length = match_size / 2;
                        os_malloc(decoded_length + 1, path2);
                        snprintf(path2, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                        os_free(decoded_buffer);
                    } else {
                        merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                    }
                }

                if (w_evt->cwd && path1 && path2) {
                    if (file_path = gen_audit_path(w_evt->cwd, path1, path2), file_path) {
                        w_evt->path = file_path;
                        mdebug2(FIM_AUDIT_EVENT(w_evt->user_name) ? w_evt->user_name : "",
                                (w_evt->audit_name) ? w_evt->audit_name : "",
                                (w_evt->effective_name) ? w_evt->effective_name : "",
                                (w_evt->group_name) ? w_evt->group_name : "", w_evt->process_id, w_evt->ppid,
                                (w_evt->inode) ? w_evt->inode : "", (w_evt->path) ? w_evt->path : "",
                                (w_evt->process_name) ? w_evt->process_name : "");

                        if (w_evt->inode) {
                            fim_whodata_event(w_evt);
                        }
                    }
                }
                free(path2);
                break;
            case 4:
                // path2
                if (regexec(&regexCompiled_path2, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, path2);
                    snprintf(path2, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                } else if (regexec(&regexCompiled_path2_hex, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                    if (decoded_buffer) {
                        const int decoded_length = match_size / 2;
                        os_malloc(decoded_length + 1, path2);
                        snprintf(path2, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                        os_free(decoded_buffer);
                    } else {
                        merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                    }
                }

                // path3
                if (regexec(&regexCompiled_path3, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, path3);
                    snprintf(path3, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                } else if (regexec(&regexCompiled_path3_hex, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                    if (decoded_buffer) {
                        const int decoded_length = match_size / 2;
                        os_malloc(decoded_length + 1, path3);
                        snprintf(path3, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
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
                        mdebug2(FIM_AUDIT_EVENT1(w_evt->user_name) ? w_evt->user_name : "",
                                (w_evt->audit_name) ? w_evt->audit_name : "",
                                (w_evt->effective_name) ? w_evt->effective_name : "",
                                (w_evt->group_name) ? w_evt->group_name : "", w_evt->process_id, w_evt->ppid,
                                (w_evt->inode) ? w_evt->inode : "", (w_evt->path) ? w_evt->path : "",
                                (w_evt->process_name) ? w_evt->process_name : "");

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
                        mdebug2(FIM_AUDIT_EVENT2(w_evt->user_name) ? w_evt->user_name : "",
                                (w_evt->audit_name) ? w_evt->audit_name : "",
                                (w_evt->effective_name) ? w_evt->effective_name : "",
                                (w_evt->group_name) ? w_evt->group_name : "", w_evt->process_id, w_evt->ppid,
                                (w_evt->inode) ? w_evt->inode : "", (w_evt->path) ? w_evt->path : "",
                                (w_evt->process_name) ? w_evt->process_name : "");

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
                if (regexec(&regexCompiled_path4, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    os_malloc(match_size + 1, path4);
                    snprintf(path4, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
                } else if (regexec(&regexCompiled_path4_hex, buffer, 2, match, 0) == 0) {
                    match_size = match[1].rm_eo - match[1].rm_so;
                    char *decoded_buffer = decode_hex_buffer_2_ascii_buffer(buffer + match[1].rm_so, match_size);
                    if (decoded_buffer) {
                        const int decoded_length = match_size / 2;
                        os_malloc(decoded_length + 1, path4);
                        snprintf(path4, decoded_length + 1, "%.*s", decoded_length, decoded_buffer);
                        os_free(decoded_buffer);
                    } else {
                        merror("Error found while decoding HEX bufer: '%.*s'", match_size, buffer + match[1].rm_so);
                    }
                }

                if (w_evt->cwd && path1 && path4) {
                    char *file_path;
                    if (file_path = gen_audit_path(w_evt->cwd, path1, path4), file_path) {
                        w_evt->path = file_path;
                        mdebug2(FIM_AUDIT_EVENT(w_evt->user_name) ? w_evt->user_name : "",
                                (w_evt->audit_name) ? w_evt->audit_name : "",
                                (w_evt->effective_name) ? w_evt->effective_name : "",
                                (w_evt->group_name) ? w_evt->group_name : "", w_evt->process_id, w_evt->ppid,
                                (w_evt->inode) ? w_evt->inode : "", (w_evt->path) ? w_evt->path : "",
                                (w_evt->process_name) ? w_evt->process_name : "");

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
        if (regexec(&regexCompiled_syscall, buffer, 2, match, 0) == 0) {
            match_size = match[1].rm_eo - match[1].rm_so;
            char *syscall = NULL;
            os_malloc(match_size + 1, syscall);
            snprintf(syscall, match_size + 1, "%.*s", match_size, buffer + match[1].rm_so);
            if (!strcmp(syscall, "2") || !strcmp(syscall, "257") || !strcmp(syscall, "5") || !strcmp(syscall, "295")) {
                // x86_64: 2 open
                // x86_64: 257 openat
                // i686: 5 open
                // i686: 295 openat
                mdebug2(FIM_HEALTHCHECK_CREATE, syscall);
                audit_health_check_creation = 1;
            } else if (!strcmp(syscall, "87") || !strcmp(syscall, "263") || !strcmp(syscall, "10") ||
                       !strcmp(syscall, "301")) {
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

#endif // ENABLE_AUDIT
#endif // __linux__
