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
#include "syscheck_audit.h"
#include "external/procps/readproc.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <os_net/os_net.h>
#include "syscheck_op.h"
#include "audit_op.h"
#include "string_op.h"

#define AUDIT_CONF_FILE DEFAULTDIR "/etc/af_wazuh.conf"
#define PLUGINS_DIR_AUDIT_2 "/etc/audisp/plugins.d"
#define PLUGINS_DIR_AUDIT_3 "/etc/audit/plugins.d"
#define AUDIT_CONF_LINK "af_wazuh.conf"
#define BUF_SIZE OS_MAXSTR
#define MAX_CONN_RETRIES 5 // Max retries to reconnect to Audit socket


#ifndef WAZUH_UNIT_TESTING
#define audit_thread_status() ((mode == READING_MODE && audit_thread_active) || \
                                (mode == HEALTHCHECK_MODE && hc_thread_active))
#else
#define audit_thread_status() FOREVER()
#endif

// Global variables
pthread_mutex_t audit_mutex;
pthread_mutex_t audit_rules_mutex;
pthread_cond_t audit_db_consistency;
pthread_cond_t audit_thread_started;

unsigned int count_reload_retries;

//This variable controls if the the modification of the rule is made by syscheck.

volatile int audit_db_consistency_flag = 0;
volatile int audit_thread_active;

#ifdef ENABLE_AUDIT
typedef struct _audit_data_s {
    int socket;
    audit_mode mode;
} audit_data_t;

/**
 * @brief Creates the necessary threads to process audit events
 *
 * @param [out] audit_data Struct that saves the audit socket to read the events from and the audit mode.
 */
static void *audit_main(audit_data_t *audit_data);

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

void audit_no_rules_to_realtime() {
    int found;
    char *real_path = NULL;
    int i;

    for (i = 0; syscheck.dir[i] != NULL; i++) {
        if ((syscheck.opts[i] & WHODATA_ACTIVE) == 0) {
            continue;
        }
        real_path = fim_get_real_path(i);
        found = search_audit_rule(real_path, WHODATA_PERMS, AUDIT_KEY);

        if (found == 0) {   // No rule found
            mwarn(FIM_ERROR_WHODATA_ADD_DIRECTORY, real_path);
            syscheck.opts[i] &= ~WHODATA_ACTIVE;
            syscheck.opts[i] |= REALTIME_ACTIVE;
        }
        free(real_path);
    }
}

// LCOV_EXCL_START
int audit_init(void) {
    static audit_data_t audit_data = { .socket = -1, .mode = AUDIT_DISABLED };

    w_mutex_init(&audit_mutex, NULL);

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
    audit_data.socket = init_auditd_socket();
    if (audit_data.socket < 0) {
        merror("Can't init auditd socket in 'init_auditd_socket()'");
        return -1;
    }

    int regex_comp = init_regex();
    if (regex_comp < 0) {
        merror("Can't init regex in 'init_regex()'");
        return -1;
    }

    if (fim_audit_rules_init() != 0) {
        return -1;
    }

    // Perform Audit healthcheck
    if (syscheck.audit_healthcheck) {
        if(audit_health_check(audit_data.socket)) {
            merror(FIM_ERROR_WHODATA_HEALTHCHECK_START);
            return -1;
        }
    } else {
        minfo(FIM_AUDIT_HEALTHCHECK_DISABLE);
    }

    // Change to realtime directories that don't have any rules when Auditd is in immutable mode
    int auditd_fd = audit_open();
    audit_data.mode = audit_is_enabled(auditd_fd);
    audit_close(auditd_fd);

    switch (audit_data.mode) {
    case AUDIT_IMMUTABLE:
        audit_no_rules_to_realtime();
        break;
    case AUDIT_ENABLED:
        fim_rules_initial_load();
        atexit(clean_rules);
        break;
    case AUDIT_DISABLED:
        mwarn(FIM_AUDIT_DISABLED);
        return -1;
    default:
        merror(FIM_ERROR_AUDIT_MODE, strerror(errno), errno);
        return -1;
    }

    // Start audit thread
    w_cond_init(&audit_thread_started, NULL);
    w_cond_init(&audit_db_consistency, NULL);
    w_create_thread(audit_main, &audit_data);
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

// LCOV_EXCL_START
void *audit_main(audit_data_t *audit_data) {
    char *path = NULL;
    int pos;
    count_reload_retries = 0;
    audit_thread_active = 0;

    w_mutex_lock(&audit_mutex);
    audit_thread_active = 1;
    w_cond_signal(&audit_thread_started);

    while (!audit_db_consistency_flag) {
        w_cond_wait(&audit_db_consistency, &audit_mutex);
    }

    w_mutex_unlock(&audit_mutex);

    if (audit_data->mode == AUDIT_ENABLED) {
        // Start rules reloading thread
        w_create_thread(audit_reload_thread, NULL);
    }

    minfo(FIM_WHODATA_STARTED);

    // Read events
    audit_read_events(&audit_data->socket, READING_MODE);

    // Auditd is not runnig or socket closed.
    mdebug1(FIM_AUDIT_THREAD_STOPED);
    close(audit_data->socket);

    // Clean regexes used for parsing events
    clean_regex();
    // Change Audit monitored folders to Inotify.
    for (pos = 0; syscheck.dir[pos]; pos++) {
        if ((syscheck.opts[pos] & WHODATA_ACTIVE) == 0) {
            continue;
        }
        path = fim_get_real_path(pos);
        // Check if it's a broken link.
        if (*path == '\0') {
            free(path);
            continue;
        }
        syscheck.opts[pos] &= ~ WHODATA_ACTIVE;
        syscheck.opts[pos] |= REALTIME_ACTIVE;

        realtime_adddir(path, 0, (syscheck.opts[pos] & CHECK_FOLLOW) ? 1 : 0);
        free(path);
    }

    // Clean Audit added rules.
    if (audit_data->mode == AUDIT_ENABLED) {
        clean_rules();
    }

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
                fim_audit_reload_rules();
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

        os_free(event_too_long_id);
    }

    free(cache_id);
    free(cache);
    free(buffer);
}

#endif
#endif
