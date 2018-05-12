/*
 * Wazuh Integration with Osquery
 * Copyright (C) 2018 Wazuh Inc.
 * April 5, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <sys/stat.h>
#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>

#define TMP_CONFIG_PATH "/tmp/osquery.conf.tmp"

#define minfo(format, ...) mtinfo(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define mwarn(format, ...) mtwarn(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define merror(format, ...) mterror(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define mdebug1(format, ...) mtdebug1(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define mdebug2(format, ...) mtdebug2(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)

static void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor);
static void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor);
static int wm_osquery_check_logfile(const char * path, FILE * fp);
static int wm_osquery_packs(wm_osquery_monitor_t *osquery);

static volatile int active = 1;

const wm_context WM_OSQUERYMONITOR_CONTEXT =
    {
        "osquery",
        (wm_routine)wm_osquery_monitor_main,
        (wm_routine)wm_osquery_monitor_destroy};

void *Read_Log(wm_osquery_monitor_t * osquery)
{
    int i = 0;
    ino_t current_inode;
    char line[OS_MAXSTR];
    FILE *result_log = NULL;
    char * end;

    while (active) {
        // Wait to open log file

        while (result_log = fopen(osquery->log_path, "r"), !result_log && active) {
            mwarn("Results file '%s' not available: %s (%d)", osquery->log_path, strerror(errno), errno);
            sleep(i < 60 ? ++i : 60);
        }

        if (!active) {
            fclose(result_log);
            break;
        }

        // Move to end of the file

        if (fseek(result_log, 0, SEEK_END) < 0) {
            merror(FSEEK_ERROR, osquery->log_path, errno, strerror(errno));
            fclose(result_log);
            continue;
        }

        // Save file inode

        if (current_inode = get_fp_inode(result_log), current_inode == (ino_t)-1) {
            merror("Couldn't get inode of file '%s': %s (%d)", osquery->log_path, strerror(errno), errno);
            fclose(result_log);
            continue;
        }

        // Read the file

        while (active) {
            // Get file until EOF

            while (fgets(line, OS_MAXSTR, result_log)) {
                // Remove newline
                if (end = strchr(line, '\n'), end) {
                    *end = '\0';
                }

                mdebug2("Sending... '%s'", line);
                if (wm_sendmsg(osquery->msg_delay, osquery->queue_fd, line, "osquery", LOCALFILE_MQ) < 0) {
                    mterror(WM_OSQUERYMONITOR_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                }
            }

            // Check if result path inode has changed.

            switch (wm_osquery_check_logfile(osquery->log_path, result_log)) {
            case -1:
                mwarn("Error accessing results file '%s': %s (%d)", osquery->log_path, strerror(errno), errno);
                goto endloop;
            case 0:
                // File did not change
                sleep(1);
                break;
            case 1:
                minfo("Results file '%s' truncated. Reloading.", osquery->log_path);

                if (fseek(result_log, 0, SEEK_SET) < 0) {
                    merror(FSEEK_ERROR, osquery->log_path, errno, strerror(errno));
                    goto endloop;
                }

                break;
            case 2:
                minfo("Results file '%s' rotated. Reloading.", osquery->log_path);
                goto endloop;
            }
        }

endloop:
        fclose(result_log);
    }

    return NULL;
}

/*
 * Check if file changed.
 * -1: error, file no longer exists.
 * 0: file did not change.
 * 1: file truncated.
 * 2: file rotated (inode changed)
 */
int wm_osquery_check_logfile(const char * path, FILE * fp) {
    struct stat buf;
    ino_t old_inode;
    long old_size;

    if (old_inode = get_fp_inode(fp), old_inode == (ino_t)-1) {
        return -1;
    } else if (old_size = ftell(fp), old_size < 0) {
        return -1;
    }

    return stat(path, &buf) < 0 ? -1 : buf.st_ino != old_inode ? 2 : buf.st_size < old_size ? 1 : 0;
}

void *Execute_Osquery(wm_osquery_monitor_t *osquery)
{
    char osqueryd_path[PATH_MAX];
    char config_path[PATH_MAX];

    snprintf(osqueryd_path, sizeof(osqueryd_path), "%s/osqueryd", osquery->bin_path);
    snprintf(config_path, sizeof(config_path), "--config_path=%s", osquery->config_path);

    // We check that the osquery demon is not down, in which case we run it again.

    while (1) {
        char buffer[4096];
        time_t time_started;
        wfd_t * wfd;
        int wstatus;
        char * text;
        char * end;

        if (wfd = wpopenl(osqueryd_path, W_BIND_STDERR | W_APPEND_POOL, osqueryd_path, config_path, NULL), !wfd) {
            mwarn("Couldn't execute osquery (%s). Sleeping for 10 minutes.", osqueryd_path);
            sleep(600);
        }

        time_started = time(NULL);

        // Get stderr

        while (fgets(buffer, sizeof(buffer), wfd->file)) {
            // Filter Bash colors: \e[*m
            text = buffer[0] == '\e' && buffer[1] == '[' && (end = strchr(buffer + 2, 'm'), end) ? end + 1 : buffer;

            // Remove newline
            if (end = strchr(text, '\n'), end) {
                *end = '\0';
            }

            if (strlen(text)) {
                // Parse most common osquery errors

                if (strstr(text, "[Ref #1382]")) {
                    mwarn("osqueryd has unsafe permissions.");
                } else if (strstr(text, "[Ref #1629]")) {
                    mwarn("osqueryd initialize failed: Could not initialize database.");
                } else {
                    switch (text[0]) {
                    case 'E':
                    case 'W':
                        mwarn("%s", text);
                        break;
                    default:
                        mdebug2("%s", text);
                    }
                }

                // Report to manager

                if (wm_sendmsg(osquery->msg_delay, osquery->queue_fd, text, "osquery", LOCALFILE_MQ) < 0) {
                    mterror(WM_OSQUERYMONITOR_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                }
            }
        }

        // If this point is reached, osquery exited

        wstatus = WEXITSTATUS(wpclose(wfd));

        if (wstatus == 127) {
            // 127 means error in exec
            merror("Couldn't execute osquery (%s). Check file and permissions.", osqueryd_path);
            active = 0;
            return NULL;
        } else if (time(NULL) - time_started < 10) {
            // If osquery was alive less than 10 seconds, give up
            merror("Osquery exited with code %d. Closing module.", wstatus);
            active = 0;
            return NULL;
        } else {
            mwarn("Osquery exited with code %d. Restarting.", wstatus);
        }
    }
}

int wm_osquery_decorators(wm_osquery_monitor_t * osquery)
{
    char *key = NULL;
    char *value = NULL;
    cJSON *root = NULL;
    cJSON *decorators;
    cJSON *always;
    wlabel_t *labels;
    char buffer[OS_MAXSTR];
    int retval = -1;
    int i;

    // Is label addition enabled?

    if (!osquery->add_labels) {
        return 0;
    }

    os_calloc(1, sizeof(wlabel_t), labels);

    if (ReadConfig(CLABELS, DEFAULTCPATH, &labels, NULL) < 0)
        goto end;

#ifdef CLIENT
    if (ReadConfig(CLABELS | CAGENT_CONFIG, AGENTCONFIG, &labels, NULL) < 0)
    {
        goto end;
    }
#endif

    // Do we have labels defined?

    if (!labels[0].key) {
        retval = 0;
        goto end;
    }

    // Load original osquery configuration

    if (root = json_fread(osquery->config_path), !root) {
        merror("Couldn't load configuration file '%s': %s (%d)", osquery->config_path, strerror(errno), errno);
        goto end;
    }

    // Add labels to JSON as decorators

    if (decorators = cJSON_GetObjectItem(root, "decorators"), !decorators) {
        decorators = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "decorators", decorators);
    }

    if (always = cJSON_GetObjectItem(decorators, "always"), !always) {
        always = cJSON_CreateArray();
        cJSON_AddItemToObject(decorators, "always", always);
    }

    for (i = 0; labels[i].key; ++i) {
        // Prevent SQL injection
        key = wstr_replace(labels[i].key, "'", "''");
        value = wstr_replace(labels[i].value, "'", "''");

        if (snprintf(buffer, sizeof(buffer), "SELECT '%s' AS '%s';", value, key) < (int)sizeof(buffer)) {
            mdebug2("Adding decorator: %s", buffer);
            cJSON_AddItemToArray(always, cJSON_CreateString(buffer));
        } else {
            mwarn("Label '%s' too long. Couldn't insert decorator.", labels[i].key);
        }

        free(key);
        free(value);
    }

    // Change configuration file path

    free(osquery->config_path);
    os_strdup(DEFAULTDIR TMP_CONFIG_PATH, osquery->config_path);

    // Write new configuration

    if (json_fwrite(osquery->config_path, root) < 0) {
        merror("At %s(): couldn't write JSON content into configuration '%s': %s (%d)", __func__, osquery->config_path, strerror(errno), errno);
        goto end;
    }

    retval = 0;

end:
    labels_free(labels);
    cJSON_Delete(root);
    return retval;
}

int wm_osquery_packs(wm_osquery_monitor_t *osquery)
{
    cJSON * root;
    cJSON * packs;
    int i;
    int retval = 0;

    // Do we have packs defined?

    for (i = 0; osquery->packs[i]; ++i);

    if (!i) {
        return 0;
    }

    // Load original osquery configuration

    if (root = json_fread(osquery->config_path), !root) {
        merror("Couldn't load configuration file '%s': %s (%d)", osquery->config_path, strerror(errno), errno);
        return -1;
    }

    // Add packs to JSON

    if (packs = cJSON_GetObjectItem(root, "packs"), !packs) {
        packs = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "packs", packs);
    }

    for (i = 0; osquery->packs[i]; ++i) {
        cJSON_AddStringToObject(packs, osquery->packs[i]->name, osquery->packs[i]->path);
    }

    // Change configuration file path

    free(osquery->config_path);
    os_strdup(DEFAULTDIR TMP_CONFIG_PATH, osquery->config_path);

    // Write new configuration

    if (json_fwrite(osquery->config_path, root) < 0) {
        merror("At %s(): couldn't write JSON content into configuration '%s': %s (%d)", __func__, osquery->config_path, strerror(errno), errno);
        retval = -1;
    }

    cJSON_Delete(root);
    return retval;
}

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery)
{
    int i;
    pthread_t thread1, thread2;

    osquery->msg_delay = 1000000 / wm_max_eps;
    minfo("Module started.");

    // Connect to queue

    for (i = 0; osquery->queue_fd = StartMQ(DEFAULTQPATH, WRITE), osquery->queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++) {
        // Trying to connect to queue
        sleep(WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "Can't connect to queue. Closing module.");
        return NULL;
    }

    // Handle configuration

    if (wm_osquery_packs(osquery) < 0 || wm_osquery_decorators(osquery) < 0) {
        return NULL;
    }

    pthread_create(&thread1, NULL, (void *)&Execute_Osquery, osquery);
    pthread_create(&thread2, NULL, (void *)&Read_Log, osquery);

    pthread_join(thread2, NULL);
    pthread_join(thread1, NULL);

    minfo("Closing module.");
    return NULL;
}

void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor)
{
    int i;

    if (osquery_monitor)
    {
        free(osquery_monitor->bin_path);
        free(osquery_monitor->log_path);
        free(osquery_monitor->config_path);

        for (i = 0; osquery_monitor->packs[i]; ++i) {
            free(osquery_monitor->packs[i]->name);
            free(osquery_monitor->packs[i]->path);
        }

        free(osquery_monitor);
    }
}
