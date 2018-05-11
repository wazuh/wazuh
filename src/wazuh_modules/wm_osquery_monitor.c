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
static char *osquery_config_temp = NULL;

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
    snprintf(config_path, sizeof(config_path), "--config_path=%s%s", DEFAULTDIR, TMP_CONFIG_PATH);

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

        // If osquery was alive less than 10 seconds, give up

        if (time(NULL) - time_started < 10) {
            merror("Osquery exited with code %d. Closing module.", wstatus);
            active = 0;
            pthread_exit(NULL);
        } else {
            mwarn("Osquery exited with code %d. Restarting.", wstatus);
        }
    }
}

void wm_osquery_decorators()
{
    char *line = strdup("");
    char *select = strdup("SELECT ");
    char *as = strdup(" AS ");
    char *key = NULL;
    char *value = NULL;
    char *coma = strdup(", ");
    char *json_block = NULL;
    char *firstPath = strdup(DEFAULTDIR);
    char *lastpath = strdup("/etc/ossec.conf");
    char *configPath = NULL;
    cJSON *root;
    cJSON *decorators;
    cJSON *always;
    wlabel_t *labels;
    struct stat stp = {0};
    char *content;
    FILE *osquery_conf = NULL;
    //PATH CREATION

    osquery_config_temp = strdup("/var/ossec/tmp/osquery.conf.tmp");
    os_malloc(strlen(firstPath) + strlen(lastpath), configPath);

    strcpy(configPath, firstPath);
    strcat(configPath, lastpath);

    //CJSON OBJECTS
    int i = 0;

    os_calloc(1, sizeof(wlabel_t), labels);

    if (ReadConfig(CLABELS | CBUFFER, configPath, &labels, NULL) < 0)
        return;

#ifdef CLIENT
    if (ReadConfig(CLABELS, AGENTCONFIG, &labels, NULL) < 0)
    {
        return;
    }

#endif

    root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "decorators", decorators = cJSON_CreateObject());
    cJSON_AddItemToObject(decorators, "always", always = cJSON_CreateArray());

    //OPEN OSQUERY CONF
    if (osquery_conf = fopen(osquery_config_temp, "r"), !osquery_conf)
    {
        merror("Cannot read tmp config file, exiting...");
        pthread_exit(0);
    }
    if(stat(osquery_config_temp, &stp)<0)
    {
        merror("invalid tmp file descriptor, exiting...");
        pthread_exit(0);
    }
    int filesize = stp.st_size;

    os_malloc(filesize + 1, content);

    if (fread(content, 1, filesize, osquery_conf) == 0)
    {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "error in reading");
        //free input string
        free(content);
    }
    content[filesize + 1] = '\0';
    //CHECK IF CONF HAVE DECORATORS
    int decorated = 0;
    if (strstr(content, "decorators") != NULL)
        decorated = 1;
    else
        decorated = 0;

    //ADD DECORATORS FROM AGENT LABELS
    if (!decorated)
    {

        for (i = 0; labels[i].key != NULL; i++)
        {
            key = strdup(labels[i].key);
            value = strdup(labels[i].value);
            int newlen = sizeof(char) * (strlen("select") + strlen(line) + strlen(key) + strlen(as) + strlen(value) + (6 * sizeof(char)));
            line = (char *)realloc(line, newlen);
            snprintf(line, newlen, "select '%s' as '%s';", value, key);
            cJSON_AddStringToObject(always, "line", line);
        }

        json_block = cJSON_PrintUnformatted(root);
        memmove(json_block, json_block + 1, strlen(json_block));
        content[strlen(content) - 1] = ',';
        content = realloc(content, sizeof(char) * (strlen(content) + strlen(json_block)));
        strcat(content, json_block);
        fclose(osquery_conf);
    }
    //Write content to TMPFile
    osquery_conf = fopen(osquery_config_temp, "w");
    fprintf(osquery_conf, "%s", content);
    fclose(osquery_conf);

    //FREE MEMORY
    free(line);
    free(select);
    free(as);
    free(key);
    free(value);
    free(coma);
    free(firstPath);
    free(lastpath);
    free(configPath);
    free(json_block);
    cJSON_Delete(root);
}



int wm_osquery_packs(wm_osquery_monitor_t *osquery)
{
    FILE * osquery_config_file = NULL;
    long filesize;
    char *content = NULL;
    cJSON * root;
    cJSON * packs;
    int i;
    int retval = -1;

    // Do we have packs defined?

    for (i = 0; osquery->packs[i]; ++i);

    if (!i) {
        return 0;
    }

    // Load original osquery configuration

    if (osquery_config_file = fopen(osquery->config_path, "r"), !osquery_config_file) {
        merror(FOPEN_ERROR, osquery->config_path, errno, strerror(errno));
        return -1;
    }

    // Get file size and alloc memory

    if (filesize = get_fp_size(osquery_config_file), filesize < 0) {
        merror(FSEEK_ERROR, osquery->config_path, errno, strerror(errno));
        goto end;
    }

    os_malloc(filesize + 1, content);

    // Get file and parse into JSON

    if (fread(content, 1, filesize, osquery_config_file) == 0)
    {
        merror(FREAD_ERROR, osquery->config_path, errno, strerror(errno));
        goto end;
    }

    content[filesize] = '\0';
    fclose(osquery_config_file);
    osquery_config_file = NULL;

    if (root = cJSON_Parse(content), !root) {
        mwarn("Couldn't parse JSON file '%s'", osquery->config_path);
        goto end;
    }

    // Add packs to JSON

    if (packs = cJSON_GetObjectItem(root, "packs"), !packs) {
        packs = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "packs", packs);
    }

    for (i = 0; osquery->packs[i]; ++i) {
        cJSON_AddStringToObject(packs, osquery->packs[i]->name, osquery->packs[i]->path);
    }

    // Print JSON into string

    free(osquery->config_path);
    os_strdup(DEFAULTDIR TMP_CONFIG_PATH, osquery->config_path);

    free(content);
    content = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    filesize = strlen(content);

    // Write new configuration

    if (osquery_config_file = fopen(osquery->config_path, "w"), !osquery_config_file) {
        merror(FOPEN_ERROR, osquery->config_path, errno, strerror(errno));
        goto end;
    }

    if (fwrite(content, 1, filesize, osquery_config_file) != (size_t)filesize) {
        merror("Couldn't write JSON content into configuration '%s': %s (%d)", osquery->config_path, strerror(errno), errno);
        goto end;
    }

    retval = 0;

end:

    if (osquery_config_file) {
        fclose(osquery_config_file);
    }

    free(content);
    return retval;
}

void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery)
{
    int i;
    pthread_t thread1, thread2;

    osquery->msg_delay = 1000000 / wm_max_eps;

    // Connect to queue

    for (i = 0; osquery->queue_fd = StartMQ(DEFAULTQPATH, WRITE), osquery->queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++) {
        // Trying to connect to queue
        sleep(WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "Can't connect to queue. Closing module.");
        pthread_exit(NULL);
    }

    // Handle configuration

    if (wm_osquery_packs(osquery) < 0) {
        return NULL;
    }

    wm_osquery_decorators(osquery);

    pthread_create(&thread1, NULL, (void *)&Execute_Osquery, osquery);
    pthread_create(&thread2, NULL, (void *)&Read_Log, osquery);

    pthread_join(thread2, NULL);
    pthread_join(thread1, NULL);
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
