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

#define TMP_CONFIG_PATH "tmp/osquery.conf.tmp"

#define minfo(format, ...) mtinfo(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define mwarn(format, ...) mtwarn(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define merror(format, ...) mterror(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define mdebug1(format, ...) mtdebug1(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)
#define mdebug2(format, ...) mtdebug2(WM_OSQUERYMONITOR_LOGTAG, format, ##__VA_ARGS__)

static void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor);
static void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor);
static int wm_osquery_check_logfile(const char * path, FILE * fp);

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
    snprintf(config_path, sizeof(config_path), "--config_path=%s/%s", DEFAULTDIR, TMP_CONFIG_PATH);

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

void wm_osquery_packs(wm_osquery_monitor_t *osquery_monitor)
{
    //LEER ARCHIVO AGENT.CONF
    char *agent_conf_path = NULL;
    FILE *agent_conf_file = NULL;
    FILE *osquery_config_file = NULL;
    FILE *osquery_config_temp_file = NULL;
    char *packs_line = NULL;
    char *osquery_config = NULL;
    char *content = NULL;
    char *osquery_config_temp = NULL;
    char *line = NULL;
    char *firstIndex = NULL;
    char *lastIndex = NULL;
    char *namepath = NULL;
    char *aux = NULL;
    char *auxLine = NULL;
    size_t line_size = OS_MAXSTR;
    int num_chars = 0;
    struct stat stp = {0};
    osquery_config_temp = "/var/ossec/tmp/osquery.conf.tmp";
    os_malloc(strlen(DEFAULTDIR) + strlen("/etc/shared/default/agent.conf") + 1, agent_conf_path);
    os_malloc(OS_MAXSTR, line);

    snprintf(agent_conf_path, strlen(DEFAULTDIR) + strlen("/etc/shared/default/agent.conf") + 1, "%s%s", DEFAULTDIR, "/etc/shared/default/agent.conf");
    packs_line = strdup(",\"packs\": {");

    if (agent_conf_file = fopen("/var/ossec/etc/shared/default/agent.conf", "r"), !agent_conf_file)
    {
        merror("Error reading angent config, exiting...");
        pthread_exit(0);
    }

    if (osquery_config_file = fopen(osquery_monitor->config_path, "r"), !osquery_config_file)
    {
        merror("Error reading osquery config, exiting...");
        free(osquery_config);
        pthread_exit(0);
    }
    if (stat(osquery_monitor->config_path, &stp) < 0)
    {
        merror("error in file descriptor, exiting..");
        free(osquery_config);
        pthread_exit(0);
    }
    int filesize = stp.st_size;

    os_malloc(filesize, content);

    if (fread(content, 1, filesize - 2, osquery_config_file) == 0)
    {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "error in reading");
        //free input string
        free(content);
    }

    while ((num_chars = getline(&line, &line_size, agent_conf_file)) && num_chars != -1)
    {
        if (strstr(line, "<pack>"))
        {

            os_malloc(strlen(line), auxLine);
            firstIndex = strstr(line, ">") + 1;
            lastIndex = strstr(firstIndex, "<");

            namepath = strdup("\"Pack\": ");
            auxLine = (char *)realloc(auxLine, (strlen(firstIndex) - strlen(lastIndex)));
            memcpy(auxLine, firstIndex, strlen(firstIndex) - strlen(lastIndex));
            os_malloc(strlen(namepath) + strlen(auxLine) + strlen("\"\0"), aux);
            snprintf(aux, strlen(namepath) + strlen(auxLine) + 3, " %s\"%s", namepath, auxLine);
            int newlen = strlen(packs_line) + strlen(aux);
            packs_line = (char *)realloc(packs_line, newlen + 2);
            strcat(packs_line, aux);
            strcat(packs_line, "/*\",");
        }
    }
    strcat(packs_line, "}");
    content = (char *)realloc(content, strlen(packs_line) + strlen(content) + 2);
    char *finalAux = NULL;
    os_malloc(strlen(packs_line) + strlen(content) + 2, finalAux);
    snprintf(finalAux, strlen(packs_line) + strlen(content) + 2, "%s%s", content, packs_line);
    osquery_config_temp_file = fopen(osquery_config_temp, "w");
    fprintf(osquery_config_temp_file, "%s", finalAux);
    fclose(osquery_config_temp_file);

    free(agent_conf_path);
    free(packs_line);
    free(osquery_config);
    free(content);
    free(line);
    free(finalAux);
    free(namepath);
    free(aux);
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

    // Parse configuration

    wm_osquery_packs(osquery);
    wm_osquery_decorators(osquery);

    pthread_create(&thread1, NULL, (void *)&Execute_Osquery, osquery);
    pthread_create(&thread2, NULL, (void *)&Read_Log, osquery);

    pthread_join(thread2, NULL);
    pthread_join(thread1, NULL);
    return NULL;
}
void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor)
{
    if (!osquery_monitor)
    {
        free(osquery_monitor->bin_path);
        free(osquery_monitor->log_path);
        free(osquery_monitor->config_path);
        free(osquery_monitor);
    }
}
