/*
 * Wazuh Integration with Osquery
 * Copyright (C) 2015, Wazuh Inc.
 * April 5, 2018.
 *
 * This program is free software; you can redistribute it
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

#ifdef WIN32
#define OSQUERYD_BIN "osqueryd.exe"
#else
#define OSQUERYD_BIN "osqueryd"
#endif

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_OSQUERYMONITOR_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#ifdef WIN32
static DWORD WINAPI wm_osquery_monitor_main(void *arg);
#else
static void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery_monitor);
#endif
static void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor);
static int wm_osquery_check_logfile(const char * path, FILE * fp);
static int wm_osquery_packs(wm_osquery_monitor_t *osquery);
STATIC char * wm_osquery_already_running(char * text);
cJSON *wm_osquery_dump(const wm_osquery_monitor_t *osquery_monitor);

static volatile int active = 1;

const wm_context WM_OSQUERYMONITOR_CONTEXT = {
    .name = "osquery",
    .start = (wm_routine)wm_osquery_monitor_main,
    .destroy = (void(*)(void *))wm_osquery_monitor_destroy,
    .dump = (cJSON * (*)(const void *))wm_osquery_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

void *Read_Log(wm_osquery_monitor_t * osquery)
{
    int i = 0;
    wino_t current_inode;
    char line[OS_MAXSTR];
    FILE *result_log = NULL;
    char * end;
    char * payload;
    cJSON * root;
    cJSON * name;
    cJSON * osquery_json;
    char * begin;

    while (active) {
        // Wait to open log file

        while (result_log = wfopen(osquery->log_path, "r"), !result_log && active) {
            i += i < 60;
            mwarn("Results file '%s' not available: %s (%d). Retrying in %d sec.", osquery->log_path, strerror(errno), errno, i);
            sleep(i);
        }

        if (!active) {
            if (result_log) {
                fclose(result_log);
            }

            break;
        }

        minfo("Following osquery results file '%s'.", osquery->log_path);

        // Move to end of the file

        if (fseek(result_log, 0, SEEK_END) < 0) {
            merror(FSEEK_ERROR, osquery->log_path, errno, strerror(errno));
            fclose(result_log);
            continue;
        }

        // Save file inode

        if (current_inode = get_fp_inode(result_log), current_inode == (wino_t)-1) {
            merror("Couldn't get inode of file '%s': %s (%d)", osquery->log_path, strerror(errno), errno);
            fclose(result_log);
            continue;
        }

        // Read the file

        while (active) {
            clearerr(result_log);

            // Get file until EOF

            while (fgets(line, OS_MAXSTR, result_log)) {

                // Remove newline

                if (end = strchr(line, '\n'), end) {
                    *end = '\0';
                }

                const char *jsonErrPtr;
                if (osquery_json = cJSON_ParseWithOpts(line, &jsonErrPtr, 0), osquery_json) {

                    // Nest object into a "osquery" object

                    root = cJSON_CreateObject();
                    cJSON_AddItemToObject(root, "osquery", osquery_json);

                    if (!cJSON_GetObjectItem(osquery_json, "pack")) {

                        // Try to find a name matching "pack_.*_.+"

                        if (name = cJSON_GetObjectItem(osquery_json, "name"), name && cJSON_IsString(name)) {
                            if (strstr(name->valuestring, "pack_")) {
                                begin = name->valuestring + 5;

                                if (end = strchr(begin, '_'), end && end[1]) {
                                    *end = '\0';
                                    cJSON_AddStringToObject(osquery_json, "pack", begin);
                                    *end = '_';
                                    end += 1;
                                    cJSON_AddStringToObject(osquery_json, "subquery", end);
                                }
                            }
                        }
                    }

                    payload = cJSON_PrintUnformatted(root);
                    mdebug2("Sending... '%s'", payload);

                    if (wm_sendmsg(osquery->msg_delay, osquery->queue_fd, payload, "osquery", LOCALFILE_MQ) < 0) {
                        mterror(WM_OSQUERYMONITOR_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                    }

                    free(payload);
                    cJSON_Delete(root);
                } else {
                    static int reported = 0;

                    if (!reported) {
                        mwarn("Result line not in JSON format: '%64s'...", line);
                        reported = 1;
                    }
                }
            }

            // Check if result path inode has changed.

            switch (wm_osquery_check_logfile(osquery->log_path, result_log)) {
            case -1:
                if (errno == ENOENT) {
                    minfo("Results file '%s' was deleted.", osquery->log_path);
                } else {
                    mwarn("Couldn't access results file '%s': %s (%d)", osquery->log_path, strerror(errno), errno);
                }

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
    wino_t old_inode;
    long old_size;

    if (old_inode = get_fp_inode(fp), old_inode == (wino_t)-1) {
        return -1;
    } else if (old_size = ftell(fp), old_size < 0) {
        return -1;
    }

    if (stat(path, &buf) < 0) {
        return -1;
    }

#ifdef WIN32
    HANDLE hFile;
    BY_HANDLE_FILE_INFORMATION fileInfo;

    if (hFile = wCreateFile(path, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL), hFile == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (GetFileInformationByHandle(hFile, &fileInfo) == 0) {
        CloseHandle(hFile);
        return -1;
    }

    CloseHandle(hFile);

    if (((wino_t)fileInfo.nFileIndexHigh << 32 | fileInfo.nFileIndexLow) != old_inode) {
        return 2;
    }

#else
    if (buf.st_ino != old_inode) {
        return 2;
    }
#endif

    return buf.st_size < old_size ? 1 : 0;
}

void *Execute_Osquery(wm_osquery_monitor_t *osquery)
{
    char osqueryd_path[PATH_MAX];
    char config_path[PATH_MAX];
    char * strpid = NULL;
    int running_count = 0;

    // Windows agent needs the complete path to osqueryd
#ifndef WIN32
    if (!(osquery->bin_path && *osquery->bin_path)) {
        /* Osquery installation path was moved from /usr/local to /opt/osquery in Osquery v5.0.1,
        so we check both paths by default to support older and newer versions */
        if (w_is_file("/opt/osquery/bin/" OSQUERYD_BIN)) {
            snprintf(osqueryd_path, sizeof(osqueryd_path), "%s/" OSQUERYD_BIN, "/opt/osquery/bin");
        } else {
            strncpy(osqueryd_path, OSQUERYD_BIN, sizeof(osqueryd_path));
            osqueryd_path[sizeof(osqueryd_path) - 1] = '\0';
        }
    } else
#endif
    {
        snprintf(osqueryd_path, sizeof(osqueryd_path), "%s/" OSQUERYD_BIN, osquery->bin_path);
    }

    mdebug1("Launching '%s' with config file '%s'", osqueryd_path, osquery->config_path);

#ifdef WIN32
    snprintf(config_path, sizeof(config_path), "--config_path=\"%s\"", osquery->config_path);
#else
    snprintf(config_path, sizeof(config_path), "--config_path=%s", osquery->config_path);
#endif

    // We check that the osquery demon is not down, in which case we run it again.

    while (1) {
        char buffer[4096];
        time_t time_started;
        wfd_t * wfd;
        int wstatus;
        char * text;
        char * end;

        // Check that the configuration file is valid

        if (waccess(osquery->config_path, R_OK) < 0) {
            mwarn("The configuration file '%s' is not accessible: %s (%d)", osquery->config_path, strerror(errno), errno);
            sleep(600);
            continue;
        }

        // Run osquery

        if (wfd = wpopenl(osqueryd_path, W_BIND_STDERR, osqueryd_path, config_path, NULL), !wfd) {
            mwarn("Couldn't execute osquery (%s). Sleeping for 10 minutes.", osqueryd_path);
            sleep(600);
            continue;
        }

#ifdef WIN32
        wm_append_handle(wfd->pinfo.hProcess);
#else
        if (0 <= wfd->pid) {
            wm_append_sid(wfd->pid);
        }
#endif

        time_started = time(NULL);

        // Get stderr

        while (fgets(buffer, sizeof(buffer), wfd->file_out)) {
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
                } else if (end = wm_osquery_already_running(text), end) {
                    os_free(strpid);
                    strpid = end;

                    // Don't report the first time

                    if (!running_count++) {
                        continue;
                    }
                }
                else {
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

#ifdef WIN32
        wm_remove_handle(wfd->pinfo.hProcess);
#else
        if (0 <= wfd->pid) {
            wm_remove_sid(wfd->pid);
        }
#endif

        // If this point is reached, osquery exited
        int wp_closefd = wpclose(wfd);
        wstatus = WEXITSTATUS(wp_closefd);

        if (wstatus == 127) {
            // 127 means error in exec
            merror("Couldn't execute osquery (%s). Check file and permissions. Sleeping for 10 minutes.", osqueryd_path);
            sleep(600);
        } else if (strpid) {
            // Osquery is already running.
            if (running_count == 1) {
                minfo("osqueryd is already running with pid %s. Will run again in 1 minute.", strpid);
                sleep(60);
            } else {
                minfo("osqueryd is already running with pid %s. Will run again in 10 minutes.", strpid);
                sleep(600);
            }
        } else if (time(NULL) - time_started < 10) {
            // If osquery was alive less than 10 seconds, give up
            merror("Osquery exited with code %d. Closing module.", wstatus);
            active = 0;
            break;
        } else {
            mwarn("Osquery exited with code %d. Restarting.", wstatus);
        }
    }

    os_free(strpid);
    return NULL;
}

char * wm_osquery_already_running(char * text) {
    const char * PATTERNS[] = { "osqueryd (", ") is already running" , "Pidfile::Error::Busy" };
    char * begin;
    char * end;

    // Find "osqueryd (xxxx) is already running"
    if (text != NULL) {
        if (begin = strstr(text, PATTERNS[0]), begin && (end = strstr(begin += strlen(PATTERNS[0]), PATTERNS[1]), end)) {
            *end = '\0';
            os_strdup(begin, text);
            *end = *PATTERNS[1];

            // Find "Pidfile::Error::Busy"
        } else if (strstr(text, PATTERNS[2]) != NULL) {
            os_strdup("unknown", text);
        } else {
            text = NULL;
        }
    }
    return text;
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

    if (ReadConfig(CLABELS, OSSECCONF, &labels, NULL) < 0)
        goto end;

#ifdef CLIENT
    ReadConfig(CLABELS | CAGENT_CONFIG, AGENTCONFIG, &labels, NULL);
#endif

    // Do we have labels defined?

    if (!labels[0].key) {
        retval = 0;
        goto end;
    }

    // Load original osquery configuration

    if (root = json_fread(osquery->config_path, 1), !root) {
        if (errno) {
            merror("Couldn't load configuration file '%s': %s (%d)", osquery->config_path, strerror(errno), errno);
        } else {
            merror("Couldn't load configuration file '%s'. Maybe format is invalid.", osquery->config_path);
        }

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
        if (labels[i].flags.hidden) {
            continue;
        }

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

    os_strdup(TMP_CONFIG_PATH, osquery->config_path);

    // Write new configuration

    if (json_fwrite(osquery->config_path, root) < 0) {
        merror("Couldn't write JSON content into configuration '%s': %s (%d)", osquery->config_path, strerror(errno), errno);
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

    if (root = json_fread(osquery->config_path, 1), !root) {
        if (errno) {
            merror("Couldn't load configuration file '%s': %s (%d)", osquery->config_path, strerror(errno), errno);
        } else {
            merror("Couldn't load configuration file '%s'. Maybe format is invalid.", osquery->config_path);
        }

        return -1;
    }

    // Add packs to JSON

    if (packs = cJSON_GetObjectItem(root, "packs"), !packs) {
        packs = cJSON_CreateObject();
        cJSON_AddItemToObject(root, "packs", packs);
    }

    for (i = 0; osquery->packs[i]; ++i) {
        if (strcmp(osquery->packs[i]->name, "*")) {
            // Check if the file exists

            if (waccess(osquery->packs[i]->path, R_OK) < 0) {
                mwarn("Possible invalid configuration: Pack file '%s' is not accessible: %s (%d)", osquery->packs[i]->path, strerror(errno), errno);
            }
        } else if (!strchr(osquery->packs[i]->path, '*')) {
            // If name is "*" but no "*" is in the path, log a warning
            mwarn("Possible invalid configuration for pack '*' (%s): no such wildcards.", osquery->packs[i]->path);
        }

        cJSON_AddStringToObject(packs, osquery->packs[i]->name, osquery->packs[i]->path);
    }

    // Change configuration file path

    free(osquery->config_path);

    os_strdup(TMP_CONFIG_PATH, osquery->config_path);

    // Write new configuration

    if (json_fwrite(osquery->config_path, root) < 0) {
        merror("Couldn't write JSON content into configuration '%s': %s (%d)", osquery->config_path, strerror(errno), errno);
        retval = -1;
    }

    cJSON_Delete(root);
    return retval;
}

#ifdef WIN32
DWORD WINAPI wm_osquery_monitor_main(void *arg) {
    wm_osquery_monitor_t *osquery = (wm_osquery_monitor_t *)arg;
#else
void *wm_osquery_monitor_main(wm_osquery_monitor_t *osquery) {
#endif
    pthread_t tlauncher = 0;
    pthread_t treader = 0;

    if (osquery->disable) {
        minfo("Module disabled. Exiting...");
#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
    }

    minfo("Module started.");
    osquery->msg_delay = 1000000 / wm_max_eps;

#ifndef WIN32
    // Connect to queue

    osquery->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
    if (osquery->queue_fd < 0) {
        mterror(WM_OSQUERYMONITOR_LOGTAG, "Can't connect to queue. Closing module.");
        return NULL;
    }

#endif

    if( pthread_create(&treader, NULL, (void *)&Read_Log, osquery) != 0){
        merror("Error while creating Read_Log thread.");
#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
    }

    if (osquery->run_daemon) {
        // Handle configuration

        if (wm_osquery_packs(osquery) < 0 || wm_osquery_decorators(osquery) < 0) {
#ifdef WIN32
            return 0;
#else
            return NULL;
#endif
        }

        if( pthread_create(&tlauncher, NULL, (void *)&Execute_Osquery, osquery) != 0){
            merror("Error while creating Execute_Osquery thread.");
#ifdef WIN32
            return 0;
#else
            return NULL;
#endif
        }
        pthread_join(tlauncher, NULL);
    } else {
        minfo("run_daemon disabled, finding detached osquery process results.");
    }

    pthread_join(treader, NULL);

    minfo("Closing module.");
#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

void wm_osquery_monitor_destroy(wm_osquery_monitor_t *osquery_monitor) {
    int i;

    if (osquery_monitor)
    {
        free(osquery_monitor->bin_path);
        free(osquery_monitor->log_path);
        free(osquery_monitor->config_path);

        for (i = 0; osquery_monitor->packs[i]; ++i) {
            free(osquery_monitor->packs[i]->name);
            free(osquery_monitor->packs[i]->path);
            free(osquery_monitor->packs[i]);
        }

        free(osquery_monitor->packs);
        free(osquery_monitor);
    }
}

// Get read data
cJSON *wm_osquery_dump(const wm_osquery_monitor_t *osquery_monitor) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_osq = cJSON_CreateObject();
    unsigned int i;

    if (osquery_monitor->disable) cJSON_AddStringToObject(wm_osq,"disabled","yes"); else cJSON_AddStringToObject(wm_osq,"disabled","no");
    if (osquery_monitor->run_daemon) cJSON_AddStringToObject(wm_osq,"run_daemon","yes"); else cJSON_AddStringToObject(wm_osq,"run_daemon","no");
    if (osquery_monitor->add_labels) cJSON_AddStringToObject(wm_osq,"add_labels","yes"); else cJSON_AddStringToObject(wm_osq,"add_labels","no");
    if (osquery_monitor->bin_path) cJSON_AddStringToObject(wm_osq,"bin_path",osquery_monitor->bin_path);
    if (osquery_monitor->log_path) cJSON_AddStringToObject(wm_osq,"log_path",osquery_monitor->log_path);
    if (osquery_monitor->config_path) cJSON_AddStringToObject(wm_osq,"config_path",osquery_monitor->config_path);

    if (osquery_monitor->packs && *osquery_monitor->packs) {
        cJSON *packs = cJSON_CreateArray();
        for (i=0;osquery_monitor->packs[i] && osquery_monitor->packs[i]->name;i++) {
            cJSON *pack = cJSON_CreateObject();
            cJSON_AddStringToObject(pack,"name",osquery_monitor->packs[i]->name);
            cJSON_AddStringToObject(pack,"path",osquery_monitor->packs[i]->path);
            cJSON_AddItemToArray(packs, pack);
        }
        cJSON_AddItemToObject(wm_osq,"packs",packs);
    }

    cJSON_AddItemToObject(root,"osquery",wm_osq);

    return root;
}
