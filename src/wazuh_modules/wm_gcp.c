/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "os_net/os_net.h"
#include <sys/stat.h>
#include "os_crypto/sha256/sha256_op.h"
#include "shared.h"
#include "wm_exec.h"

#ifdef WAZUH_UNIT_TESTING
/* Remove static qualifier when testing */
#define static
#endif

/**
 * @brief Run module function for Google Cloud Pub/Sub
 * @param data Module configuration structure
 */
static void wm_gcp_pubsub_run(const wm_gcp_pubsub *data);            // Running python script

/**
 * @brief Dump configuration structure in JSON for Google Cloud Pub/Sub
 * @param gcp_config Module configuration structure
 * @return JSON structure with module configuration
 */
cJSON *wm_gcp_pubsub_dump(const wm_gcp_pubsub *gcp_config);          // Read config
#ifdef WIN32
/**
 * @brief Main function for Google Cloud Pub/Sub
 * @param gcp_config Module configuration structure
 */
static DWORD WINAPI wm_gcp_pubsub_main(void *arg);                     // Module main function. It won't return

/**
 * @brief Main function for Google Cloud bucket
 * @param gcp_config Module configuration structure
 */
static DWORD WINAPI wm_gcp_bucket_main(void *arg);                     // Module main function. It won't return
#else
/**
 * @brief Main function for Google Cloud Pub/Sub
 * @param gcp_config Module configuration structure
 */
static void* wm_gcp_pubsub_main(wm_gcp_pubsub *gcp_config);          // Module main function. It won't return

/**
 * @brief Main function for Google Cloud bucket
 * @param gcp_config Module configuration structure
 */
static void* wm_gcp_bucket_main(wm_gcp_bucket_base *gcp_config);          // Module main function. It won't return
#endif

/**
 * @brief Free configuration structure for Google Cloud Pub/Sub
 * @param gcp_config Module configuration structure
 */
static void wm_gcp_pubsub_destroy(wm_gcp_pubsub *gcp_config);        // Destroy data

/**
 * @brief Free configuration structure for Google Cloud bucket
 * @param gcp_config Module configuration structure
 */
static void wm_gcp_bucket_destroy(wm_gcp_bucket_base *gcp_config);        // Destroy data

/**
 * @brief Run module function for Google Cloud bucket
 * @param exec_bucket Bucket configuration structure
 */
static void wm_gcp_bucket_run(wm_gcp_bucket *exec_bucket);            // Running python script

/**
 * @brief Dump configuration structure in JSON for Google Cloud bucket
 * @param gcp_config Module configuration structure
 * @return JSON structure with module configuration
 */
cJSON *wm_gcp_bucket_dump(const wm_gcp_bucket_base *gcp_config);          // Read config

/**
 * @brief Parse the output of the GCP script and prints it depending on the debug
 *        level stated by the script
 * @param output Output returned by the call to the script
 * @param tag Tag that should be used when printing the messages
 */
static void wm_gcp_parse_output(char *output, char *tag);


/* Context definition */

const wm_context WM_GCP_PUBSUB_CONTEXT = {
    .name = GCP_PUBSUB_WM_NAME,
    .start = (wm_routine)wm_gcp_pubsub_main,
    .destroy = (void(*)(void *))wm_gcp_pubsub_destroy,
    .dump = (cJSON * (*)(const void *))wm_gcp_pubsub_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

const wm_context WM_GCP_BUCKET_CONTEXT = {
    .name = GCP_BUCKET_WM_NAME,
    .start = (wm_routine)wm_gcp_bucket_main,
    .destroy = (void(*)(void *))wm_gcp_bucket_destroy,
    .dump = (cJSON * (*)(const void *))wm_gcp_bucket_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

#ifdef WAZUH_UNIT_TESTING
// Replace pthread_exit for testing purposes
#define pthread_exit(a) return a
#endif
// Module main function. It won't return
#ifdef WIN32
DWORD WINAPI wm_gcp_pubsub_main(void *arg) {
    wm_gcp_pubsub *data = (wm_gcp_pubsub *)arg;
#else
void* wm_gcp_pubsub_main(wm_gcp_pubsub *data) {
#endif
    char * timestamp = NULL;
    // If module is disabled, exit
    if (data->enabled) {
        mtinfo(WM_GCP_PUBSUB_LOGTAG, "Module started.");
    } else {
        mtinfo(WM_GCP_PUBSUB_LOGTAG, "Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(data->scan_config), WM_GCP_PUBSUB_LOGTAG, data->pull_on_start);

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(data->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_GCP_PUBSUB_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }
        mtdebug1(WM_GCP_PUBSUB_LOGTAG, "Starting fetching of logs.");

        wm_gcp_pubsub_run(data);

        mtdebug1(WM_GCP_PUBSUB_LOGTAG, "Fetching logs finished.");
    } while (FOREVER());

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

#ifdef WIN32
DWORD WINAPI wm_gcp_bucket_main(void *arg) {
    wm_gcp_bucket_base *data = (wm_gcp_bucket_base *)arg;
#else
void* wm_gcp_bucket_main(wm_gcp_bucket_base *data) {
#endif
    char * timestamp = NULL;
    // If module is disabled, exit
    if (data->enabled) {
        mtinfo(WM_GCP_BUCKET_LOGTAG, "Module started.");
    } else {
        mtinfo(WM_GCP_BUCKET_LOGTAG, "Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    wm_gcp_bucket *cur_bucket;
    char *log_info;
    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(data->scan_config), WM_GCP_BUCKET_LOGTAG, data->run_on_start);

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(data->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_GCP_BUCKET_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }
        mtdebug1(WM_GCP_BUCKET_LOGTAG, "Starting fetching of logs.");

        for (cur_bucket = data->buckets; cur_bucket; cur_bucket = cur_bucket->next) {

            log_info = NULL;

            wm_strcat(&log_info, "Executing Bucket Analysis: (Bucket:", '\0');
            if (cur_bucket->bucket) {
                wm_strcat(&log_info, cur_bucket->bucket, ' ');
            }
            else {
                wm_strcat(&log_info, "unknown_bucket", ' ');
            }


            if (cur_bucket->prefix) {
                wm_strcat(&log_info, ", Path:", '\0');
                wm_strcat(&log_info, cur_bucket->prefix, ' ');
            }

            if (cur_bucket->type) {
                wm_strcat(&log_info, ", Type:", '\0');
                wm_strcat(&log_info, cur_bucket->type, ' ');
            }

            if (cur_bucket->credentials_file) {
                wm_strcat(&log_info, ", Credentials file:", '\0');
                wm_strcat(&log_info, cur_bucket->credentials_file, ' ');
            }

            wm_strcat(&log_info, ")", '\0');

            mtinfo(WM_GCP_BUCKET_LOGTAG, "%s", log_info);
            wm_gcp_bucket_run(cur_bucket);
            free(log_info);
        }

        mtdebug1(WM_GCP_BUCKET_LOGTAG, "Fetching logs finished.");
    } while (FOREVER());

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
}

#ifdef WAZUH_UNIT_TESTING
/* Replace pthread_exit for testing purposes */
#undef pthread_exit
#define pthread_exit(a) return

__attribute__((weak))
#endif
void wm_gcp_pubsub_run(const wm_gcp_pubsub *data) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Create arguments
    mtdebug2(WM_GCP_PUBSUB_LOGTAG, "Create argument list");

    char * script = NULL;
    os_calloc(PATH_MAX, sizeof(char), script);

    snprintf(script, PATH_MAX, "%s", WM_GCP_SCRIPT_PATH);

    wm_strcat(&command, script, '\0');
    os_free(script);

    wm_strcat(&command, "--integration_type pubsub", ' ');

    if (data->project_id) {
        wm_strcat(&command, "--project", ' ');
        wm_strcat(&command, data->project_id, ' ');
    }
    if (data->subscription_name) {
        wm_strcat(&command, "--subscription_id", ' ');
        wm_strcat(&command, data->subscription_name, ' ');
    }
    if (data->credentials_file) {
        wm_strcat(&command, "--credentials_file", ' ');
        wm_strcat(&command, data->credentials_file, ' ');
    }

    if (data->max_messages) {
        char *int_to_string;
        os_malloc(OS_SIZE_1024, int_to_string);
        sprintf(int_to_string, "%d", data->max_messages);
        wm_strcat(&command, "--max_messages", ' ');
        wm_strcat(&command, int_to_string, ' ');
        os_free(int_to_string);
    }
    if (data->num_threads) {
        char *int_to_string;
        os_malloc(OS_SIZE_1024, int_to_string);
        sprintf(int_to_string, "%d", data->num_threads);
        wm_strcat(&command, "--num_threads", ' ');
        wm_strcat(&command, int_to_string, ' ');
        os_free(int_to_string);
    }

    if (isDebug()){
        char *int_to_string;
        os_malloc(OS_SIZE_1024, int_to_string);
        sprintf(int_to_string, "%d", isDebug());
        wm_strcat(&command, "--log_level", ' ');
        wm_strcat(&command, int_to_string, ' ');
        os_free(int_to_string);
    }

    // Execute

    mtdebug1(WM_GCP_PUBSUB_LOGTAG, "Launching command: %s", command);

    const int wm_exec_ret_code = wm_exec(command, &output, &status, 0, NULL);

    os_free(command);

    if (wm_exec_ret_code != 0){
        mterror(WM_GCP_PUBSUB_LOGTAG, "Internal error. Exiting...");
        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    } else if (status > 0) {
        mtwarn(WM_GCP_PUBSUB_LOGTAG, "Command returned exit code %d", status);
    }

    wm_gcp_parse_output(output, WM_GCP_PUBSUB_LOGTAG);
    os_free(output);
}

static void wm_gcp_parse_output(char *output, char *tag){
    char *line;
    char * parsing_output = output;
    int debug_level = isDebug();

    for (line = strstr(parsing_output, WM_GCP_LOGGING_TOKEN); line; line = strstr(parsing_output, WM_GCP_LOGGING_TOKEN)) {
        char * tokenized_line;
        os_calloc(WM_STRING_MAX, sizeof(char), tokenized_line);
        char * next_lines;

        line += strlen(WM_GCP_LOGGING_TOKEN);
        next_lines = strstr(line, WM_GCP_LOGGING_TOKEN);

        int next_lines_chars = next_lines == NULL ? 0 : strlen(next_lines);

        // 1 is added because it's mandatory to consider the null byte
        int cp_length = 1 + strlen(line) - next_lines_chars > WM_STRING_MAX ? WM_STRING_MAX : 1 + strlen(line) - next_lines_chars;
        snprintf(tokenized_line, cp_length, "%s", line);
        if (tokenized_line[cp_length - 2] == '\n') tokenized_line[cp_length - 2] = '\0';

        char *p_line = NULL;

        if (debug_level >= 2) {
            if ((p_line = strstr(tokenized_line, "- DEBUG - "))) {
                p_line += 10;
                mtdebug1(tag, "%s", p_line);
            }
        }
        if (debug_level >= 1) {
            if ((p_line = strstr(tokenized_line, "- INFO - "))) {
                p_line += 9;
                mtinfo(tag, "%s", p_line);
            }
        }
        if (debug_level >= 0) {
            if ((p_line = strstr(tokenized_line, "- CRITICAL - "))) {
                p_line += 13;
                mterror(tag, "%s", p_line);
            }
            if ((p_line = strstr(tokenized_line, "- ERROR - "))) {
                p_line += 10;
                mterror(tag, "%s", p_line);
            }
            if ((p_line = strstr(tokenized_line, "- WARNING - "))) {
                p_line += 12;
                mtwarn(tag, "%s", p_line);
            }
        }

        parsing_output += cp_length + strlen(WM_GCP_LOGGING_TOKEN) - 1;
        os_free(tokenized_line);
    }
}

void wm_gcp_bucket_run(wm_gcp_bucket *exec_bucket) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Create arguments
    mtdebug2(WM_GCP_BUCKET_LOGTAG, "Create argument list");

    char * script = NULL;
    os_calloc(PATH_MAX, sizeof(char), script);

    snprintf(script, PATH_MAX, "%s", WM_GCP_SCRIPT_PATH);

    wm_strcat(&command, script, '\0');
    os_free(script);

    wm_strcat(&command, "--integration_type", ' ');
    wm_strcat(&command, exec_bucket->type, ' ');

    wm_strcat(&command, "--bucket_name", ' ');
    wm_strcat(&command, exec_bucket->bucket, ' ');

    if (exec_bucket->credentials_file) {
        wm_strcat(&command, "--credentials_file", ' ');
        wm_strcat(&command, exec_bucket->credentials_file, ' ');
    }
    if (exec_bucket->prefix) {
        wm_strcat(&command, "--prefix", ' ');
        wm_strcat(&command, exec_bucket->prefix, ' ');
    }
    if (exec_bucket->only_logs_after) {
        wm_strcat(&command, "--only_logs_after", ' ');
        wm_strcat(&command, exec_bucket->only_logs_after, ' ');
    }
    if (exec_bucket->remove_from_bucket) {
        wm_strcat(&command, "--remove", ' ');
    }

    if (isDebug()){
        char *int_to_string;
        os_malloc(OS_SIZE_1024, int_to_string);
        sprintf(int_to_string, "%d", isDebug());
        wm_strcat(&command, "--log_level", ' ');
        wm_strcat(&command, int_to_string, ' ');
        os_free(int_to_string);
    }

    // Execute

    mtdebug1(WM_GCP_BUCKET_LOGTAG, "Launching command: %s", command);

    const int wm_exec_ret_code = wm_exec(command, &output, &status, 0, NULL);

    os_free(command);

    if (wm_exec_ret_code != 0){
        mterror(WM_GCP_BUCKET_LOGTAG, "Internal error. Exiting...");
        if (wm_exec_ret_code > 0) {
            os_free(output);
        }
        pthread_exit(NULL);
    } else if (status > 0) {
        mtwarn(WM_GCP_BUCKET_LOGTAG, "Command returned exit code %d", status);
    }

    wm_gcp_parse_output(output, WM_GCP_BUCKET_LOGTAG);
    os_free(output);
}

void wm_gcp_pubsub_destroy(wm_gcp_pubsub * data) {
    if (data->project_id) os_free(data->project_id);
    if (data->subscription_name) os_free(data->subscription_name);
    if (data->credentials_file) os_free(data->credentials_file);
    os_free(data);
}

void wm_gcp_bucket_destroy(wm_gcp_bucket_base * data) {
    wm_gcp_bucket *cur_bucket;
    wm_gcp_bucket *next_bucket = data->buckets;
    while(next_bucket){
        cur_bucket = next_bucket;
        next_bucket = next_bucket->next;
        if (cur_bucket->bucket) os_free(cur_bucket->bucket);
        if (cur_bucket->type) os_free(cur_bucket->type);
        if (cur_bucket->credentials_file) os_free(cur_bucket->credentials_file);
        if (cur_bucket->prefix) os_free(cur_bucket->prefix);
        if (cur_bucket->only_logs_after) os_free(cur_bucket->only_logs_after);
        os_free(cur_bucket);
    }
    os_free(data);
}

cJSON *wm_gcp_pubsub_dump(const wm_gcp_pubsub *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    sched_scan_dump(&(data->scan_config), wm_wd);

    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "pull_on_start", data->pull_on_start ? "yes" : "no");
    if (data->max_messages) cJSON_AddNumberToObject(wm_wd, "max_messages", data->max_messages);
    if (data->num_threads) cJSON_AddNumberToObject(wm_wd, "num_threads", data->num_threads);
    if (data->project_id) cJSON_AddStringToObject(wm_wd, "project_id", data->project_id);
    if (data->subscription_name) cJSON_AddStringToObject(wm_wd, "subscription_name", data->subscription_name);
    if (data->credentials_file) cJSON_AddStringToObject(wm_wd, "credentials_file", data->credentials_file);

    int debug_level = isDebug();

    if (debug_level >= 2) cJSON_AddStringToObject(wm_wd, "logging", "debug");
    if (debug_level == 1) cJSON_AddStringToObject(wm_wd, "logging", "info");
    if (debug_level == 0) cJSON_AddStringToObject(wm_wd, "logging", "warning");

    cJSON_AddItemToObject(root, "gcp-pubsub", wm_wd);

    return root;
}

cJSON *wm_gcp_bucket_dump(const wm_gcp_bucket_base *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();

    sched_scan_dump(&(data->scan_config), wm_wd);
    cJSON_AddStringToObject(wm_wd, "enabled", data->enabled ? "yes" : "no");
    cJSON_AddStringToObject(wm_wd, "run_on_start", data->run_on_start ? "yes" : "no");

    if (data->buckets) {
        wm_gcp_bucket *cur_bucket;
        cJSON *arr_buckets = cJSON_CreateArray();
        for (cur_bucket = data->buckets; cur_bucket; cur_bucket = cur_bucket->next) {
            cJSON *buck = cJSON_CreateObject();
            if (cur_bucket->bucket) cJSON_AddStringToObject(buck, "bucket", cur_bucket->bucket);
            if (cur_bucket->type) cJSON_AddStringToObject(buck, "type", cur_bucket->type);
            if (cur_bucket->credentials_file) cJSON_AddStringToObject(buck, "credentials_file", cur_bucket->credentials_file);
            if (cur_bucket->prefix) cJSON_AddStringToObject(buck, "prefix", cur_bucket->prefix);
            if (cur_bucket->only_logs_after) cJSON_AddStringToObject(buck, "only_logs_after", cur_bucket->only_logs_after);
            if (cur_bucket->remove_from_bucket) cJSON_AddNumberToObject(buck, "remove_from_bucket", cur_bucket->remove_from_bucket);
            cJSON_AddItemToArray(arr_buckets, buck);
        }
        if (cJSON_GetArraySize(arr_buckets) > 0) {
            cJSON_AddItemToObject(wm_wd, "buckets", arr_buckets);
        } else {
            cJSON_free(arr_buckets);
        }
    }

    int debug_level = isDebug();

    if (debug_level >= 2) cJSON_AddStringToObject(wm_wd, "logging", "debug");
    if (debug_level == 1) cJSON_AddStringToObject(wm_wd, "logging", "info");
    if (debug_level == 0) cJSON_AddStringToObject(wm_wd, "logging", "warning");

    cJSON_AddItemToObject(root, "gcp-bucket", wm_wd);

    return root;
}
