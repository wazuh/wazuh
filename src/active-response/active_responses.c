/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

void write_debug_file (const char *ar_name, const char *msg) {
    char path[PATH_MAX];
    char *timestamp = w_get_timestamp(time(NULL));

#ifndef WIN32
    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOG_FILE);
#else
    snprintf(path, PATH_MAX, "%s", LOG_FILE);
#endif

    FILE *ar_log_file = fopen(path, "a");

    fprintf(ar_log_file, "%s %s: %s\n", timestamp, ar_name, msg);
    fclose(ar_log_file);
    os_free(timestamp);
}

cJSON* get_json_from_input (const char *input) {
    cJSON *input_json = NULL;
    cJSON *origin_json = NULL;
    cJSON *version_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *extra_args = NULL;
    cJSON *alert_json = NULL;
    const char *json_err;

    // Parsing input
    if (input_json = cJSON_ParseWithOpts(input, &json_err, 0), !input_json) {
        return NULL;
    }

    // Detect version
    if (version_json = cJSON_GetObjectItem(input_json, "version"), !version_json || (version_json->type != cJSON_Number)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect origin
    if (origin_json = cJSON_GetObjectItem(input_json, "origin"), !origin_json || (origin_json->type != cJSON_Object)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect command
    if (command_json = cJSON_GetObjectItem(input_json, "command"), !command_json || (command_json->type != cJSON_String)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input_json, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect extra_args
    if (extra_args = cJSON_GetObjectItem(parameters_json, "extra_args"), !extra_args || (extra_args->type != cJSON_Array)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect program
    if (alert_json = cJSON_GetObjectItem(parameters_json, "program"), !alert_json || (alert_json->type != cJSON_String)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    return input_json;
}

char* get_command (cJSON *input) {
    // Detect command
    cJSON *command_json = cJSON_GetObjectItem(input, "command");
    if (command_json && (command_json->type == cJSON_String)) {
        return command_json->valuestring;
    }

    return NULL;
}

char* get_username_from_json (cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *username_json = NULL;

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect data
    if (data_json = cJSON_GetObjectItem(alert_json, "data"), !data_json || (data_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect username
    username_json = cJSON_GetObjectItem(data_json, "dstuser");
    if (username_json && (username_json->type == cJSON_String)) {
        return username_json->valuestring;
    }

    return NULL;
}

char* get_srcip_from_json (cJSON *input) {
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *srcip_json = NULL;

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect data
    if (data_json = cJSON_GetObjectItem(alert_json, "data"), !data_json || (data_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect srcip
    srcip_json = cJSON_GetObjectItem(data_json, "srcip");
    if (srcip_json && (srcip_json->type == cJSON_String)) {
        return srcip_json->valuestring;
    }

    return NULL;
}

int get_ip_version (char * ip) {
    struct addrinfo hint, *res = NULL;
    int ret;

    memset(&hint, '\0', sizeof hint);

    hint.ai_family = PF_UNSPEC;
    hint.ai_flags = AI_NUMERICHOST;

    ret = getaddrinfo(ip, NULL, &hint, &res);
    if (ret) {
        freeaddrinfo(res);
        return OS_INVALID;
    }
    if (res->ai_family == AF_INET) {
        freeaddrinfo(res);
        return 4;
    } else if (res->ai_family == AF_INET6) {
        freeaddrinfo(res);
        return 6;
    }

    freeaddrinfo(res);
    return OS_INVALID;
}
