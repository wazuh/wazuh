#include "active_responses.h"
#include "shared.h"


void write_debug_file (const char *ar_name, const char *msg) {
    char path[PATH_MAX];
    char *timestamp = w_get_timestamp(time(NULL));

    snprintf(path, PATH_MAX, "%s%s", isChroot() ? "" : DEFAULTDIR, LOG_FILE);
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

    // Parsing Input
    if (input_json = cJSON_ParseWithOpts(input, &json_err, 0), !input_json) {
        return NULL;
    }

    // Detect version
    if (version_json = cJSON_GetObjectItem(input_json, "version"), !version_json || (version_json->type != cJSON_String)) {
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

    // Detect Extra_args
    if (extra_args = cJSON_GetObjectItem(parameters_json, "extra_args"), !extra_args || (extra_args->type != cJSON_Array)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    // Detect Alert
    if (alert_json = cJSON_GetObjectItem(parameters_json, "alert"), !alert_json || (alert_json->type != cJSON_Object)) {
        cJSON_Delete(input_json);
        return NULL;
    }

    return input_json;
}

char* get_command (cJSON *input) {
    char *command = NULL;

    // Detect command
    cJSON *command_json = cJSON_GetObjectItem(input, "command");
    if (command_json && (command_json->type == cJSON_String)) {
        os_strdup(command_json->valuestring, command);
    }

    return command;
}

char* get_username_from_json (cJSON *input) {
    char *username = NULL;
    cJSON *parameters_json = NULL;
    cJSON *alert_json = NULL;
    cJSON *data_json = NULL;
    cJSON *username_json = NULL;

    // Detect parameters
    if (parameters_json = cJSON_GetObjectItem(input, "parameters"), !parameters_json || (parameters_json->type != cJSON_Object)) {
        return NULL;
    }

    // Detect Alert
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
        os_strdup(username_json->valuestring, username);
    }

    return username;
}
