/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * May 27, 2022.
 *
 * This program is os_free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#include "wdb.h"
#include "wdb_state.h"

typedef enum _error_codes {
    ERROR_OK = 0,
    ERROR_INVALID_INPUT,
    ERROR_EMPTY_COMMAND,
    ERROR_UNRECOGNIZED_COMMAND,
    ERROR_EMPTY_PARAMATERS,
    ERROR_EMPTY_SECTION,
    ERROR_UNRECOGNIZED_SECTION
} error_codes;

const char * error_messages[] = {
    [ERROR_OK] = "ok",
    [ERROR_INVALID_INPUT] = "Invalid JSON input",
    [ERROR_EMPTY_COMMAND] = "Empty command",
    [ERROR_UNRECOGNIZED_COMMAND] = "Unrecognized command",
    [ERROR_EMPTY_PARAMATERS] = "Empty parameters",
    [ERROR_EMPTY_SECTION] = "Empty section",
    [ERROR_UNRECOGNIZED_SECTION] = "Unrecognized or not configured section"
};

/**
 * Format message into the response format
 * @param error_code code error
 * @param message string message of the error
 * @param data_json data to return from request
 * @return string meessage with the response format
 * */
STATIC char* wdbcom_output_builder(int error_code, const char* message, cJSON* data_json);

/**
 * @brief Process the message received to send the configuration requested
 * @param section contains the name of configuration requested
 * @return JSON string
 */
cJSON* wdbcom_getconfig(char* section);


STATIC char* wdbcom_output_builder(int error_code, const char* message, cJSON* data_json) {
    cJSON* root = cJSON_CreateObject();

    cJSON_AddNumberToObject(root, "error", error_code);
    cJSON_AddStringToObject(root, "message", message);
    cJSON_AddItemToObject(root, "data", data_json ? data_json : cJSON_CreateObject());

    char *msg_string = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    return msg_string;
}

void wdbcom_dispatch(char* request, char* output) {
    cJSON *request_json = NULL;
    cJSON *command_json = NULL;
    cJSON *parameters_json = NULL;
    cJSON *section_json = NULL;
    cJSON* config_json = NULL;
    const char *json_err;
    char * output_builder;

    if (request_json = cJSON_ParseWithOpts(request, &json_err, 0), !request_json) {
        output_builder = wdbcom_output_builder(ERROR_INVALID_INPUT, error_messages[ERROR_INVALID_INPUT], NULL);
        snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
        os_free(output_builder);
        return;
    }

    if (command_json = cJSON_GetObjectItem(request_json, "command"), cJSON_IsString(command_json)) {
        if (strcmp(command_json->valuestring, "getstats") == 0) {
            output_builder = wdbcom_output_builder(ERROR_OK, error_messages[ERROR_OK], wdb_create_state_json());
            snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
        } else if (strcmp(command_json->valuestring, "getconfig") == 0) {
            if (parameters_json = cJSON_GetObjectItem(request_json, "parameters"), cJSON_IsObject(parameters_json)) {
                if (section_json = cJSON_GetObjectItem(parameters_json, "section"), cJSON_IsString(section_json)) {
                    if (config_json = wdbcom_getconfig(section_json->valuestring), config_json) {
                        output_builder = wdbcom_output_builder(ERROR_OK, error_messages[ERROR_OK], config_json);
                        snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
                    } else {
                        output_builder = wdbcom_output_builder(ERROR_UNRECOGNIZED_SECTION, error_messages[ERROR_UNRECOGNIZED_SECTION], NULL);
                        snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
                    }
                } else {
                    output_builder = wdbcom_output_builder(ERROR_EMPTY_SECTION, error_messages[ERROR_EMPTY_SECTION], NULL);
                    snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
                }
            } else {
                output_builder = wdbcom_output_builder(ERROR_EMPTY_PARAMATERS, error_messages[ERROR_EMPTY_PARAMATERS], NULL);
                snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
            }
        } else {
            output_builder = wdbcom_output_builder(ERROR_UNRECOGNIZED_COMMAND, error_messages[ERROR_UNRECOGNIZED_COMMAND], NULL);
            snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
        }
    } else {
        output_builder = wdbcom_output_builder(ERROR_EMPTY_COMMAND, error_messages[ERROR_EMPTY_COMMAND], NULL);
        snprintf(output, OS_MAXSTR + 1, "%s", output_builder);
    }

    os_free(output_builder);
    cJSON_Delete(request_json);
}

cJSON* wdbcom_getconfig(char* section) {
    if (strcmp(section, "internal") == 0) {
        return wdb_get_internal_config();
    } else if (strcmp(section, "wdb") == 0) {
        return wdb_get_config();
    }
    return NULL;
}
