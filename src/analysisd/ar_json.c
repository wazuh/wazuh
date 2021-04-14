/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "config.h"
#include "shared.h"
#include "format/to_json.h"

#define VERSION 1
#ifndef ARGV0
#define ARGV0 "wazuh-analysisd"
#endif

/**
 * @brief Build the JSON message
 *
 * @param[in] lf Event information.
 * @param[in] ar Active Response information.
 * @param[in] extra_args Extra arguments escaped.
 * @param[out] temp_msg Message in JSON format.
 */
void getActiveResponseInJSON(const Eventinfo *lf, const active_response *ar, char *extra_args, char *temp_msg)
{
    cJSON *_object = NULL;
    cJSON *_array = NULL;
    cJSON *json_alert = NULL;
    char *node_name = NULL;
    char *alert_string = NULL;
    char *msg = NULL;

    cJSON *message = cJSON_CreateObject();

    cJSON_AddNumberToObject(message, "version", VERSION);

    _object = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "origin", _object);

    node_name = get_node_name();
    cJSON_AddStringToObject(_object, "name", node_name ? node_name : "");
    os_free(node_name);

    cJSON_AddStringToObject(_object, "module", ARGV0);
    cJSON_AddStringToObject(message, "command", ar->name);

    _object = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "parameters", _object);

    _array = cJSON_CreateArray();
    cJSON_AddItemToObject(_object, "extra_args", _array);

    // extra_args will be split by " "
    if (extra_args) {
        char str[OS_SIZE_2048];
        char *pch;
        strncpy(str, extra_args, OS_SIZE_2048 - 1);
        pch = strtok(str, " ");
        while (pch != NULL) {
            cJSON_AddItemToArray(_array, cJSON_CreateString(pch));
            pch = strtok(NULL, " ");
        }
    }

    // We use the JSON created for the alert and embed it in the message.
    alert_string = Eventinfo_to_jsonstr(lf, false);
    json_alert = cJSON_Parse(alert_string);
    os_free(alert_string);

    cJSON_AddItemToObject(_object, "alert", json_alert);

    msg = cJSON_PrintUnformatted(message);
    strcpy(temp_msg, msg);
    os_free(msg);

    // Clean up Memory
    cJSON_Delete(message);
}
