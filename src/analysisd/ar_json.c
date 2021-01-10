/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
*/

#include "config.h"
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
 * @param[out] temp_msg Message in JSON format.
 * @return int, 0 on success or 1 on failure.
 */
int getActiveResponseInJSON(const Eventinfo *lf, const active_response *ar, char *extra_args, char *temp_msg)
{
    cJSON *_object = NULL;
    cJSON *_array = NULL;
    cJSON *json_alert = NULL;
    char *node_name = NULL;
    char *alert_string = NULL;
    char *msg = NULL;

    cJSON *message = cJSON_CreateObject();
    if (message == NULL) {
        merror("Failed to create active response JSON");
        return OS_INVALID;
    }

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

    // extra_args will be split by " " and "\"
    if (extra_args) {
        char str[OS_SIZE_1024];
        char * pch;
        strcpy(str, extra_args);
        pch = strtok (str," ");
        while (pch != NULL) {
            if(pch[0] != '\\') {
                cJSON_AddItemToArray(_array, cJSON_CreateString(pch));
            }
            pch = strtok (NULL, " ");
        }
    }

    // We use the JSON created for the alert and embed it in the message.
    alert_string = Eventinfo_to_jsonstr(lf, false);
    json_alert = cJSON_Parse(alert_string);
    os_free(alert_string);
    if (json_alert == NULL) {
        merror("Cannot parse alert JSON");
        cJSON_Delete(message);
        return OS_INVALID;
    }
    cJSON_AddItemToObject(_object, "alert", json_alert);

    msg = cJSON_PrintUnformatted(message);
    strcpy(temp_msg, msg);
    os_free(msg);

    // Clean up Memory
    cJSON_Delete(message);

    return OS_SUCCESS;
}

/**
 * @return char*, remember to free memory after return.
 */
char *get_node_name()
{
    char* node_name = NULL;
    OS_XML xml;

    const char *(xml_node[]) = {"ossec_config", "cluster", "node_name", NULL};
    if (OS_ReadXML(DEFAULTCPATH, &xml) >= 0) {
        node_name = OS_GetOneContentforElement(&xml, xml_node);
    }
    OS_ClearXML(&xml);
    return node_name;
}
