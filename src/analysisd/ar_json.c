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

#define VERSION "1.0"
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
int getActiveResponseInJSON(const Eventinfo *lf, const active_response *ar, char *temp_msg)
{
    cJSON *_object = NULL;
    cJSON *_array = NULL;
    cJSON *json_alert = NULL;

    cJSON *message = cJSON_CreateObject();
    if (message == NULL){
        merror("Failed to create active response JSON");
        return 1;
    }

    cJSON_AddStringToObject(message, "version", VERSION);
    
    _object = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "origin", _object);
    cJSON_AddStringToObject(_object, "name", ar->name);
    cJSON_AddStringToObject(_object, "module", ARGV0);

    cJSON_AddStringToObject(message, "command", ar->command);

    _object = cJSON_CreateObject();
    cJSON_AddItemToObject(message, "parameters", _object);
    
    _array = cJSON_CreateArray();
    cJSON_AddItemToObject(_object, "extra_args", _array);

    // ar->ar_cmd->extra_args will be split by " ;,"
    if (ar->ar_cmd->extra_args)
    {
        char str[OS_SIZE_1024];
        char * pch;
        strcpy(str, ar->ar_cmd->extra_args);
        pch = strtok (str," ;,");
        while (pch != NULL)
        {
            cJSON_AddItemToArray(_array, cJSON_CreateString(pch));
            pch = strtok (NULL, " ;,");
        }
    }
    
    // We use the JSON created for the alert and embed it in the message.
    json_alert = cJSON_Parse(Eventinfo_to_jsonstr(lf, false));
    if (json_alert == NULL) {
        merror("Cannot parse alert JSON");
        cJSON_Delete(message);
        return 1;
    }
    cJSON_AddItemToObject(_object, "alert", json_alert);

    strcpy(temp_msg, cJSON_PrintUnformatted(message));
    cJSON_Delete(message);

    return 0;
}
