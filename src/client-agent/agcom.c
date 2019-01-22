/* Remote request listener
 * Copyright (C) 2015-2019, Wazuh Inc.
 * Mar 12, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "agentd.h"
#include "os_net/os_net.h"
#include "wazuh_modules/wmodules.h"


size_t agcom_dispatch(char * command, char ** output){

    char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            mdebug1("AGCOM getconfig needs arguments.");
            *output = strdup("err AGCOM getconfig needs arguments");
            return strlen(*output);
        }
        return agcom_getconfig(rcv_args, output);

    } else {
        mdebug1("AGCOM Unrecognized command '%s'.", rcv_comm);
        *output = strdup("err Unrecognized command");
        return strlen(*output);
    }
}

size_t agcom_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "client") == 0){
        if (cfg = getClientConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "buffer") == 0){
        if (cfg = getBufferConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "labels") == 0){
        if (cfg = getLabelsConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getAgentInternalOptions(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_free(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else {
        goto error;
    }
error:
    mdebug1("At AGCOM getconfig: Could not get '%s' section", section);
    *output = strdup("err Could not get requested section");
    return strlen(*output);
}
