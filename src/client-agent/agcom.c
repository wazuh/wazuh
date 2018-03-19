/* Remote request listener
 * Copyright (C) 2018 Wazuh Inc.
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

#ifndef WIN32

size_t agcom_dispatch(char *command, size_t length __attribute__ ((unused)), char *output){

    char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            merror("AGCOM getconfig needs arguments.");
            strcpy(output, "err AGCOM getconfig needs arguments");
            return strlen(output);
        }
        return agcom_getconfig(rcv_args, output);

    } else {
        merror("AGCOM Unrecognized command '%s'.", rcv_comm);
        strcpy(output, "err Unrecognized command");
        return strlen(output);
    }
}

size_t agcom_getconfig(const char * section, char * output) {

    cJSON *cfg;

    if (strcmp(section, "client") == 0){
        if (cfg = getClientConfig(), cfg) {
            snprintf(output, OS_MAXSTR + 1, "ok %s", cJSON_PrintUnformatted(cfg));
            cJSON_free(cfg);
            return strlen(output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "client-buffer") == 0){
        if (cfg = getBufferConfig(), cfg) {
            snprintf(output, OS_MAXSTR + 1, "ok %s", cJSON_PrintUnformatted(cfg));
            cJSON_free(cfg);
            return strlen(output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "labels") == 0){
        if (cfg = getLabelsConfig(), cfg) {
            snprintf(output, OS_MAXSTR + 1, "ok %s", cJSON_PrintUnformatted(cfg));
            cJSON_free(cfg);
            return strlen(output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal_options") == 0){
        if (cfg = getAgentInternalOptions(), cfg) {
            snprintf(output, OS_MAXSTR + 1, "ok %s", cJSON_PrintUnformatted(cfg));
            cJSON_free(cfg);
            return strlen(output);
        } else {
            goto error;
        }
    } else {
        goto error;
    }
error:
    merror("At AGCOM getconfig: Could not get '%s' section", section);
    strcpy(output, "err Could not get requested section");
    return strlen(output);
}

#endif
