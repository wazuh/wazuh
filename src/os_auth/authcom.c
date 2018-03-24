/* Remote request listener
 * Copyright (C) 2018 Wazuh Inc.
 * Mar 22, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "auth.h"
#include "os_net/os_net.h"

size_t authcom_dispatch(const char *command, char *output){

    const char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            merror("AUTHCOM getconfig needs arguments.");
            strcpy(output, "err AUTHCOM getconfig needs arguments");
            return strlen(output);
        }
        return authcom_getconfig(rcv_args, output);

    } else {
        merror("AUTHCOM Unrecognized command '%s'.", rcv_comm);
        strcpy(output, "err Unrecognized command");
        return strlen(output);
    }
}

size_t authcom_getconfig(const char * section, char * output) {

    cJSON *cfg;

    if (strcmp(section, "auth") == 0){
        if (cfg = getAuthdConfig(), cfg) {
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
    merror("At AUTHCOM getconfig: Could not get '%s' section", section);
    strcpy(output, "err Could not get requested section");
    return strlen(output);
}
