/* Remote request listener
 * Copyright (C) 2018 Wazuh Inc.
 * Mar 28, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "os_net/os_net.h"
#include "agentlessd.h"

size_t lessdcom_dispatch(char *command, size_t length __attribute__ ((unused)), char *output) {

    const char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            merror("LESSDCOM getconfig needs arguments.");
            strcpy(output, "err LESSDCOM getconfig needs arguments");
            return strlen(output);
        }
        return lessdcom_getconfig(rcv_args, output);

    } else {
        merror("LESSDCOM Unrecognized command '%s'.", rcv_comm);
        strcpy(output, "err Unrecognized command");
        return strlen(output);
    }
}

size_t lessdcom_getconfig(const char * section, char * output) {

    cJSON *cfg;

    if (strcmp(section, "agentless") == 0){
        if (cfg = getAgentlessConfig(), cfg) {
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
    merror("At LESSDCOM getconfig: Could not get '%s' section", section);
    strcpy(output, "err Could not get requested section");
    return strlen(output);
}


void * lessdcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char buffer[OS_MAXSTR + 1];
    char response[OS_MAXSTR + 1];
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(DEFAULTDIR LESSD_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s'. Closing local server.", LESSD_LOCAL_SOCK);
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At lessdcom_main(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At lessdcom_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        switch (length = recv(peer, buffer, OS_MAXSTR, 0), length) {
        case -1:
            merror("At lessdcom_main(): recv(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        default:
            buffer[length] = '\0';
            length = lessdcom_dispatch(buffer, length, response);
            send(peer, response, length, 0);
            close(peer);
        }
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}
