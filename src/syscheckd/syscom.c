/* Remote request listener
 * Copyright (C) 2018 Wazuh Inc.
 * Mar 14, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "syscheck.h"
#include "rootcheck/rootcheck.h"
#include "os_net/os_net.h"

#ifndef WIN32

size_t syscom_dispatch(char *command, size_t length __attribute__ ((unused)), char *output){

    char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            merror("SYSCOM getconfig needs arguments.");
            strcpy(output, "err SYSCOM getconfig needs arguments");
            return strlen(output);
        }
        return syscom_getconfig(rcv_args, output);

    } else {
        merror("SYSCOM Unrecognized command '%s'.", rcv_comm);
        strcpy(output, "err Unrecognized command");
        return strlen(output);
    }
}

size_t syscom_getconfig(const char * section, char * output) {

    cJSON *cfg;

    if (strcmp(section, "syscheck") == 0){
        if (cfg = getSyscheckConfig(), cfg) {
            snprintf(output, OS_MAXSTR + 1, "ok %s", cJSON_PrintUnformatted(cfg));
            cJSON_free(cfg);
            return strlen(output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "rootcheck") == 0){
        if (cfg = getRootcheckConfig(), cfg) {
            snprintf(output, OS_MAXSTR + 1, "ok %s", cJSON_PrintUnformatted(cfg));
            cJSON_free(cfg);
            return strlen(output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal_options") == 0){
        if (cfg = getSyscheckInternalOptions(), cfg) {
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
    merror("At SYSCOM getconfig: Could not get '%s' section", section);
    strcpy(output, "err Could not get requested section");
    return strlen(output);
}

void * syscom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char buffer[OS_MAXSTR + 1];
    char response[OS_MAXSTR + 1];
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomain(DEFAULTDIR SYS_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s'. Closing local server.", SYS_LOCAL_SOCK);
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At syscom_main(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At syscom_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        switch (length = recv(peer, buffer, OS_MAXSTR, 0), length) {
        case -1:
            merror("At syscom_main(): recv(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        default:
            buffer[length] = '\0';
            length = syscom_dispatch(buffer, length, response);
            send(peer, response, length, 0);
            close(peer);
        }
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}

#endif
