/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * Mar 14, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "wmodules.h"
#include "os_net/os_net.h"


size_t wmcom_dispatch(char * command, char ** output){

    if (strncmp(command, "getconfig", 9) == 0){
        /*
         * getconfig wmodules
         * getconfig internal_options
        */
        char *rcv_comm = command;
        char *rcv_args = NULL;

        if ((rcv_args = strchr(rcv_comm, ' '))){
            *rcv_args = '\0';
            rcv_args++;
        }
        // getconfig section
        if (!rcv_args){
            mdebug1("WMCOM getconfig needs arguments.");
            os_strdup("err WMCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return wmcom_getconfig(rcv_args, output);
    } else if (strncmp(command, "query ", 6) == 0) {
        return wm_module_query(command + 6, output);
    } else if (strstr(command, SYNC_HEADER) != NULL) {
        return wm_module_sync_response(command, output);
    } else if (wmcom_sync(command) == 0) {
        /*
         * syscollector_hwinfo dbsync checksum_fail { ... }
         * syscollector_osinfo dbsync checksum_fail { ... }
         * syscollector_ports dbsync checksum_fail { ... }
         * syscollector_processes dbsync checksum_fail { ... }
        */
        return 0;
    } else {
        mdebug1("WMCOM Unrecognized command '%s'.", command);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

size_t wmcom_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "wmodules") == 0){
        if (cfg = getModulesConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal_options") == 0){
        if (cfg = getModulesInternalOptions(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else {
        goto error;
    }
error:
    mdebug1("At WMCOM getconfig: Could not get '%s' section", section);
    os_strdup("err Could not get requested section", *output);
    return strlen(*output);
}

int wmcom_sync(char * buffer) {
    const int ret = modulesSync(buffer);
    if(ret) {
        mdebug1("At WMCOM sync: Could not sync '%s' buffer", buffer);
    }
    return ret;
}

#ifdef WIN32
void wmcom_send(char * message)
{
    wmcom_sync(message);
}
#else

void wmcom_send(char * message)
{
    int sock;
    if (sock = OS_ConnectUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        switch (errno) {
            case ECONNREFUSED:
                mdebug1("Target wmodules refused connection. The component might be disabled");
                break;

            default:
                mdebug1("Could not connect to socket wmodules: %s (%d).", strerror(errno), errno);
        }
    }
    else
    {
        OS_SendSecureTCP(sock, strlen(message), message);
        close(sock);
    }
}

void * wmcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    if (sock = OS_BindUnixDomainWithPerms(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.", WM_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At wmcom_main(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At wmcom_main(): accept(): %s", strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At wmcom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("At wmcom_main(): OS_RecvSecureTCP(): %s", strerror(errno));
            break;

        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            break;

        case OS_MAXLEN:
            merror("Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            length = wmcom_dispatch(buffer, &response);
            if (length) {
                OS_SendSecureTCP(peer, length, response);
            }
            os_free(response);
            close(peer);
        }
        os_free(buffer);
    }

    mdebug1("Local server thread finished.");

    close(sock);
    return NULL;
}

#endif
