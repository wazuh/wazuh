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

size_t wmcom_dispatch(char * command, char ** output) {
    cJSON* message = cJSON_Parse(command);
    if (message) {
        return wmcom_parse_request(command, output);
    } else if (strncmp(command, "getconfig", 9) == 0) {
        char *rcv_comm = command;
        char *rcv_args = NULL;

        if ((rcv_args = strchr(rcv_comm, ' '))) {
            *rcv_args = '\0';
            rcv_args++;
        }
        // getconfig section
        if (!rcv_args) {
            mdebug1("WMCOM getconfig needs arguments.");
            os_strdup("err WMCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return wmcom_getconfig(rcv_args, output);
    } else if (wmcom_sync(command) == 0) {
        return 0;
    } else {
        mdebug1("WMCOM Unrecognized command '%s'.", command);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

size_t wmcom_parse_request(const char * command, char ** output) {
    cJSON *j_message = cJSON_Parse(command);

    cJSON *j_version = cJSON_GetObjectItem(j_message, "version");
    if (!cJSON_IsNumber(j_version)) {
        mdebug1("WMCOM Invalid version value '%s'.", command);
        os_strdup("err Invalid version value", *output);
        return strlen(*output);
    }
    cJSON *j_command = cJSON_GetObjectItem(j_message, "command");
    if(!cJSON_IsString(j_command)) {
        mdebug1("WMCOM Invalid command '%s'.", command);
        os_strdup("err Invalid command", *output);
        return strlen(*output);
    }
    cJSON *j_origin = cJSON_GetObjectItem(j_message, "origin");
    cJSON *j_origin_name = cJSON_GetObjectItem(j_origin, "name");
    cJSON *j_origin_module = cJSON_GetObjectItem(j_origin, "module");
    if(!cJSON_IsString(j_origin_name) || !cJSON_IsString(j_origin_module)) {
        mdebug1("WMCOM Invalid origin information '%s'.", command);
        os_strdup("err Invalid origin information", *output);
        return strlen(*output);
    }
    cJSON *j_parameters = cJSON_GetObjectItem(j_message, "parameters");
    if(!cJSON_IsObject(j_parameters)) {
        mdebug1("WMCOM Invalid command parameters '%s'.", command);
        os_strdup("err Invalid command parameters", *output);
        return strlen(*output);
    }
    char *module = cJSON_GetStringValue(cJSON_GetObjectItem(j_parameters, "module"));
    if (module && strcmp(module, VU_WM_NAME) == 0) {
        cJSON *response = NULL;
        if (response = run_task(j_message), response) {
            os_strdup("ok", *output);
            char *json_str = cJSON_PrintUnformatted(response);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(response);
            return strlen(*output);
        }
    }
    cJSON_Delete(j_message);
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

void wmcom_send(char * message) {
    int sock;
    if (sock = OS_ConnectUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        switch (errno) {
            case ECONNREFUSED:
                mdebug1("Target wmodules refused connection. The component might be disabled");
                break;

            default:
                mdebug1("Could not connect to socket wmodules: %s (%d).", strerror(errno), errno);
        }
    } else {
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

    if (sock = OS_BindUnixDomain(WM_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
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
                minfo("COMMAND: %s", buffer);
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
