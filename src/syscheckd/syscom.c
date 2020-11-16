/* Remote request listener
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Mar 14, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "syscheck.h"
#include "rootcheck/rootcheck.h"
#include "os_net/os_net.h"
#include "wazuh_modules/wmodules.h"

#ifdef WAZUH_UNIT_TESTING
/* Replace assert with mock_assert */
extern void mock_assert(const int result, const char* const expression,
                        const char * const file, const int line);
#undef assert
#define assert(expression) \
    mock_assert((int)(expression), #expression, __FILE__, __LINE__);
#endif

size_t syscom_dispatch(char * command, char ** output){
    assert(command != NULL);
    assert(output != NULL);

    char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            mdebug1(FIM_SYSCOM_ARGUMENTS, "getconfig");
            os_strdup("err SYSCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return syscom_getconfig(rcv_args, output);
    } else if (strcmp(rcv_comm, "dbsync") == 0) {
        if (rcv_args == NULL) {
            mdebug1(FIM_SYSCOM_ARGUMENTS, "dbsync");
        } else {
            fim_sync_push_msg(rcv_args);
        }

        return 0;
    } else if (strcmp(rcv_comm, "restart") == 0) {
        os_set_restart_syscheck();
        return 0;
    } else {
        mdebug1(FIM_SYSCOM_UNRECOGNIZED_COMMAND, rcv_comm);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

size_t syscom_getconfig(const char * section, char ** output) {
    assert(section != NULL);
    assert(output != NULL);

    cJSON *cfg;
    char *json_str;

    if (strcmp(section, "syscheck") == 0){
        if (cfg = getSyscheckConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "rootcheck") == 0){
        if (cfg = getRootcheckConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getSyscheckInternalOptions(), cfg) {
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
    mdebug1(FIM_SYSCOM_FAIL_GETCONFIG, section);
    os_strdup("err Could not get requested section", *output);
    return strlen(*output);
}

// LCOV_EXCL_START
#ifndef WIN32
void * syscom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1(FIM_SYSCOM_REQUEST_READY);

    if (sock = OS_BindUnixDomain(DEFAULTDIR SYS_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror(FIM_ERROR_SYSCOM_BIND_SOCKET, SYS_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit(FIM_CRITICAL_ERROR_SELECT, "syscom_main()", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror(FIM_ERROR_SYSCOM_ACCEPT, strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror(FIM_ERROR_SYSCOM_RECV_TOOLONG);
            break;

        case -1:
            merror(FIM_ERROR_SYSCOM_RECV, strerror(errno));
            break;

        case 0:
            mdebug1(FIM_SYSCOM_EMPTY_MESSAGE);
            close(peer);
            break;

        case OS_MAXLEN:
            merror(FIM_ERROR_SYSCOM_RECV_MAXLEN, MAX_DYN_STR);
            close(peer);
            break;

        default:
            length = syscom_dispatch(buffer, &response);

            if (length > 0) {
                OS_SendSecureTCP(peer, length, response);
            }
            os_free(response);

            close(peer);
        }
        free(buffer);
    }

    mdebug1(FIM_SYSCOM_THREAD_FINISED);

    close(sock);
    return NULL;
}

#endif
// LCOV_EXCL_STOP
