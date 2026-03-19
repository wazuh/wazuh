/*
 * Wazuh Module for Agent control
 * Copyright (C) 2015, Wazuh Inc.
 * January, 2019
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined(__linux__) || defined(__MACH__) || defined(FreeBSD) || defined(OpenBSD)

#include "wm_control.h"
#include <cJSON.h>
#include "defs.h"
#include "os_net.h"

static void *wm_control_main();
static void wm_control_destroy();
cJSON *wm_control_dump();
static void *send_agent_control();

const wm_context WM_CONTROL_CONTEXT = {
    .name = "control",
    .start = (wm_routine)wm_control_main,
    .destroy = (void(*)(void *))wm_control_destroy,
    .dump = (cJSON * (*)(const void *))wm_control_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

static void *wm_control_main() {
    mtinfo(WM_CONTROL_LOGTAG, "Starting control thread.");
    w_create_thread(send_agent_control, NULL);
    return NULL;
}

static void wm_control_destroy() {
}

wmodule *wm_control_read() {
    wmodule *module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CONTROL_CONTEXT;
    module->tag = strdup(module->context->name);

    return module;
}

cJSON *wm_control_dump() {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd, "enabled", "yes");
    cJSON_AddItemToObject(root, "wazuh_control", wm_wd);
    return root;
}

static void *send_agent_control() {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    if (sock = OS_BindUnixDomainWithPerms(CONTROL_SOCK, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660), sock < 0) {
        mterror(WM_CONTROL_LOGTAG, "Unable to bind to socket '%s': (%d) %s.", CONTROL_SOCK, errno, strerror(errno));
        return NULL;
    }

    while (1) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                mterror_exit(WM_CONTROL_LOGTAG, "At send_agent_control(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_CONTROL_LOGTAG, "At send_agent_control(): accept(): %s", strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR + 1, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case -1:
            mterror(WM_CONTROL_LOGTAG, "At send_agent_control(): OS_RecvSecureTCP(): %s", strerror(errno));
            break;

        case 0:
            mtinfo(WM_CONTROL_LOGTAG, "Empty message from local client.");
            close(peer);
            break;

        case OS_SOCKTERR:
            mterror(WM_CONTROL_LOGTAG, "Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            buffer[length] = '\0';
            wm_agentcontrol_dispatch(buffer, &response);
            if (response) {
                OS_SendSecureTCP(peer, strlen(response), response);
                free(response);
            } else {
                OS_SendSecureTCP(peer, 3, "Err");
            }
            close(peer);
        }
        free(buffer);
        buffer = NULL;
    }

    close(sock);
    return NULL;
}

#endif
