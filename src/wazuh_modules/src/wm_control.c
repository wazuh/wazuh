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
#include "file_op.h"
#include "os_net.h"

static void *wm_control_main();
static void wm_control_destroy();
cJSON *wm_control_dump();
static void *process_control();

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
#ifdef CLIENT
    w_create_thread(process_control, NULL);
#else
    process_control();
#endif
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

bool wm_control_check_systemd() {
    if (access("/run/systemd/system", F_OK) != 0) {
        return false;
    }

    FILE *fp = fopen("/proc/1/comm", "r");
    if (fp) {
        char init_name[256];
        if (fgets(init_name, sizeof(init_name), fp)) {
            init_name[strcspn(init_name, "\n")] = 0;
            if (strcmp(init_name, "systemd") == 0) {
                fclose(fp);
                return true;
            }
        }
        fclose(fp);
    }

    return false;
}

bool wm_control_wait_for_service_active(const char *service) {
    const int timeout = 60;
    int elapsed = 0;
    char cmd[256];

    snprintf(cmd, sizeof(cmd), "systemctl is-active %s 2>/dev/null", service);

    while (elapsed < timeout) {
        FILE *fp = popen(cmd, "r");
        if (fp) {
            char state[256];
            if (fgets(state, sizeof(state), fp)) {
                state[strcspn(state, "\n")] = 0;

                if (strcmp(state, "inactive") == 0 || strcmp(state, "failed") == 0) {
                    pclose(fp);
                    mterror(WM_CONTROL_LOGTAG, "Service %s is in state '%s', cannot reload", service, state);
                    return false;
                }

                if (strcmp(state, "active") == 0) {
                    pclose(fp);
                    return true;
                }
            }
            pclose(fp);
        }

        sleep(1);
        elapsed++;
    }

    mterror(WM_CONTROL_LOGTAG, "Service %s is not active after waiting %d seconds", service, timeout);
    return false;
}

size_t wm_control_execute_action(const char *action, const char *service, char **output) {
    bool use_systemd = wm_control_check_systemd();
    char *exec_cmd[4] = {NULL};

    if (use_systemd) {
        exec_cmd[0] = "/usr/bin/systemctl";
        exec_cmd[1] = (char *)action;
        exec_cmd[2] = (char *)service;
        mtinfo(WM_CONTROL_LOGTAG, "Executing '%s' on %s using systemctl", action, service);
    } else {
        exec_cmd[0] = "bin/wazuh-control";
        exec_cmd[1] = (char *)action;
        mtinfo(WM_CONTROL_LOGTAG, "Executing '%s' on %s using wazuh-control", action, service);
    }

    switch (fork()) {
        case -1:
            mterror(WM_CONTROL_LOGTAG, "Cannot fork for %s", action);
            os_strdup("err Cannot fork", *output);
            return strlen(*output);
        case 0:
            if (use_systemd && strcmp(action, "reload") == 0) {
                if (!wm_control_wait_for_service_active(service)) {
                    mterror(WM_CONTROL_LOGTAG, "Service %s not active for reload", service);
                    _exit(1);
                }
            }
            if (execv(exec_cmd[0], exec_cmd) < 0) {
                mterror(WM_CONTROL_LOGTAG, "Error executing %s command: %s (%d)", action, strerror(errno), errno);
            }
            _exit(1);
        default:
            os_strdup("ok ", *output);
            return strlen(*output);
    }
}

size_t wm_control_dispatch(char *command, char **output) {
    char *args = strchr(command, ' ');
    if (args) {
        *args = '\0';
        args++;
    }

    mtdebug2(WM_CONTROL_LOGTAG, "Dispatching command: '%s'", command);

#ifdef CLIENT
    const char *service = "wazuh-agent";
#else
    const char *service = "wazuh-manager";
#endif

    if (strcmp(command, "restart") == 0) {
        return wm_control_execute_action("restart", service, output);

    } else if (strcmp(command, "reload") == 0) {
        return wm_control_execute_action("reload", service, output);

    } else {
        mterror(WM_CONTROL_LOGTAG, "Unknown command: '%s'", command);
        os_strdup("Err", *output);
        return strlen(*output);
    }
}

static void *process_control() {
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

        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                mterror_exit(WM_CONTROL_LOGTAG, "At process_control(): select(): %s", strerror(errno));
            }
            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_CONTROL_LOGTAG, "At process_control(): accept(): %s", strerror(errno));
            }
            continue;
        }

        os_calloc(OS_MAXSTR + 1, sizeof(char), buffer);

#ifdef CLIENT
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case -1:
            mterror(WM_CONTROL_LOGTAG, "At process_control(): OS_RecvSecureTCP(): %s", strerror(errno));
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
            wm_control_dispatch(buffer, &response);
            if (response) {
                OS_SendSecureTCP(peer, strlen(response), response);
                free(response);
            } else {
                OS_SendSecureTCP(peer, 3, "Err");
            }
            close(peer);
        }
#else
        switch (length = OS_RecvUnix(peer, OS_MAXSTR, buffer), length) {
        case -1:
            mterror(WM_CONTROL_LOGTAG, "At process_control(): OS_RecvUnix(): %s", strerror(errno));
            break;
        case 0:
            mtinfo(WM_CONTROL_LOGTAG, "Empty message from local client.");
            close(peer);
            break;
        case OS_MAXLEN:
            mterror(WM_CONTROL_LOGTAG, "Received message > %i", MAX_DYN_STR);
            close(peer);
            break;
        default:
            wm_control_dispatch(buffer, &response);
            if (response) {
                OS_SendUnix(peer, response, 0);
                free(response);
            } else {
                OS_SendUnix(peer, "Err", 4);
            }
            close(peer);
        }
#endif

        free(buffer);
        buffer = NULL;
    }

    close(sock);
    return NULL;
}

#endif
