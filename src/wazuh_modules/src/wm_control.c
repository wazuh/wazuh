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

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

#if defined (__linux__) || defined (__MACH__) || defined(FreeBSD) || defined(OpenBSD)
#include "wm_control.h"
#include "sysInfo.h"
#include "sym_load.h"
#include <cJSON.h>
#include "file_op.h"
#include "os_net.h"
static void *wm_control_main();
static void wm_control_destroy();
cJSON *wm_control_dump();

const wm_context WM_CONTROL_CONTEXT = {
    .name = "control",
    .start = (wm_routine)wm_control_main,
    .destroy = (void(*)(void *))wm_control_destroy,
    .dump = (cJSON * (*)(const void *))wm_control_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};
STATIC void *sysinfo_module = NULL;
STATIC sysinfo_networks_func sysinfo_network_ptr = NULL;
STATIC sysinfo_free_result_func sysinfo_free_result_ptr = NULL;

/**
 * @brief Get the Primary IP address
 *
 * Resolve the host's IP as the IP address of the default route interface,
 * or the first non-loopback available interface.
 *
 * @return Pointer to a string holding the host's IP.
 * @post The user must free the returned pointer.
 */
char* getPrimaryIP(){
     /* Get Primary IP */
    char * agent_ip = NULL;

#if defined __linux__ || defined __MACH__ || defined(FreeBSD) || defined(OpenBSD)
    cJSON *object;
    if (sysinfo_network_ptr && sysinfo_free_result_ptr) {
        const int error_code = sysinfo_network_ptr(&object);
        if (error_code == 0) {
            if (object) {
                const cJSON *iface = cJSON_GetObjectItem(object, "iface");
                if (iface) {
                    const int size_ids = cJSON_GetArraySize(iface);
                    for (int i = 0; i < size_ids; i++){
                        const cJSON *element = cJSON_GetArrayItem(iface, i);
                        if(!element) {
                            continue;
                        }
                        cJSON *gateway = cJSON_GetObjectItem(element, "gateway");
                        if (gateway && cJSON_GetStringValue(gateway) && 0 != strcmp(gateway->valuestring," ")) {

                            const char * primaryIpType = NULL;
                            const char * secondaryIpType = NULL;

                            if (strchr(gateway->valuestring, ':') != NULL) {
                                //Assume gateway is IPv6. IPv6 IP will be prioritary
                                primaryIpType = "IPv6";
                                secondaryIpType = "IPv4";
                            } else {
                                //Assume gateway is IPv4. IPv4 IP will be prioritary
                                primaryIpType = "IPv4";
                                secondaryIpType = "IPv6";
                            }

                            const cJSON * ip = cJSON_GetObjectItem(element, primaryIpType);
                            if (NULL == ip) {
                                ip = cJSON_GetObjectItem(element, secondaryIpType);
                                if (NULL == ip) {
                                    continue;
                                }
                            }
                            const int size_proto_interfaces = cJSON_GetArraySize(ip);
                            for (int j = 0; j < size_proto_interfaces; ++j) {
                                const cJSON *element_ip = cJSON_GetArrayItem(ip, j);
                                if(!element_ip) {
                                    continue;
                                }
                                cJSON *address = cJSON_GetObjectItem(element_ip, "address");
                                if (address && cJSON_GetStringValue(address))
                                {
                                    os_strdup(address->valuestring, agent_ip);
                                    break;
                                }
                            }
                            if (agent_ip) {
                                break;
                            }
                        }
                    }
                }
                sysinfo_free_result_ptr(&object);
            }
        }
        else {
            mterror(WM_CONTROL_LOGTAG, "Unable to get system network information. Error code: %d.", error_code);
        }
    }

#endif

    if (agent_ip && (strchr(agent_ip, ':') != NULL)) {
        os_realloc(agent_ip, IPSIZE + 1, agent_ip);
        OS_ExpandIPv6(agent_ip, IPSIZE);
    }

    return agent_ip;
}


void *wm_control_main(){
    mtinfo(WM_CONTROL_LOGTAG, "Starting control thread.");
    if (sysinfo_module = so_get_module_handle("sysinfo"), sysinfo_module)
    {
        sysinfo_free_result_ptr = so_get_function_sym(sysinfo_module, "sysinfo_free_result");
        sysinfo_network_ptr = so_get_function_sym(sysinfo_module, "sysinfo_networks");
    }

    send_ip();

    return NULL;
}

void wm_control_destroy(){
    if (sysinfo_module){
        so_free_library(sysinfo_module);
    }
}

wmodule *wm_control_read(){
    wmodule * module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CONTROL_CONTEXT;
    module->tag = strdup(module->context->name);

    return module;
}

cJSON *wm_control_dump() {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");
    cJSON_AddItemToObject(root,"wazuh_control",wm_wd);
    return root;
}

void *send_ip(){
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
                mterror_exit(WM_CONTROL_LOGTAG, "At send_ip(): select(): %s", strerror(errno));
            }

            continue;

        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_CONTROL_LOGTAG, "At send_ip(): accept(): %s", strerror(errno));
            }

            continue;
        }

        os_calloc(OS_MAXSTR + 1, sizeof(char), buffer);
        switch (length = OS_RecvUnix(peer, OS_MAXSTR, buffer), length) {
        case -1:
            mterror(WM_CONTROL_LOGTAG, "At send_ip(): OS_RecvUnix(): %s", strerror(errno));
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
            if(response){
                OS_SendUnix(peer, response, 0);
                free(response);
            }
            else{
                OS_SendUnix(peer,"Err",4);
            }
            close(peer);
        }
        free(buffer);
    }

    close(sock);
    return NULL;
}

size_t wm_control_dispatch(char *command, char **output) {
    // Parse command and arguments
    char *args = strchr(command, ' ');
    if (args) {
        *args = '\0';
        args++;
    }

    mtdebug2(WM_CONTROL_LOGTAG, "Dispatching command: '%s'", command);

    if (strcmp(command, "restart") == 0) {
        return wm_control_execute_action("restart", output);

    } else if (strcmp(command, "reload") == 0) {
        return wm_control_execute_action("reload", output);

    } else {
        // Default: return IP for backward compatibility (getip, host_ip, or any other message)
        *output = getPrimaryIP();
        if (!*output) {
            os_strdup("Err", *output);
        }
        return strlen(*output);
    }
}

/**
 * @brief Check if systemd is available as the init system
 * @return true if systemd is available, false otherwise
 */
STATIC bool wm_control_check_systemd() {
    // Check if systemd system directory exists
    if (access("/run/systemd/system", F_OK) != 0) {
        return false;
    }

    // Check if systemd is PID 1
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

/**
 * @brief Wait for wazuh-manager service to be in active state
 *
 * This is needed before attempting a reload to ensure the service is ready.
 * Waits up to 60 seconds for the service to become active.
 *
 * @return true if service is active, false otherwise
 */
STATIC bool wm_control_wait_for_service_active() {
    const int timeout = 60;
    int elapsed = 0;

    while (elapsed < timeout) {
        FILE *fp = popen("systemctl is-active wazuh-manager 2>/dev/null", "r");
        if (fp) {
            char state[256];
            if (fgets(state, sizeof(state), fp)) {
                state[strcspn(state, "\n")] = 0;

                if (strcmp(state, "inactive") == 0 || strcmp(state, "failed") == 0) {
                    pclose(fp);
                    mterror(WM_CONTROL_LOGTAG, "Service wazuh-manager is in state '%s', cannot reload", state);
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

    mterror(WM_CONTROL_LOGTAG, "Service wazuh-manager is not active after waiting %d seconds", timeout);
    return false;
}

size_t wm_control_execute_action(const char *action, char **output) {
    bool use_systemd = wm_control_check_systemd();
    char *exec_cmd[4] = {NULL};

    if (use_systemd) {
        exec_cmd[0] = "/usr/bin/systemctl";
        exec_cmd[1] = (char *)action;
        exec_cmd[2] = "wazuh-manager";
        mtinfo(WM_CONTROL_LOGTAG, "Executing '%s' on manager using systemctl", action);
    } else {
        exec_cmd[0] = "bin/wazuh-control";
        exec_cmd[1] = (char *)action;
        mtinfo(WM_CONTROL_LOGTAG, "Executing '%s' on manager using wazuh-control", action);
    }

    switch (fork()) {
        case -1:
            // Fork failed
            mterror(WM_CONTROL_LOGTAG, "Cannot fork for %s", action);
            os_strdup("err Cannot fork", *output);
            return strlen(*output);
        case 0:
            // Child process - this code path never returns to the caller

            // For reload with systemd, wait for service to be active first
            if (use_systemd && strcmp(action, "reload") == 0) {
                if (!wm_control_wait_for_service_active()) {
                    mterror(WM_CONTROL_LOGTAG, "Service not active for reload");
                    _exit(1);
                }
            }

            // Execute command - either replaces process or exits on error
            if (execv(exec_cmd[0], exec_cmd) < 0) {
                mterror(WM_CONTROL_LOGTAG, "Error executing %s command: %s (%d)", action, strerror(errno), errno);
            }
            _exit(1);  // Always exit if execv fails or returns
        default:
            // Parent process - return success immediately
            os_strdup("ok ", *output);
            return strlen(*output);
    }
}

#endif
