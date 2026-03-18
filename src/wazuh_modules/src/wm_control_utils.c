/*
 * Wazuh Module for Agent control - Shared utilities
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

/**
 * @brief Check if systemd is available as the init system
 * @return true if systemd is available, false otherwise
 */
bool wm_control_check_systemd() {
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
 * @brief Wait for a Wazuh service to be in active state
 *
 * This is needed before attempting a reload to ensure the service is ready.
 * Waits up to 60 seconds for the service to become active.
 *
 * @param service Service name to check (e.g. "wazuh-manager", "wazuh-agent")
 * @return true if service is active, false otherwise
 */
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
            // Wait for service to be active before reloading
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

size_t wm_agentcontrol_dispatch(char *command, char **output) {
    // Parse command and arguments
    char *args = strchr(command, ' ');
    if (args) {
        *args = '\0';
        args++;
    }

    mtdebug2(WM_CONTROL_LOGTAG, "Agent control dispatching command: '%s'", command);

    if (strcmp(command, "restart") == 0) {
        return wm_control_execute_action("restart", "wazuh-agent", output);

    } else if (strcmp(command, "reload") == 0) {
        return wm_control_execute_action("reload", "wazuh-agent", output);

    } else {
        mterror(WM_CONTROL_LOGTAG, "Agent control unknown command: '%s'", command);
        os_strdup("err Unknown command", *output);
        return strlen(*output);
    }
}

#endif
