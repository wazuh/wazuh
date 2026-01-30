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
#ifndef WIN32
#ifndef WM_CONTROL
#define WM_CONTROL

#define WM_CONTROL_LOGTAG ARGV0 ":control"

#include "wmodules.h"

extern const wm_context WM_CONTROL_CONTEXT;

typedef struct wm_control_t {
    unsigned int enabled:1;
    unsigned int run_on_start:1;
} wm_control_t;

wmodule *wm_control_read();
char *getPrimaryIP();
void *send_ip();

/**
 * @brief Dispatch control commands and execute corresponding actions
 *
 * Parses incoming commands and routes them to appropriate handlers.
 * Supported commands: restart, reload, getip (or empty for backward compatibility)
 *
 * @param command Command string with optional arguments
 * @param output Pointer to string that will contain the response message
 * @return size_t Length of the output string
 */
size_t wm_control_dispatch(char *command, char **output);

/**
 * @brief Execute restart or reload action on the Wazuh manager
 *
 * Detects if systemd is available and uses systemctl, otherwise falls back to wazuh-control.
 * For reload actions, waits for service to be active before proceeding (systemd only).
 *
 * @param action "restart" or "reload"
 * @param output Pointer to string that will contain the response message
 * @return size_t Length of the output string
 */
size_t wm_control_execute_action(const char *action, char **output);

#endif
#endif
