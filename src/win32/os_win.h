/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_WIN_H
#define OS_WIN_H

#include "defs.h"
#include "wmodules_def.h"

/* Context handed to win_module_thread(): boxes a module's start routine and
 * data so the thread entry point can wait on the startup gate before
 * invoking it. Exposed here (rather than kept private to win_utils.c) so
 * unit tests can construct one directly. */
typedef struct win_module_start_ctx {
    wm_routine routine;
    void *data;
    char name[OS_SIZE_128];
} win_module_start_ctx_t;

#ifdef WIN32
DWORD WINAPI skthread(LPVOID arg);
DWORD WINAPI logcollector_thread(LPVOID arg);
DWORD WINAPI win_module_thread(void *arg);
#endif

/* Install the WAZUH-HIDS agent service */
int InstallService(char *path);

/* Uninstall the WAZUH-HIDS agent service */
int UninstallService();

/* Check if the WAZUH-HIDS agent service is running
 * Returns 1 on success (running) or 0 if not running
 */
int CheckServiceRunning();

/* Start WAZUH-HIDS service */
int os_start_service();

/* Stop WAZUH-HIDS service */
int os_stop_service();

/* Start the process from the services */
int os_WinMain(int argc, char **argv);

/* Locally start the process (after the services initialization) */
int local_start();

#ifdef WAZUH_UNIT_TESTING
/* Stop the running service and start a fresh one (the "service-restart" CLI
 * subcommand's implementation). Only declared here under test: in a real
 * build it stays STATIC to win_agent.c, so this prototype would otherwise
 * conflict with that static definition. */
int run_service_restart(void);
#endif

#endif /* OS_WIN_H */
