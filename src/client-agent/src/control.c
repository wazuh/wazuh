/* Agent control command dispatcher (Windows)
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include <shared.h>
#include "agentd.h"

/**
 * @brief Spawn a detached process to stop and restart the WazuhSvc service.
 *
 * Calling os_stop_service() from within WazuhSvc kills all its threads before
 * os_start_service() can run. A detached cmd.exe process is independent of
 * WazuhSvc, survives the stop, and issues the start. The caller returns "ok"
 * immediately so the req-protocol response reaches remoted before the service
 * goes down — matching the old wcom_restart/wcom_reload pattern of spawning a
 * separate process (restart-wazuh.exe) and returning "ok" straight away.
 *
 * @param action  Label used in the debug log ("restart" or "reload").
 * @param output  Allocated response string set by this function.
 * @return size_t Length of *output.
 */
static size_t control_run_detached(const char *action, char **output) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    /* ping buys ~1 s so the "ok" reply reaches remoted before WazuhSvc stops.
     * net stop waits for full stop; net start brings it back up. */
    char cmd[] = "cmd.exe /c \"ping -n 2 127.0.0.1 >nul"
                 " && net stop WazuhSvc"
                 " && net start WazuhSvc\"";

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | DETACHED_PROCESS,
                        NULL, NULL, &si, &pi)) {
        mdebug1("CONTROL: CreateProcess failed for '%s' (error %lu).", action, GetLastError());
        os_strdup("err CreateProcess failed", *output);
        return strlen(*output);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    mdebug1("CONTROL: Dispatched detached process for '%s'.", action);
    os_strdup("ok ", *output);
    return strlen(*output);
}

size_t control_dispatch(char *command, char **output) {
    char *args = strchr(command, ' ');
    if (args) {
        *args = '\0';
        args++;
    }

    if (strcmp(command, "restart") == 0) {
        mdebug1("Restarting Wazuh agent service via control.");
        return control_run_detached("restart", output);

    } else if (strcmp(command, "reload") == 0) {
        /* Windows has no SIGHUP equivalent; reload is a full stop + start,
         * consistent with the old wcom_reload behaviour on Windows. */
        mdebug1("Reloading Wazuh agent service via control (restart).");
        return control_run_detached("reload", output);

    } else {
        mdebug1("CONTROL: Unrecognized command '%s'.", command);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

#endif /* WIN32 */
