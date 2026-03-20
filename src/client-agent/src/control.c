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
 * os_start_service() can run. A detached copy of wazuh-agent.exe is independent
 * of WazuhSvc, survives the stop, and brings it back up. The caller returns "ok"
 * immediately so the req-protocol response reaches remoted before the service
 * goes down — mirroring the old wcom_restart/wcom_reload pattern of spawning a
 * separate process (restart-wazuh.exe) and returning "ok" straight away.
 *
 * @param action  Label used in the debug log ("restart" or "reload").
 * @param output  Allocated response string set by this function.
 * @return size_t Length of *output.
 */
static size_t control_run_detached(const char *action, char **output) {
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char exe[MAX_PATH];
    char cmd[OS_FLSIZE];

    /* Resolve the full path of the running wazuh-agent.exe binary and spawn a
     * detached copy of it with the "service-restart" argument.  That child
     * process runs outside WazuhSvc, waits briefly, stops the service and then
     * starts it again — mirroring the old restart-wazuh.exe pattern.  The
     * caller returns "ok" immediately so the req-protocol response reaches
     * remoted before the service goes down. */
    if (!GetModuleFileNameA(NULL, exe, MAX_PATH)) {
        mdebug1("CONTROL: GetModuleFileName failed for '%s' (error %lu).", action, GetLastError());
        os_strdup("err GetModuleFileName failed", *output);
        return strlen(*output);
    }

    snprintf(cmd, sizeof(cmd), "\"%s\" service-restart", exe);

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

    minfo("Agent control: '%s' command received, detached restart process spawned.", action);
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
        minfo("Agent control: restart command received.");
        return control_run_detached("restart", output);

    } else if (strcmp(command, "reload") == 0) {
        /* Windows has no SIGHUP equivalent; reload is a full stop + start,
         * consistent with the old wcom_reload behaviour on Windows. */
        minfo("Agent control: reload command received.");
        return control_run_detached("reload", output);

    } else {
        mdebug1("CONTROL: Unrecognized command '%s'.", command);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

#endif /* WIN32 */
