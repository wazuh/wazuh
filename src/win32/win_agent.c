/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "shared.h"
#include "wmodules.h"
#include "agentd.h"
#include "logcollector.h"
#include "wmodules.h"
#include "os_win.h"
#include "os_net.h"
#include "execd.h"
#include "md5_op.h"
#include "external/cJSON/cJSON.h"

#ifndef ARGV0
#define ARGV0 "wazuh-agent"
#endif

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/* Defined in win_utils.c; idempotent (issue 38428). */
extern void wm_lifecycle_lock_init(void);

/**************************************************************************************
    WARNING: all the logging functions of this file must use the plain_ variant
    to avoid calling any external library that could be loaded before the signature
    verification can be executed in local_start.
**************************************************************************************/

/* Help message */
void agent_help()
{
    printf("\n%s %s %s .\n", __wazuh_name, ARGV0, __wazuh_version);
    printf("Available options:\n");
    printf("\t/?                This help message.\n");
    printf("\t-h                This help message.\n");
    printf("\thelp              This help message.\n");
    printf("\tinstall-service   Installs as a service\n");
    printf("\tuninstall-service Uninstalls as a service\n");
    printf("\tstart             Manually starts (not from services)\n");
    exit(1);
}

/* Stop the running service and start a fresh one, invoked either by
 * control_run_detached() as a detached process (manager-pushed shared-config
 * reload) or directly as the "service-restart" CLI subcommand. Extracted out
 * of main() so it can be unit-tested without a real argv/process exit.
 *
 * Serializes concurrent invocations on a named, cross-process mutex: without
 * this, N overlapping restarts each independently fall through
 * os_stop_service()'s "already stopping"/"already stopped" soft-success
 * cases into their own stop-wait-start sequence, with nothing coordinating
 * which one's stop/start actually wins. Observed live to leave the service
 * permanently SERVICE_STOPPED with no self-recovery and no error logged
 * anywhere (issue 38428). The mutex is held for the rest of this process's
 * life -- released automatically on exit, whichever return below is taken. */
STATIC int run_service_restart(void)
{
    DWORD startTime = 0;
    // Comfortably above the real worst case for a single restart: stop_wmodules()'s
    // own 20 s module-join budget, plus fim_db_teardown() (unbounded, runs right
    // after stop_wmodules() in OssecServiceCtrlHandler) and wm_kill_children(), both
    // of which used to happen inside the old process's own shutdown window but are
    // not covered by any timeout of their own. 30 s left no margin for either -- a
    // shutdown that legitimately used all of stop_wmodules()'s budget plus a slow
    // fim_db_teardown() would trip this timeout and return without ever calling
    // os_start_service(), leaving the service permanently stopped (issue 38428).
    const DWORD timeoutMs = 45000;           // 45 seconds
    const DWORD sleepIntervalMs = 500;       // 0.5 seconds
    const DWORD waitForServiceStopMs = 1000; // 1 second
    // ~2-3x the normal worst case for a single restart (20 s module-join budget
    // + 10 s SCA wait + overhead), so a second concurrent restart request only
    // ever times out here if something is already badly wrong (issue 38428).
    const DWORD restartMutexWaitMs = 60000;  // 60 seconds

    HANDLE restart_mutex = CreateMutex(NULL, FALSE, "Global\\WazuhAgentServiceRestart");
    if (restart_mutex == NULL) {
        plain_merror("service-restart: CreateMutex failed (error %lu); proceeding unsynchronized.", GetLastError());
    } else {
        const DWORD restart_mutex_wait_result = WaitForSingleObject(restart_mutex, restartMutexWaitMs);
        if (restart_mutex_wait_result == WAIT_TIMEOUT) {
            plain_merror("service-restart: another restart has been in progress for over %lu ms "
                         "(expected well under that) -- the agent may be stuck; not starting a "
                         "second concurrent restart attempt.", restartMutexWaitMs);
            CloseHandle(restart_mutex);
            return 1;
        }
        /* WAIT_ABANDONED: a previous restart's process exited (or crashed)
         * while still holding the mutex -- treat that the same as a clean
         * acquisition and proceed; it's ours now. */
    }

    /* Sleep briefly so the calling service has time to send its "ok"
     * response before we stop it, then perform stop + start. */
    Sleep(waitForServiceStopMs);
    /* Attempt to send the SERVICE_CONTROL_STOP command.
     * If this fails, the stop signal was not delivered to the SCM,
     * so there is no point in waiting for the service to stop. */
    int stop_rc = os_stop_service();
    if (stop_rc == 0) {
        plain_merror("Failure running stop service.");
        return 1;
    }
    /* Wait until the service fully transitions to the STOPPED state --
     * not just "not RUNNING": CheckServiceRunning() now also treats
     * every pending/paused state as still-running, so this correctly
     * keeps waiting through the old process's own shutdown instead of
     * starting a new one over it (issue 38428, defect #6). */
    startTime = GetTickCount();
    while (CheckServiceRunning()) {
        if (GetTickCount() - startTime > timeoutMs) {
            plain_merror("Failure service did not stop within the expected time.");
            return 1;
        }
        Sleep(sleepIntervalMs);
    }
    int start_rc = os_start_service();
    if (start_rc == 0) {
        plain_merror("Failure running start service.");
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    char *tmpstr;
    char mypath[OS_MAXSTR + 1];
    char myfinalpath[OS_MAXSTR + 1];
    char myfile[OS_MAXSTR + 1];

    /* Set the name */
    OS_SetName(ARGV0);

    /* Find where we are */
    mypath[OS_MAXSTR] = '\0';
    myfinalpath[OS_MAXSTR] = '\0';
    myfile[OS_MAXSTR] = '\0';

    /* mypath is going to be the whole path of the file */
    strncpy(mypath, argv[0], OS_MAXSTR);
    tmpstr = strrchr(mypath, '\\');
    if (tmpstr) {
        /* tmpstr is now the file name */
        *tmpstr = '\0';
        tmpstr++;
        strncpy(myfile, tmpstr, OS_MAXSTR);
    } else {
        strncpy(myfile, argv[0], OS_MAXSTR);
        mypath[0] = '.';
        mypath[1] = '\0';
    }
    if (chdir(mypath) < 0) {
        plain_merror_exit(CHDIR_ERROR, mypath, errno, strerror(errno));
    }
    getcwd(mypath, OS_MAXSTR - 1);
    snprintf(myfinalpath, OS_MAXSTR, "\"%s\\%s\"", mypath, myfile);

    if (argc > 1) {
        if (strcmp(argv[1], "install-service") == 0) {
            return (InstallService(myfinalpath));
        } else if (strcmp(argv[1], "uninstall-service") == 0) {
            return (UninstallService());
        } else if (strcmp(argv[1], "start") == 0) {
            /* local_start() -> wm_start_modules_unless_shutting_down() takes
             * wm_lifecycle_lock. OssecServiceStart() (the SCM-invoked path)
             * initializes it before calling local_start(); this direct CLI
             * path bypasses OssecServiceStart() entirely, so it must
             * initialize the lock itself. wm_lifecycle_lock_init() is
             * idempotent, so this is safe even though it's also called from
             * win_service.c (issue 38428). */
            wm_lifecycle_lock_init();
            return (local_start());
        } else if (strcmp(argv[1], "service-restart") == 0) {
            return run_service_restart();
        } else if (strcmp(argv[1], "/?") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "-h") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "help") == 0) {
            agent_help();
        } else {
            plain_merror("Unknown option: %s", argv[1]);
            exit(1);
        }
    }

    /* Start it */
    if (!os_WinMain(argc, argv)) {
        plain_merror_exit("Unable to start WinMain.");
    }

    return (0);
}

#endif
