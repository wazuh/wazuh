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
#include "os_win.h"
#include <winsvc.h>
#include "syscheckd/src/db/include/db.h"
#ifndef ARGV0
#define ARGV0 "wazuh-agent"
#endif

/**************************************************************************************
    WARNING: all the logging functions of this file must use the plain_ variant
    to avoid calling any external library that could be loaded before the signature
    verification can be executed in local_start.
**************************************************************************************/

static LPTSTR g_lpszServiceName        = "WazuhSvc";
static LPTSTR g_lpszServiceDisplayName = "Wazuh";
static LPTSTR g_lpszServiceDescription = "Wazuh Windows Agent";

static SERVICE_STATUS          ossecServiceStatus;
static SERVICE_STATUS_HANDLE   ossecServiceStatusHandle;

void WINAPI OssecServiceStart (DWORD argc, LPTSTR *argv);
void wm_kill_children();
extern void stop_wmodules();

/* Start OSSEC-HIDS service */
int os_start_service()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;

    /* Start the database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if (schService) {
            if (StartService(schService, 0, NULL)) {
                rc = 1;
            } else {
                if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
                    rc = -1;
                }
            }

            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    return (rc);
}

/* Stop OSSEC-HIDS service */
int os_stop_service()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;

    /* Stop the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if (schService) {
            SERVICE_STATUS lpServiceStatus;

            if (ControlService(schService, SERVICE_CONTROL_STOP, &lpServiceStatus)) {
                rc = 1;
            }

            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    /*
    * Sleep for a short period of time to avoid possible race-conditions with
    * newer instances of wazuh-agent.
    */
    Sleep(300); //milliseconds

    return (rc);
}

/* Check if the OSSEC-HIDS agent service is running
 * Returns 1 on success (running) or 0 if not running
 */
int CheckServiceRunning()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;

    /* Check service status */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if (schService) {
            /* Check status */
            SERVICE_STATUS lpServiceStatus;

            if (QueryServiceStatus(schService, &lpServiceStatus)) {
                if (lpServiceStatus.dwCurrentState == SERVICE_RUNNING) {
                    rc = 1;
                }
            }
            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    return (rc);
}

/* Install the OSSEC-HIDS agent service */
int InstallService(char *path)
{
    int ret;
    SC_HANDLE schSCManager, schService;
    LPCTSTR lpszBinaryPathName = NULL;
    SERVICE_DESCRIPTION sdBuf;

    /* Uninstall service (if it exists) */
    if (!UninstallService()) {
        plain_merror("Failure running UninstallService().");
        return (0);
    }

    /* Executable path -- it must be called with the full path */
    lpszBinaryPathName = path;

    /* Opening the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);

    if (schSCManager == NULL) {
        goto install_error;
    }

    /* Create the service */
    schService = CreateService(schSCManager,
                               g_lpszServiceName,
                               g_lpszServiceDisplayName,
                               SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS,
                               SERVICE_AUTO_START,
                               SERVICE_ERROR_NORMAL,
                               lpszBinaryPathName,
                               NULL, NULL, NULL, NULL, NULL);

    if (schService == NULL) {
        CloseServiceHandle(schSCManager);
        goto install_error;
    }

    /* Set description */
    sdBuf.lpDescription = g_lpszServiceDescription;
    ret = ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sdBuf);

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    /* Check for errors */
    if (!ret) {
        goto install_error;
    }

    plain_minfo("Successfully added to the service database.");
    return (1);

install_error: {
        char local_msg[1025];
        LPVOID lpMsgBuf;

        memset(local_msg, 0, 1025);

        FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER |
                       FORMAT_MESSAGE_FROM_SYSTEM |
                       FORMAT_MESSAGE_IGNORE_INSERTS,
                       NULL,
                       GetLastError(),
                       MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                       (LPTSTR) &lpMsgBuf,
                       0,
                       NULL);

        plain_merror("Unable to create service entry: %s", (LPCTSTR)lpMsgBuf);
        return (0);
    }
}

/* Uninstall the OSSEC-HIDS agent service */
int UninstallService()
{
    int ret;
    int rc = 0;
    SC_HANDLE schSCManager, schService;
    SERVICE_STATUS lpServiceStatus;

    /* Remove from the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager) {
        schService = OpenService(schSCManager, g_lpszServiceName, SERVICE_STOP | DELETE);
        if (schService) {
            if (CheckServiceRunning()) {
                plain_minfo("Found (%s) service is running going to try and stop it.", g_lpszServiceName);
                ret = ControlService(schService, SERVICE_CONTROL_STOP, &lpServiceStatus);
                if (!ret) {
                    plain_merror("Failure stopping service (%s) before removing it (%ld).", g_lpszServiceName, GetLastError());
                } else {
                    plain_minfo("Successfully stopped (%s).", g_lpszServiceName);
                }
            } else {
                plain_minfo("Found (%s) service is not running.", g_lpszServiceName);
                ret = 1;
            }

            if (ret && DeleteService(schService)) {
                plain_minfo("Successfully removed (%s) from the service database.", g_lpszServiceName);
                rc = 1;
            }
            CloseServiceHandle(schService);
        } else {
            plain_minfo("Service does not exist (%s) nothing to remove.", g_lpszServiceName);
            rc = 1;
        }
        CloseServiceHandle(schSCManager);
    }

    if (!rc) {
        plain_merror("Failure removing (%s) from the service database.", g_lpszServiceName);
    }

    return (rc);
}

/* "Signal" handler */
VOID WINAPI OssecServiceCtrlHandler(DWORD dwOpcode)
{
    if (ossecServiceStatusHandle) {
        switch (dwOpcode) {
            case SERVICE_CONTROL_STOP:
                ossecServiceStatus.dwWin32ExitCode          = 0;
                ossecServiceStatus.dwCheckPoint             = 0;
                ossecServiceStatus.dwWaitHint               = 0;

                plain_minfo("Received exit signal. Starting exit process.");
#ifdef OSSECHIDS
                extern bool is_fim_shutdown;

                ossecServiceStatus.dwCurrentState           = SERVICE_STOP_PENDING;
                SetServiceStatus (ossecServiceStatusHandle, &ossecServiceStatus);
                plain_minfo("Set pending exit signal.");

                // Kill children processes spawned by modules, only in wazuh-agent
                wm_kill_children();
                stop_wmodules();
                is_fim_shutdown = true;
                fim_db_teardown();
#endif
                ossecServiceStatus.dwCurrentState           = SERVICE_STOPPED;
                SetServiceStatus (ossecServiceStatusHandle, &ossecServiceStatus);
                plain_minfo("Exit completed successfully.");
                break;
        }
    }
}

/* Set the error code in the service */
void WinSetError()
{
    OssecServiceCtrlHandler(SERVICE_CONTROL_STOP);
}

/* Initialize OSSEC-HIDS dispatcher */
int os_WinMain(__attribute__((unused)) int argc, __attribute__((unused)) char **argv)
{
    SERVICE_TABLE_ENTRY   steDispatchTable[] = {
        { g_lpszServiceName, OssecServiceStart },
        { NULL,       NULL                     }
    };

    if (!StartServiceCtrlDispatcher(steDispatchTable)) {
        plain_minfo("Unable to set service information.");
        return (1);
    }

    return (1);
}

/* Start OSSEC service */
void WINAPI OssecServiceStart (__attribute__((unused)) DWORD argc, __attribute__((unused)) LPTSTR *argv)
{
    ossecServiceStatus.dwServiceType            = SERVICE_WIN32;
    ossecServiceStatus.dwCurrentState           = SERVICE_START_PENDING;
    ossecServiceStatus.dwControlsAccepted       = SERVICE_ACCEPT_STOP;
    ossecServiceStatus.dwWin32ExitCode          = 0;
    ossecServiceStatus.dwServiceSpecificExitCode = 0;
    ossecServiceStatus.dwCheckPoint             = 0;
    ossecServiceStatus.dwWaitHint               = 0;

    ossecServiceStatusHandle =
        RegisterServiceCtrlHandler(g_lpszServiceName,
                                   OssecServiceCtrlHandler);

    if (ossecServiceStatusHandle == (SERVICE_STATUS_HANDLE)0) {
        plain_minfo("RegisterServiceCtrlHandler failed.");
        return;
    }

    ossecServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ossecServiceStatus.dwCheckPoint = 0;
    ossecServiceStatus.dwWaitHint = 0;

    if (!SetServiceStatus(ossecServiceStatusHandle, &ossecServiceStatus)) {
        plain_minfo("SetServiceStatus error.");
        return;
    }

#ifdef OSSECHIDS
    /* Start process */
    local_start();
#endif
}

int service_reload(HWND hwnd) {
#ifdef OSSECHIDS
    if (local_reload() == 0) {
        MessageBox(hwnd, "Reload successful.", "Reload Success", MB_OK | MB_ICONINFORMATION);
        return 1;
    } else {
        MessageBox(hwnd, "Failed to reload.", "Reload Error", MB_OK | MB_ICONERROR);
        return -1;
    }
#endif
}

#endif /* WIN32 */
