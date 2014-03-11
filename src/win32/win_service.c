/* @(#) $Id: ./src/win32/win_service.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#ifdef WIN32

#include "shared.h"
#include "os_win.h"
#include <winsvc.h>

#ifndef ARGV0
#define ARGV0 "ossec-agent"
#endif

static LPTSTR g_lpszServiceName        = "OssecSvc";
static LPTSTR g_lpszServiceDisplayName = "OSSEC HIDS";
static LPTSTR g_lpszServiceDescription = "OSSEC HIDS Windows Agent";

static SERVICE_STATUS          ossecServiceStatus;
static SERVICE_STATUS_HANDLE   ossecServiceStatusHandle;

/* ServiceStart */
void WINAPI OssecServiceStart (DWORD argc, LPTSTR *argv);



/* os_start_service: Starts ossec service */
int os_start_service()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;


    /* Start the database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager)
    {
        schService = OpenService(schSCManager,g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if(schService)
        {
            if(StartService(schService, 0, NULL))
            {
                rc = 1;
            }
            else
            {
                if(GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                {
                    rc = -1;
                }
            }

            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    return(rc);
}


/* os_stop_service: Stops ossec service */
int os_stop_service()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;


    /* Stop the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager)
    {
        schService = OpenService(schSCManager,g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if(schService)
        {
            SERVICE_STATUS lpServiceStatus;

            if(ControlService(schService, SERVICE_CONTROL_STOP, &lpServiceStatus))
            {
                rc = 1;
            }

            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    return(rc);
}


/* int CheckServiceRunning(): Checks if service is running. */
int CheckServiceRunning()
{
    int rc = 0;
    SC_HANDLE schSCManager, schService;


    /* Checking service status */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schSCManager)
    {
        schService = OpenService(schSCManager,g_lpszServiceName,
                                 SC_MANAGER_ALL_ACCESS);
        if(schService)
        {
            /* Checking status */
            SERVICE_STATUS lpServiceStatus;

            if(QueryServiceStatus(schService, &lpServiceStatus))
            {
                if(lpServiceStatus.dwCurrentState == SERVICE_RUNNING)
                {
                    rc = 1;
                }
            }
            CloseServiceHandle(schService);
        }

        CloseServiceHandle(schSCManager);
    }

    return(rc);
}


/* int InstallService()
 * Install the OSSEC HIDS agent service.
 */
int InstallService(char *path)
{
    int ret;

    SC_HANDLE schSCManager, schService;
    LPCTSTR lpszBinaryPathName = NULL;
    SERVICE_DESCRIPTION sdBuf;


    /* Uninstall service (if it exists) */
    if (!UninstallService())
    {
        verbose("%s: ERROR: Failure running UninstallService().", ARGV0);
        return(0);
    }


    /* Executable path -- it must be called with the
     * full path
     */
    lpszBinaryPathName = path;

    /* Opening the service database */
    schSCManager = OpenSCManager(NULL,NULL,SC_MANAGER_ALL_ACCESS);

    if (schSCManager == NULL)
    {
        goto install_error;
    }

    /* Creating the service */
    schService = CreateService(schSCManager,
                               g_lpszServiceName,
                               g_lpszServiceDisplayName,
                               SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS,
                               SERVICE_AUTO_START,
                               SERVICE_ERROR_NORMAL,
                               lpszBinaryPathName,
                               NULL, NULL, NULL, NULL, NULL);

    if (schService == NULL)
    {
        CloseServiceHandle(schSCManager);
        goto install_error;
    }

    /* Setting description */
    sdBuf.lpDescription = g_lpszServiceDescription;
    ret = ChangeServiceConfig2(schService, SERVICE_CONFIG_DESCRIPTION, &sdBuf);

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    /* Check for errors */
    if (!ret)
    {
        goto install_error;
    }


    verbose("%s: INFO: Successfully added to the service database.", ARGV0);
    return(1);


    install_error:
    {
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

        verbose("%s: ERROR: Unable to create service entry: %s", ARGV0, (LPCTSTR)lpMsgBuf);
        return(0);
    }
}


/* int UninstallService()
 * Uninstall the OSSEC HIDS agent service.
 */
int UninstallService()
{
    int ret;
    int rc = 0;
    SC_HANDLE schSCManager, schService;
    SERVICE_STATUS lpServiceStatus;


    /* Removing from the service database */
    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if(schSCManager)
    {
        schService = OpenService(schSCManager,g_lpszServiceName,SERVICE_STOP|DELETE);
        if(schService)
        {
            if(CheckServiceRunning())
            {
                verbose("%s: INFO: Found (%s) service is running going to try and stop it.", ARGV0, g_lpszServiceName);
                ret = ControlService(schService, SERVICE_CONTROL_STOP, &lpServiceStatus);
                if(!ret)
                {
                    verbose("%s: ERROR: Failure stopping service (%s) before removing it (%ld).", ARGV0, g_lpszServiceName, GetLastError());
                }
                else
                {
                    verbose("%s: INFO: Successfully stopped (%s).", ARGV0, g_lpszServiceName);
                }
            }
            else
            {
                verbose("%s: INFO: Found (%s) service is not running.", ARGV0, g_lpszServiceName);
                ret = 1;
            }

            if(ret && DeleteService(schService))
            {
                verbose("%s: INFO: Successfully removed (%s) from the service database.", ARGV0, g_lpszServiceName);
                rc = 1;
            }
            CloseServiceHandle(schService);
        }
        else
        {
                verbose("%s: INFO: Service does not exist (%s) nothing to remove.", ARGV0, g_lpszServiceName);
                rc = 1;
        }
        CloseServiceHandle(schSCManager);
    }

    if(!rc)
    {
        verbose("%s: ERROR: Failure removing (%s) from the service database.", ARGV0, g_lpszServiceName);
    }

    return(rc);
}



/** VOID WINAPI OssecServiceCtrlHandler (DWORD dwOpcode)
 * "Signal" handler
 */
VOID WINAPI OssecServiceCtrlHandler(DWORD dwOpcode)
{
    switch(dwOpcode)
    {
        case SERVICE_CONTROL_STOP:
            ossecServiceStatus.dwCurrentState           = SERVICE_STOPPED;
            ossecServiceStatus.dwWin32ExitCode          = 0;
            ossecServiceStatus.dwCheckPoint             = 0;
            ossecServiceStatus.dwWaitHint               = 0;

            verbose("%s: INFO: Received exit signal.", ARGV0);
            SetServiceStatus (ossecServiceStatusHandle, &ossecServiceStatus);
            verbose("%s: INFO: Exiting...", ARGV0);
            return;
        default:
            break;
    }
    return;
}


/** void WinSetError()
 * Sets the error code in the service
 */
void WinSetError()
{
    OssecServiceCtrlHandler(SERVICE_CONTROL_STOP);
}


/** int os_WinMain(int argc, char **argv)
 * Initializes OSSEC dispatcher
 */
int os_WinMain(int argc, char **argv)
{
    SERVICE_TABLE_ENTRY   steDispatchTable[] =
    {
        { g_lpszServiceName, OssecServiceStart },
        { NULL,       NULL                     }
    };

    if(!StartServiceCtrlDispatcher(steDispatchTable))
    {
        verbose("%s: INFO: Unable to set service information.", ARGV0);
        return(1);
    }

    return(1);
}


/** void WINAPI OssecServiceStart (DWORD argc, LPTSTR *argv)
 * Starts OSSEC service
 */
void WINAPI OssecServiceStart (DWORD argc, LPTSTR *argv)
{
    ossecServiceStatus.dwServiceType            = SERVICE_WIN32;
    ossecServiceStatus.dwCurrentState           = SERVICE_START_PENDING;
    ossecServiceStatus.dwControlsAccepted       = SERVICE_ACCEPT_STOP;
    ossecServiceStatus.dwWin32ExitCode          = 0;
    ossecServiceStatus.dwServiceSpecificExitCode= 0;
    ossecServiceStatus.dwCheckPoint             = 0;
    ossecServiceStatus.dwWaitHint               = 0;

    ossecServiceStatusHandle =
        RegisterServiceCtrlHandler(g_lpszServiceName,
                                   OssecServiceCtrlHandler);

    if (ossecServiceStatusHandle == (SERVICE_STATUS_HANDLE)0)
    {
        verbose("%s: INFO: RegisterServiceCtrlHandler failed.", ARGV0);
        return;
    }

    ossecServiceStatus.dwCurrentState = SERVICE_RUNNING;
    ossecServiceStatus.dwCheckPoint = 0;
    ossecServiceStatus.dwWaitHint = 0;

    if (!SetServiceStatus(ossecServiceStatusHandle, &ossecServiceStatus))
    {
        verbose("%s: INFO: SetServiceStatus error.", ARGV0);
        return;
    }


    #ifdef OSSECHIDS
    /* Starting process */
    local_start();
    #endif
}


#endif
/* EOF */
