/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef WIN32
#include "shared.h"
#include "rootcheck.h"

#include <tlhelp32.h>
#include <psapi.h>


/* Set Debug privilege
 * See: "How to obtain a handle to any process with SeDebugPrivilege"
 * http://support.microsoft.com/kb/131065/en-us
 */
int os_win32_setdebugpriv(HANDLE h, int en)
{
    TOKEN_PRIVILEGES tp;
    TOKEN_PRIVILEGES tpPrevious;
    LUID luid;
    DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        return (0);
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = 0;

    AdjustTokenPrivileges(h, FALSE, &tp, sizeof(TOKEN_PRIVILEGES),
                          &tpPrevious, &cbPrevious);

    if (GetLastError() != ERROR_SUCCESS) {
        return (0);
    }

    tpPrevious.PrivilegeCount = 1;
    tpPrevious.Privileges[0].Luid = luid;

    /* If en is set to true, we enable the privilege */
    if (en) {
        tpPrevious.Privileges[0].Attributes |= (SE_PRIVILEGE_ENABLED);
    } else {
        tpPrevious.Privileges[0].Attributes ^= (SE_PRIVILEGE_ENABLED &
                                                tpPrevious.Privileges[0].Attributes);
    }

    AdjustTokenPrivileges(h, FALSE, &tpPrevious, cbPrevious, NULL, NULL);
    if (GetLastError() != ERROR_SUCCESS) {
        return (0);
    }

    return (1);
}

/* Get list of win32 processes */
OSList *os_get_process_list()
{
    OSList *p_list = NULL;
    HANDLE hsnap;
    HANDLE hpriv;
    PROCESSENTRY32 p_entry;
    p_entry.dwSize = sizeof(PROCESSENTRY32);

    /* Get token to enable Debug privilege */
    if (!OpenThreadToken(GetCurrentThread(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hpriv)) {
        if (GetLastError() == ERROR_NO_TOKEN) {
            if (!ImpersonateSelf(SecurityImpersonation)) {
                mterror(ARGV0, "os_get_win32_process_list -> ImpersonateSelf");
                return (NULL);
            }

            if (!OpenThreadToken(GetCurrentThread(),
                                 TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                 FALSE, &hpriv)) {
                mterror(ARGV0, "os_get_win32_process_list -> OpenThread");
                return (NULL) ;
            }
        } else {
            mterror(ARGV0, "os_get_win32_process_list -> OpenThread");
            return (NULL);
        }
    }

    /* Enable debug privilege */
    if (!os_win32_setdebugpriv(hpriv, 1)) {
        mterror(ARGV0, "os_win32_setdebugpriv");

        if(CloseHandle(hpriv) == 0) {
            mdebug2("Can't close handle");
        }

        return (NULL);
    }

    /* Make a snapshot of every process */
    hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnap == INVALID_HANDLE_VALUE) {
        mterror(ARGV0, "CreateToolhelp32Snapshot");

        if (CloseHandle(hpriv) == 0) {
            mdebug2("Can't close handle");
        }

        return (NULL);
    }

    /* Get first and second processes -- system entries */
    if (!Process32First(hsnap, &p_entry) && !Process32Next(hsnap, &p_entry )) {
        mterror(ARGV0, "Process32First");

        if (CloseHandle(hsnap) == 0) {
            mdebug2("Can't close handle");
        }

        if (CloseHandle(hpriv) == 0) {
            mdebug2("Can't close handle");
        }

        return (NULL);
    }

    /* Create process list */
    p_list = OSList_Create();
    if (!p_list) {

        if (CloseHandle(hsnap) == 0) {
            mdebug2("Can't close handle");
        }

        if (CloseHandle(hpriv) == 0) {
            mdebug2("Can't close handle");
        }

        mterror(ARGV0, LIST_ERROR);
        return (0);
    }

    /* Get each process name and path */
    while (Process32Next( hsnap, &p_entry)) {
        char *p_name;
        char *p_path;
        Proc_Info *p_info;

        /* Set process name */
        os_strdup(p_entry.szExeFile, p_name);

        /* Get additional information from modules */
        HANDLE hmod = INVALID_HANDLE_VALUE;
        MODULEENTRY32 m_entry;
        m_entry.dwSize = sizeof(MODULEENTRY32);

        /* Snapshot of the process */
        hmod = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, p_entry.th32ProcessID);

        if (hmod == INVALID_HANDLE_VALUE) {
            os_strdup(p_name, p_path);
        } else if (!Module32First(hmod, &m_entry)) {
            /* Get executable path (first entry in the module list) */

            if (CloseHandle(hmod) == 0){
                mdebug2("Can't close handle");
            }

            os_strdup(p_name, p_path);
        }
        else {
            os_strdup(m_entry.szExePath, p_path);

            if (CloseHandle(hmod) == 0) {
                mdebug2("Can't close handle");
            }
        }

        os_calloc(1, sizeof(Proc_Info), p_info);
        p_info->p_name = p_name;
        p_info->p_path = p_path;
        OSList_AddData(p_list, p_info);
    }

    /* Remove debug privileges */
    os_win32_setdebugpriv(hpriv, 0);

    if (CloseHandle(hsnap) == 0) {
        mdebug2("Can't close handle");
    }

    if (CloseHandle(hpriv) == 0) {
        mdebug2("Can't close handle");
    }

    return (p_list);
}

#endif /* WIN32 */
