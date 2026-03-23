/*
 * Shared functions for Rootcheck events decoding
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "os_utils.h"

#ifdef WIN32
#include <tlhelp32.h>
#include <psapi.h>
#include <windows.h>
#endif

#ifndef WIN32

char *w_os_get_runps(const char *ps, int mpid)
{
    char *tmp_str, *nbuf;
    char buf[OS_SIZE_2048 + 1];
    char command[OS_SIZE_1024 + 1];
    FILE *fp;

    buf[0] = '\0';
    command[0] = '\0';
    command[OS_SIZE_1024] = '\0';

    snprintf(command, OS_SIZE_1024, "%s -p %d 2> /dev/null", ps, mpid);
    fp = popen(command, "r");
    if (fp) {
        while (fgets(buf, OS_SIZE_2048, fp) != NULL) {
            tmp_str = strchr(buf, ':');
            if (!tmp_str) {
                continue;
            }

            nbuf = tmp_str++;

            tmp_str = strchr(nbuf, ' ');
            if (!tmp_str) {
                continue;
            }
            tmp_str++;

            /* Remove whitespaces */
            while (*tmp_str == ' ') {
                tmp_str++;
            }

            nbuf = tmp_str;

            tmp_str = strchr(nbuf, '\n');
            if (tmp_str) {
                *tmp_str = '\0';
            }

            pclose(fp);
            return (strdup(nbuf));
        }

        pclose(fp);
    }

    return (NULL);
}

/* Get list of Unix processes */
OSList *w_os_get_process_list()
{
    int i = 1;
    pid_t max_pid = MAX_PID;
    OSList *p_list = NULL;
    char ps[OS_SIZE_1024 + 1];

    /* Check where ps is */
    memset(ps, '\0', OS_SIZE_1024 + 1);
    strncpy(ps, "/bin/ps", OS_SIZE_1024);
    if (!w_is_file(ps)) {
        strncpy(ps, "/usr/bin/ps", OS_SIZE_1024);
        if (!w_is_file(ps)) {
            mterror(ARGV0, "'ps' not found.");
            return (NULL);
        }
    }

    /* Create process list */
    p_list = OSList_Create();
    if (!p_list) {
        mterror(ARGV0, LIST_ERROR);
        return (NULL);
    }

    for (i = 1; i <= max_pid; i++) {
        /* Check if the pid is present */
        if ((!((getsid(i) == -1) && (errno == ESRCH))) &&
                (!((getpgid(i) == -1) && (errno == ESRCH)))) {
            W_Proc_Info *p_info;
            char *p_name;

            p_name = w_os_get_runps(ps, (int)i);
            if (!p_name) {
                continue;
            }

            os_calloc(1, sizeof(W_Proc_Info), p_info);
            p_info->p_path = p_name;
            p_info->p_name = NULL;
            OSList_AddData(p_list, p_info);
        }
    }

    return (p_list);
}

#endif
/* Check if a file exists */
int w_is_file(const char * const file) {
    FILE *fp = wfopen(file, "r");
    int is_exist = 0;
    if (fp != NULL) {
        is_exist = 1;
        fclose(fp);
    }
    return is_exist;
}

/* Delete the process list */
int w_del_plist(OSList *p_list)
{
    OSListNode *l_node;
    OSListNode *p_node = NULL;

    if (p_list == NULL) {
        return (0);
    }

    l_node = OSList_GetFirstNode(p_list);
    while (l_node) {
        W_Proc_Info *pinfo;

        pinfo = (W_Proc_Info *)l_node->data;

        if (pinfo->p_name) {
            free(pinfo->p_name);
        }

        if (pinfo->p_path) {
            free(pinfo->p_path);
        }

        free(l_node->data);

        if (p_node) {
            free(p_node);
            p_node = NULL;
        }
        p_node = l_node;

        l_node = OSList_GetNextNode(p_list);
    }

    if (p_node) {
        free(p_node);
        p_node = NULL;
    }

    pthread_mutex_destroy(&(p_list->mutex));
    pthread_rwlock_destroy(&(p_list->wr_mutex));

    free(p_list);

    return (1);
}

#ifdef WIN32

/* Set Debug privilege
 * See: "How to obtain a handle to any process with SeDebugPrivilege"
 * http://support.microsoft.com/kb/131065/en-us
 */
int w_os_win32_setdebugpriv(HANDLE h, int en)
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
OSList *w_os_get_process_list()
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
    if (!w_os_win32_setdebugpriv(hpriv, 1)) {
        mterror(ARGV0, "w_os_win32_setdebugpriv");
        CloseHandle(hpriv);
        return (NULL);
    }

    /* Make a snapshot of every process */
    hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hsnap == INVALID_HANDLE_VALUE) {
        mterror(ARGV0, "CreateToolhelp32Snapshot");
        return (NULL);
    }

    /* Get first and second processes -- system entries */
    if (!Process32First(hsnap, &p_entry) && !Process32Next(hsnap, &p_entry )) {
        mterror(ARGV0, "Process32First");
        CloseHandle(hsnap);
        return (NULL);
    }

    /* Create process list */
    p_list = OSList_Create();
    if (!p_list) {
        CloseHandle(hsnap);
        mterror(ARGV0, LIST_ERROR);
        return (0);
    }

    /* Get each process name and path */
    while (Process32Next( hsnap, &p_entry)) {
        char *p_name;
        char *p_path;
        W_Proc_Info *p_info;

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
            CloseHandle(hmod);
            os_strdup(p_name, p_path);
        } else {
            os_strdup(m_entry.szExePath, p_path);
            CloseHandle(hmod);
        }

        os_calloc(1, sizeof(W_Proc_Info), p_info);
        p_info->p_name = p_name;
        p_info->p_path = p_path;
        OSList_AddData(p_list, p_info);
    }

    /* Remove debug privileges */
    w_os_win32_setdebugpriv(hpriv, 0);

    CloseHandle(hsnap);
    return (p_list);
}

typedef BOOL (WINAPI *LPFN_WOW64DISABLEWOW64FSREDIRECTION)(PVOID *OldValue);

void SafeWow64DisableWow64FsRedirection(PVOID *oldValue) {
    LPFN_WOW64DISABLEWOW64FSREDIRECTION Wow64DisableWow64FsRedirection = NULL;
    HMODULE kernel32 = GetModuleHandle(TEXT("kernel32.dll"));
    if (kernel32) {
        Wow64DisableWow64FsRedirection = (LPFN_WOW64DISABLEWOW64FSREDIRECTION)GetProcAddress(kernel32, "Wow64DisableWow64FsRedirection");
    }
    if (Wow64DisableWow64FsRedirection) {
        // The Wow64DisableWow64FsRedirection function is supported
        Wow64DisableWow64FsRedirection(oldValue);
    }
}

#endif
