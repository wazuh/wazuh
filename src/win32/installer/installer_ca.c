/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Custom actions of wazuh-installer.wxs. Native code, so the MSI does not need the VBScript engine. */

#include <windows.h>
#include <msi.h>
#include <msiquery.h>
#include <stdlib.h>
#include "installer_conf.h"

#define CUSTOM_ACTION __declspec(dllexport) UINT __stdcall

static void log_info(MSIHANDLE h, const wchar_t *msg)
{
    MSIHANDLE rec = MsiCreateRecord(0);

    if (rec) {
        MsiRecordSetStringW(rec, 0, msg);
        MsiProcessMessage(h, INSTALLMESSAGE_INFO, rec);
        MsiCloseHandle(rec);
    }
}

static wchar_t *get_property(MSIHANDLE h, const wchar_t *name)
{
    wchar_t empty[1] = L"";
    DWORD n = 0;
    wchar_t *value;
    UINT rc = MsiGetPropertyW(h, name, empty, &n);

    if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS) {
        return NULL;
    }
    if ((value = calloc(++n, sizeof(*value))) && MsiGetPropertyW(h, name, value, &n) != ERROR_SUCCESS) {
        free(value);
        value = NULL;
    }
    return value;
}

/* Runs a System32 tool without a window and waits for it. Its exit code is ignored. */
static void run_hidden(const wchar_t *exe, const wchar_t *args)
{
    wchar_t sysdir[MAX_PATH];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    wchar_t *app;
    wchar_t *cmd;
    UINT n = GetSystemDirectoryW(sysdir, MAX_PATH);

    if (!n || n >= MAX_PATH) {
        return;
    }
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    app = installer_wconcat(sysdir, L"\\", exe, NULL);
    cmd = installer_wconcat(L"\"", sysdir, L"\\", exe, L"\" ", args, NULL);
    if (app && cmd && CreateProcessW(app, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }
    free(cmd);
    free(app);
}

static void set_permissions(const wchar_t *home)
{
    static const struct {
        int in_home;
        const wchar_t *name;
        const wchar_t *args;
    } commands[] = {
        {0, L"", L" /reset /t"},
        {0, L"", L" /inheritancelevel:r /q"},
        {0, L"", L" /grant *S-1-5-32-544:(OI)(CI)F"},
        {0, L"", L" /grant *S-1-5-18:(OI)(CI)F"},
        {0, L"", L"\\* /grant *S-1-5-11:(OI)(CI)RX"},
        {0, L"", L"\\* /grant *S-1-5-11:RX"},
        {0, L"", L" /grant *S-1-5-11:RX"},
        {1, L"*ossec.conf", L" /remove *S-1-5-11 /q"},
        {1, L"client.keys", L" /remove *S-1-5-11 /q"},
        {1, L"authd.pass", L" /remove *S-1-5-11 /q"},
        {1, L"tmp", L" /remove:g *S-1-5-11 /q"},
        {1, L"shared", L" /remove:g *S-1-5-11 /t /c /q"},
    };
    OSVERSIONINFOW version;
    size_t len = wcslen(home);
    wchar_t *dir;
    size_t i;

    ZeroMemory(&version, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    if (!len || (GetVersionExW(&version) && version.dwMajorVersion < 6) || !(dir = installer_wconcat(home, NULL))) {
        return;
    }
    dir[len - 1] = L'\0';

    for (i = 0; i < sizeof(commands) / sizeof(commands[0]); i++) {
        wchar_t *args =
            installer_wconcat(L"\"", commands[i].in_home ? home : dir, commands[i].name, L"\"", commands[i].args, NULL);

        if (args) {
            run_hidden(L"icacls.exe", args);
            free(args);
        }
    }
    free(dir);
}

static int service_running(const wchar_t *name)
{
    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    SERVICE_STATUS status;
    SC_HANDLE service;
    int running = 0;

    if (!scm) {
        return 0;
    }
    if ((service = OpenServiceW(scm, name, SERVICE_QUERY_STATUS))) {
        running = QueryServiceStatus(service, &status) && status.dwCurrentState == SERVICE_RUNNING;
        CloseServiceHandle(service);
    }
    CloseServiceHandle(scm);
    return running;
}

/* NULL-terminated copy of a REG_MULTI_SZ value; *len gets its length in characters. */
static wchar_t *read_multi_sz(HKEY key, const wchar_t *name, size_t *len)
{
    DWORD type;
    DWORD size = 0;
    wchar_t *data;
    LSTATUS rc;
    int tries;

    /* Another process may grow the value between the size query and the read. */
    for (tries = 0; tries < 5; tries++) {
        if (RegQueryValueExW(key, name, NULL, &type, NULL, &size) != ERROR_SUCCESS || type != REG_MULTI_SZ ||
            !(data = calloc(size / sizeof(*data) + 2, sizeof(*data)))) {
            return NULL;
        }
        if ((rc = RegQueryValueExW(key, name, NULL, &type, (LPBYTE)data, &size)) == ERROR_SUCCESS && type == REG_MULTI_SZ) {
            *len = size / sizeof(*data);
            return data;
        }
        free(data);
        if (rc != ERROR_MORE_DATA) {
            break;
        }
    }
    return NULL;
}

CUSTOM_ACTION CheckSvcRunning(MSIHANDLE h)
{
    if (service_running(L"OssecSvc")) {
        MsiSetPropertyW(h, L"OSSECRUNNING", L"Running");
    }
    if (service_running(L"WazuhSvc")) {
        MsiSetPropertyW(h, L"WAZUHRUNNING", L"Running");
    }
    return ERROR_SUCCESS;
}

/* Sets WAZUH_PENDING_CONFLICT to the first pending restart file operation that touches the install folder. */
CUSTOM_ACTION CheckPendingConflict(MSIHANDLE h)
{
    static const wchar_t *const values[] = {L"PendingFileRenameOperations", L"PendingFileRenameOperations2"};
    wchar_t *folder = get_property(h, L"APPLICATIONFOLDER");
    wchar_t *dir = NULL;
    wchar_t *short_dir = NULL;
    HKEY key;
    size_t i;

    if (folder && !*folder) {
        wchar_t *pf = get_property(h, L"ProgramFilesFolder");
        wchar_t *name = get_property(h, L"ApplicationFolderName");

        free(folder);
        folder = pf && name ? installer_wconcat(pf, name, NULL) : NULL;
        free(name);
        free(pf);
    }
    if (!folder) {
        return ERROR_SUCCESS;
    }

    dir = folder[0] && folder[wcslen(folder) - 1] == L'\\' ? installer_wconcat(folder, NULL)
                                                           : installer_wconcat(folder, L"\\", NULL);
    if (dir) {
        DWORD n = GetShortPathNameW(dir, NULL, 0);

        if (n && (short_dir = calloc(n + 1, sizeof(*short_dir))) && !GetShortPathNameW(dir, short_dir, n)) {
            free(short_dir);
            short_dir = NULL;
        }
    }

    if (dir && RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager", 0,
                             KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
        for (i = 0; i < sizeof(values) / sizeof(values[0]); i++) {
            size_t len = 0;
            wchar_t *entries = read_multi_sz(key, values[i], &len);
            const wchar_t *hit = NULL;

            if (entries) {
                if (!(hit = installer_pending_conflict(entries, len, dir)) && short_dir) {
                    hit = installer_pending_conflict(entries, len, short_dir);
                }
                if (hit) {
                    MsiSetPropertyW(h, L"WAZUH_PENDING_CONFLICT", hit);
                }
                free(entries);
            }
            if (hit) {
                break;
            }
        }
        RegCloseKey(key);
    } else if (dir) {
        wchar_t *pending = get_property(h, L"MsiSystemRebootPending");

        if (pending && !wcscmp(pending, L"1")) {
            MsiSetPropertyW(h, L"WAZUH_PENDING_CONFLICT", L"PendingFileRenameOperations");
        }
        free(pending);
    }

    free(short_dir);
    free(dir);
    free(folder);
    return ERROR_SUCCESS;
}

CUSTOM_ACTION InstallerConfig(MSIHANDLE h)
{
    wchar_t *cad = get_property(h, L"CustomActionData");
    wchar_t *home = cad ? installer_cad_field(cad, L"/+/", CAD_HOME_DIR) : NULL;
    UINT rc = ERROR_INSTALL_FAILURE;

    if (home && !installer_config(cad)) {
        set_permissions(home);
        rc = ERROR_SUCCESS;
    } else {
        log_info(h, L"Wazuh: could not write the agent configuration files.");
    }
    free(home);
    free(cad);
    return rc;
}

CUSTOM_ACTION SetWazuhPermissions(MSIHANDLE h)
{
    wchar_t *cad = get_property(h, L"CustomActionData");
    wchar_t *home = cad ? installer_cad_field(cad, L"/+/", CAD_HOME_DIR) : NULL;

    if (home) {
        set_permissions(home);
    }
    free(home);
    free(cad);
    return ERROR_SUCCESS;
}

CUSTOM_ACTION StartWazuhSvc(MSIHANDLE h)
{
    (void)h;
    run_hidden(L"net.exe", L"start WazuhSvc");
    return ERROR_SUCCESS;
}

CUSTOM_ACTION KillGUITask(MSIHANDLE h)
{
    (void)h;
    run_hidden(L"taskkill.exe", L"/f /im win32ui.exe");
    return ERROR_SUCCESS;
}

CUSTOM_ACTION CreateDumpRegistryKey(MSIHANDLE h)
{
    static const wchar_t folder[] = L"%LOCALAPPDATA%\\WazuhCrashDumps";
    DWORD type = 2;
    HKEY key;

    (void)h;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                        L"SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\wazuh-agent.exe", 0, NULL,
                        0, KEY_SET_VALUE | KEY_WOW64_64KEY, NULL, &key, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(key, L"DumpFolder", 0, REG_EXPAND_SZ, (const BYTE *)folder, sizeof(folder));
        RegSetValueExW(key, L"DumpType", 0, REG_DWORD, (const BYTE *)&type, sizeof(type));
        RegCloseKey(key);
    }
    return ERROR_SUCCESS;
}

CUSTOM_ACTION RemoveAll(MSIHANDLE h)
{
    wchar_t *cad = get_property(h, L"CustomActionData");
    wchar_t *home = cad ? installer_cad_field(cad, NULL, 0) : NULL;
    UINT rc = ERROR_SUCCESS;

    if (!home || installer_remove_all(home)) {
        log_info(h, L"Wazuh: could not keep the agent configuration files.");
        rc = ERROR_INSTALL_FAILURE;
    }
    free(home);
    free(cad);
    return rc;
}
