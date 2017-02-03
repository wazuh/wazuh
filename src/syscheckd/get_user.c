/*
 * Copyright (C) 2016 Wazuh Inc.
 * July 07, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

const char* get_user(__attribute__((unused)) const char *path, int uid) {
    struct passwd *user = getpwuid(uid);
    return user ? user->pw_name : "";
}

const char* get_group(int gid) {
    struct group *group = getgrgid(gid);
    return group ? group->gr_name : "";
}

#else

#include "shared.h"
#include "aclapi.h"

#define BUFFER_LEN 1024

const char *get_user(const char *path, __attribute__((unused)) int uid)
{
    DWORD dwRtnCode = 0;
    PSID pSidOwner = NULL;
    BOOL bRtnBool = TRUE;
    static char AcctName[BUFFER_LEN];
    char DomainName[BUFFER_LEN];
    DWORD dwAcctName = BUFFER_LEN;
    DWORD dwDomainName = BUFFER_LEN;
    SID_NAME_USE eUse = SidTypeUnknown;
    HANDLE hFile;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Get the handle of the file object.
    hFile = CreateFile(
                       TEXT(path),
                       GENERIC_READ,
                       FILE_SHARE_READ | FILE_SHARE_WRITE,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

    // Check GetLastError for CreateFile error code.
    if (hFile == INVALID_HANDLE_VALUE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();

        switch (dwErrorCode) {
        case ERROR_SHARING_VIOLATION: // 32
            debug1("%s: DEBUG: CreateFile (%s) error = %lu", ARGV0, path, dwErrorCode);
            break;
        default:
            merror("%s: ERROR: CreateFile (%s) error = %lu", ARGV0, path, dwErrorCode);
        }

        return "";
    }

    // Get the owner SID of the file.
    dwRtnCode = GetSecurityInfo(
                                hFile,
                                SE_FILE_OBJECT,
                                OWNER_SECURITY_INFORMATION,
                                &pSidOwner,
                                NULL,
                                NULL,
                                NULL,
                                &pSD);

    CloseHandle(hFile);

    // Check GetLastError for GetSecurityInfo error condition.
    if (dwRtnCode != ERROR_SUCCESS) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();
        merror("%s: ERROR: GetSecurityInfo error = %lu", ARGV0, dwErrorCode);
        return "";
    }

    // Second call to LookupAccountSid to get the account name.
    bRtnBool = LookupAccountSid(
                                NULL,                   // name of local or remote computer
                                pSidOwner,              // security identifier
                                AcctName,               // account name buffer
                                (LPDWORD)&dwAcctName,   // size of account name buffer
                                DomainName,             // domain name
                                (LPDWORD)&dwDomainName, // size of domain name buffer
                                &eUse);                 // SID type

    // Check GetLastError for LookupAccountSid error condition.
    if (bRtnBool == FALSE) {
        DWORD dwErrorCode = 0;

        dwErrorCode = GetLastError();

        if (dwErrorCode == ERROR_NONE_MAPPED)
            debug1("%s: DEBUG: Account owner not found for file '%s'", ARGV0, path);
        else
            merror("%s: ERROR: Error in LookupAccountSid.", ARGV0);

        return "";
    }

    return AcctName;
}

const char *get_group(__attribute__((unused)) int gid) {
    return "";
}

#endif
