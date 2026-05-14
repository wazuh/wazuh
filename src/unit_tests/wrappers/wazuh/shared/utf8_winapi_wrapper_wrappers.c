/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef WIN32

#include "utf8_winapi_wrapper_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include "../../common.h"

wchar_t* __wrap_auto_to_wide(const char* input) {
    if (input) {
        check_expected(input);
    }
    return mock_type(wchar_t*);
}

char* __wrap_wide_to_utf8(const wchar_t* input) {
    if (input) {
        check_expected(input);
    }
    return mock_type(char*);
}

char* __wrap_wide_to_ansi(const wchar_t* input) {
    if (input) {
        check_expected(input);
    }
    return mock_type(char*);
}

char* __wrap_auto_to_utf8(const char* input) {
    if (input) {
        check_expected(input);
    }
    return mock_type(char*);
}

char* __wrap_auto_to_ansi(const char* input) {
    if (input) {
        check_expected(input);
    }
    return mock_type(char*);}

int __wrap_utf8_stat64(const char* pathname, struct _stat64* statbuf) {
    struct _stat64 * mock_buf;

    check_expected(pathname);

    mock_buf = mock_type(struct _stat64 *);
    if (mock_buf != NULL) {
        memcpy(statbuf, mock_buf, sizeof(struct _stat64));
    }

    return mock_type(int);
}

HANDLE __wrap_utf8_CreateFile(const char* utf8_path,
                              DWORD access,
                              DWORD share,
                              LPSECURITY_ATTRIBUTES sa,
                              DWORD creation,
                              DWORD flags,
                              HANDLE h_template) {
    if (test_mode) {
        check_expected(utf8_path);
        return mock_type(HANDLE);
    } else {
        return CreateFileA(utf8_path, access, share, sa, creation, flags, h_template);
    }
}

BOOL __wrap_utf8_ReplaceFile(const char* old_name, const char* new_name, const char* backup_name, __attribute__((unused)) DWORD flags) {
    check_expected(old_name);
    check_expected(new_name);
    if (backup_name) {
        check_expected(backup_name);
    }

    return mock_type(BOOL);
}

BOOL __wrap_utf8_DeleteFile(const char* utf8_path) {
    check_expected(utf8_path);

    return mock_type(BOOL);
}

DWORD __wrap_utf8_GetFileAttributes(const char* utf8_path) {
    check_expected(utf8_path);

    return mock_type(DWORD);
}

char* __wrap_utf8_GetShortPathName(const char* utf8_path) {
    check_expected(utf8_path);

    return mock_type(char*);
}

BOOL __wrap_utf8_GetFileSecurity(const char* utf8_path,
                                 __attribute__((unused)) SECURITY_INFORMATION si,
                                 PSECURITY_DESCRIPTOR psd,
                                 DWORD len,
                                 LPDWORD needed) {
    check_expected(utf8_path);

    if(!len) {
        *needed = mock();
    } else {
        PSECURITY_DESCRIPTOR sec_desc = mock_type(PSECURITY_DESCRIPTOR);

        if(sec_desc) {
            memcpy(psd, sec_desc, len);
        }
    }

    return mock_type(BOOL);
}

DWORD __wrap_utf8_GetNamedSecurityInfo(const char* utf8_path,
                                       SE_OBJECT_TYPE obj_type,
                                       SECURITY_INFORMATION si,
                                       __attribute__((unused)) PSID* owner,
                                       __attribute__((unused)) PSID* group,
                                       __attribute__((unused)) PACL* dacl,
                                       PACL* sacl,
                                       PSECURITY_DESCRIPTOR* psd) {
    check_expected(utf8_path);
    check_expected(obj_type);
    check_expected(si);

    *sacl = mock_type(PACL);
    *psd = mock_type(PSECURITY_DESCRIPTOR);

    return mock_type(DWORD);
}

DWORD __wrap_utf8_SetNamedSecurityInfo(const char* utf8_path,
                                       SE_OBJECT_TYPE obj_type,
                                       SECURITY_INFORMATION si,
                                       PSID owner,
                                       PSID group,
                                       PACL dacl,
                                       PACL sacl) {
    check_expected(utf8_path);
    check_expected(obj_type);
    check_expected(si);
    check_expected(owner);
    check_expected(group);
    check_expected(dacl);
    check_expected(sacl);

    return mock_type(DWORD);
}

#endif
