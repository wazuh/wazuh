/* Copyright (C) 2015, Wazuh Inc.
 * May, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"

const char *binary_path[] = {
#if defined (__linux__)
    [USR_LOCAL_SBIN] = "/usr/local/sbin",
    [USR_LOCAL_BIN] = "/usr/local/bin",
    [USR_SBIN] = "/usr/sbin",
    [USR_BIN] = "/usr/bin",
    [SBIN] = "/sbin",
    [BIN] = "/bin",
    [SNAP_BIN] = "/snap/bin",
#elif defined (__MACH__)
    [USR_LOCAL_BIN] = "/usr/local/bin",
    [USR_BIN] = "/usr/bin",
    [BIN] = "/bin",
    [USR_SBIN] = "/usr/sbin",
    [SBIN] = "/sbin",
#elif defined (sun)
    [USR_SBIN] = "/usr/sbin",
    [USR_BIN] = "/usr/bin",
    [OPT_CSW_GNU] = "/opt/csw/gnu",
    [USR_SFW_BIN] = "/usr/sfw/bin",
    [OPT_CSW_BIN] = "/opt/csw/bin",
#elif defined(FreeBSD)
    [SBIN] = "/sbin",
    [BIN] = "/bin",
    [USR_SBIN] = "/usr/sbin",
    [USR_BIN] = "/usr/bin",
    [USR_LOCAL_SBIN] = "/usr/local/sbin",
    [USR_LOCAL_BIN] = "/usr/local/bin",
    [ROOT_BIN] = "/root/bin",
#elif defined(OpenBSD)
    [USR_BIN] = "/usr/bin",
    [BIN] = "/bin",
    [USR_SBIN] = "/usr/sbin",
    [SBIN] = "/sbin",
    [USR_LOCAL_BIN] = "/usr/local/bin",
    [USR_LOCAL_SBIN] = "/usr/local/sbin",
#elif defined(NetBSD)
    [SBIN] = "/sbin",
    [BIN] = "/bin",
    [USR_SBIN] = "/usr/sbin",
    [USR_BIN] = "/usr/bin",
    [USR_PKG_BIN] = "/usr/pkg/bin",
    [USR_PKG_SBIN] = "/usr/pkg/sbin",
    [USR_LOCAL_BIN] = "/usr/local/bin",
#endif
};

int get_binary_path(const char *command, char *path) {
    char tmp_full_path[PATH_MAX];

    for (int i=INITIAL_KEY + 1; i<LAST_KEY; i++) {
        memset(tmp_full_path, '\0', PATH_MAX);
        snprintf(tmp_full_path, sizeof(tmp_full_path), "%s/%s", binary_path[i], command);
        if (access(tmp_full_path, F_OK) == 0) {
            strcpy(path, tmp_full_path);
            return OS_SUCCESS;
        }
    }

    strcpy(path, command);
    return OS_INVALID;
}
