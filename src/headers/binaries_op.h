/* Copyright (C) 2015, Wazuh Inc.
 * May, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef BINARIES_OP_H
#define BINARIES_OP_H

typedef enum _binary_path_key {
    INITIAL_KEY = 0,
#if defined (__linux__)
    USR_LOCAL_SBIN,
    USR_LOCAL_BIN,
    USR_SBIN,
    USR_BIN,
    SBIN,
    BIN,
    SNAP_BIN,
#elif defined (__MACH__)
    USR_LOCAL_BIN,
    USR_BIN,
    BIN,
    USR_SBIN,
    SBIN,
#elif defined (sun)
    USR_SBIN,
    USR_BIN,
    OPT_CSW_GNU,
    USR_SFW_BIN,
    OPT_CSW_BIN,
#elif defined(FreeBSD)
    SBIN,
    BIN,
    USR_SBIN,
    USR_BIN,
    USR_LOCAL_SBIN,
    USR_LOCAL_BIN,
    ROOT_BIN,
#elif defined(OpenBSD)
    USR_BIN,
    BIN,
    USR_SBIN,
    SBIN,
    USR_LOCAL_BIN,
    USR_LOCAL_SBIN,
#elif defined(NetBSD)
    SBIN,
    BIN,
    USR_SBIN,
    USR_BIN,
    USR_PKG_BIN,
    USR_PKG_SBIN,
    USR_LOCAL_BIN,
#endif
    LAST_KEY
} binary_path_key;

/**
 * @brief Check if the binary exists in the default path and complete the path parameter with the full_path.
 *
 * @param command Command searched for.
 * @param path Variable to be filled with full_path in case of success, or with the original command if it was not found in any path.
 * @retval -1 If it was not found on any path.
 * @retval 0 If it was found.
 */
int get_binary_path(const char *command, char *path);

#endif /* BINARIES_OP_H */
