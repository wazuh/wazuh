/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 17, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#include "options.h"

const option_set_t options = {
    .syscheck = {
        /* Syscheck checking/usage speed. To avoid large cpu/memory usage, you can specify how much to sleep after generating
        the checksum of X files. The default is to sleep one second per 100 files read. */
        .sleep = {
            .def = 1,
            .min = 0,
            .max = 64
        },
        .sleep_after = { 100, 1, 99999 },
        .rt_delay = { 10, 1, 1000 },                    // Syscheck perform a delay when dispatching real-time notifications so it avoids triggering on some temporary files like vim edits. (ms)
        .max_fd_win_rt = { 256, 1, 1024 },              // Maximum number of directories monitored for realtime on windows
        .max_audit_entries = { 256, 1, 4096 },          // Maximum number of directories monitored for who-data on Linux
        .default_max_depth = { 256, 1, 320 },           // Maximum level of recursivity allowed
        .symlink_scan_interval = { 600, 1, 2592000 },   // Check interval of the symbolic links configured in the directories section
        .file_max_size = { 1024, 0, 4095 },             // Maximum file size for calcuting integrity hashes in MBytes
        .logging = { 0, 0, 2 }                          // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Syscheck (local, server and Unix agent).
    }
};
