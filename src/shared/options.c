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
    },
    .rootcheck = {
        .sleep = { 50, 0, 1000 }                        // Rootcheck checking/usage speed. The default is to sleep 50 milliseconds per each PID or suspictious port.
    },
    .sca = {
        .request_db_interval = { 5, 0, 60 },            // Security Configuration Assessment DB request interval in minutes. This option sets the maximum waiting time to resend a scan when the DB integrity check fails
        .remote_commands = { 0, 0, 1},                  // Enable it to accept execute commands from SCA policies pushed from the manager in the shared configuration. Local policies ignore this option
        .commands_timeout = { 30, 1, 300}               // Default timeout for executed commands during a SCA scan in seconds
    },
    .remote = {
        .recv_counter_flush = { 128, 10, 999999},
        .comp_average_printout = { 19999, 10, 999999 },
        .verify_msg_id = { 0, 0, 1 },
        .pass_empty_keyfile = { 1, 0, 1 },
        .sender_pool = { 8, 1, 64 },
        .request_pool = { 1024, 1, 4096 },
        .request_timeout = { 10, 1, 600 },
        .response_timeout = { 60, 1, 3600 },
        .request_rto_sec = { 1, 0, 60 },
        .request_rto_msec = { 0, 0, 999 },
        .max_attempts = { 4, 1, 16 },
        .shared_reload = { 10, 1, 18000 },
        .rlimit_nofile = { 65536, 1024, 1048576 },
        .recv_timeout = { 1, 1, 60 },
        .send_timeout = { 1, 1, 60 },
        .nocmerged = { 1, 0, 1 },
        .keyupdate_interval = { 10, 1, 3600 },
        .worker_pool = { 4, 1, 16 },
        .state_interval = { 5, 0, 86400 },
        .guess_agent_group = { 0, 0, 1 },
        .group_data_flush = { 86400, 0, 2592000 },
        .receive_chunk = { 4096, 1024, 16384 },
        .buffer_relax = { 1, 0, 2 },
        .tcp_keepidle = { 30, 1, 7200 },
        .tcp_keepintvl = { 10, 1, 100 },
        .tcp_keepcnt = { 3, 1, 50 },
        .logging = { 0, 0, 2 }
    }
};
