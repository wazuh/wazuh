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
#include <limits.h>
#include "logcollector/logcollector.h"
#include "analysisd/analysisd.h"

const option_set_t options = {
    .syscheck = {
        /* Syscheck checking/usage speed. To avoid large cpu/memory usage, you can specify how much to sleep after generating
        the checksum of X files. The default is to sleep one second per 100 files read. */
        .sleep = {
            .def = 1,
            .min = 0,
            .max = 64
        },
        .sleep_after = { 100, 1, 9999 },
        .rt_delay = { 10, 1, 1000 },                                            // Syscheck perform a delay when dispatching real-time notifications so it avoids triggering on some temporary files like vim edits (ms)
        .max_fd_win_rt = { 256, 1, 1024 },                                      // Maximum number of directories monitored for realtime on windows
        .max_audit_entries = { 256, 1, 4096 },                                  // Maximum number of directories monitored for who-data on Linux
        .default_max_depth = { 256, 1, 320 },                                   // Maximum level of recursivity allowed
        .symlink_scan_interval = { 600, 1, 2592000 },                           // Check interval of the symbolic links configured in the directories section
        .file_max_size = { 1024, 0, 4095 },                                     // Maximum file size for calcuting integrity hashes in MBytes
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Syscheck (local, server and Unix agent)
    },
    .rootcheck = {
        .sleep = { 50, 0, 1000 }                                                // Rootcheck checking/usage speed. The default is to sleep 50 milliseconds per each PID or suspicious port
    },
    .sca = {
        .request_db_interval = { 5, 1, 60 },                                    // Security Configuration Assessment DB request interval in minutes. This option sets the maximum waiting time to resend a scan when the DB integrity check fails
        .remote_commands = { 0, 0, 1},                                          // Enable it to accept execute commands from SCA policies pushed from the manager in the shared configuration. Local policies ignore this option
        .commands_timeout = { 30, 1, 300}                                       // Default timeout for executed commands during a SCA scan in seconds
    },
    .remote = {
        .recv_counter_flush = { 128, 10, 999999},                               // Remoted counter io flush
        .comp_average_printout = { 19999, 10, 999999 },                         // Remoted compression averages printout
        .verify_msg_id = { 0, 0, 1 },                                           // Verify msg id (set to 0 to disable it)
        .pass_empty_keyfile = { 1, 0, 1 },                                      // Don't exit when client.keys empty
        .sender_pool = { 8, 1, 64 },                                            // Number of shared file sender threads
        .request_pool = { 1024, 1, 4096 },                                      // Limit of parallel request dispatchers
        .request_timeout = { 10, 1, 600 },                                      // Timeout to reject a new request (seconds)
        .response_timeout = { 60, 1, 3600 },                                    // Timeout for request responses (seconds)
        .request_rto_sec = { 1, 0, 60 },                                        // Retransmission timeout seconds
        .request_rto_msec = { 0, 0, 999 },                                      // Retransmission timeout milliseconds
        .max_attempts = { 4, 1, 16 },                                           // Max. number of sending attempts
        .shared_reload = { 10, 1, 18000 },                                      // Shared files reloading interval (sec)
        .rlimit_nofile = { 65536, 1024, 1048576 },                              // Maximum number of file descriptor that Remoted can open
        .recv_timeout = { 1, 1, 60 },                                           // Maximum time waiting for a client response in TCP (seconds)
        .send_timeout = { 1, 1, 60 },                                           // Maximum time waiting for a client delivery in TCP (seconds)
        .nocmerged = { 1, 0, 1 },                                               // Merge shared configuration to be broadcasted to agents
        .keyupdate_interval = { 10, 1, 3600 },                                  // Keys file reloading latency (seconds)
        .worker_pool = { 4, 1, 16 },                                            // Number of parallel worker threads
        .state_interval = { 5, 0, 86400 },                                      // Interval for remoted status file updating (seconds). 0 means disabled
        .guess_agent_group = { 0, 0, 1 },                                       // Guess the group to which the agent belongs (0. No, do not guess (default), 1. Yes, do guess)
        .group_data_flush = { 86400, 0, 2592000 },                              // Cleans residual data from unused groups/multigroups. Minimum number of seconds between cleanings. 0 means never clean up residual data
        .receive_chunk = { 4096, 1024, 16384 },                                 // Receiving chunk size for TCP. We suggest using powers of two
        .buffer_relax = { 1, 0, 2 },                                            // Deallocate network buffers after usage (0. Do not deallocate memory, 1. Shrink memory to the reception chunk, 2. Full memory deallocation)
        .tcp_keepidle = { 30, 1, 7200 },                                        // Time (in seconds) the connection needs to remain idle before TCP starts sending keepalive probes
        .tcp_keepintvl = { 10, 1, 100 },                                        // The time (in seconds) between individual keepalive probes
        .tcp_keepcnt = { 3, 1, 50 },                                            // Maximum number of keepalive probes TCP should send before dropping the connection
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Remoted (server debug)
    },
    .mail = {
        .strict_checking = { 1, 0, 1 },                                         // Maild strict checking (0=disabled, 1=enabled)
        .grouping = { 1, 0, 1 },                                                // Maild grouping (0=disabled, 1=enabled). Groups alerts within the same e-mail.
        .full_subject = { 0, 0, 1 },                                            // Maild full subject (0=disabled, 1=enabled)
        .geoip = { 1, 0, 1 }                                                    // Maild display GeoIP data (0=disabled, 1=enabled)
    },
    .auth = {
        .timeout_sec = { 1, 0, INT_MAX },                                       // Network timeout for Authd clients
        .timeout_usec = { 0, 0, 999999},                                        // Network timeout for Authd clients
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Auth daemon debug (server)
    },
    .client_buffer = {
        .tolerance = { 15, 0, 600 },                                            // Time since the agent buffer is full to consider events flooding
        .min_eps = { 50, 1, 1000 },                                             // Minimum events per second, configurable at XML settings
        .warn_level = { 90, 1, 100 },                                           // Level of occupied capacity in Agent buffer to trigger a warning message
        .normal_level = { 70, 0, 99 }                                           // Level of occupied capacity in Agent buffer to come back to normal state
    },
    .client = {
        .state_interval = { 5, 0, 86400 },                                      // Interval for agent status file updating (seconds). 0 means disabled
        .recv_timeout = { 60, 1, 600 },                                         // Maximum time waiting for a server response in TCP (seconds)
        .remote_conf = { 1, 0, 1 },                                             // Apply remote configuration. (0. Disabled, 1. Enabled)
        .log_level = { 0, 0, 2 },                                               // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Unix agentd
        .recv_counter_flush = { 128, 10, 999999},                               // Remoted counter io flush
        .comp_average_printout = { 19999, 10, 999999 },                         // Remoted compression averages printout
        .verify_msg_id = { 0, 0, 1 },                                           // Verify msg id (set to 0 to disable it)
        .request_pool = { 1024, 1, 4096 },                                      // Limit of parallel request dispatchers
        .request_rto_sec = { 1, 0, 60 },                                        // Retransmission timeout seconds
        .request_rto_msec = { 0, 0, 999 },                                      // Retransmission timeout milliseconds
        .max_attempts = { 4, 1, 16 },                                           // Max. number of sending attempts
    },
    .logcollector = {
        .loop_timeout = { 2, 1, 120 },                                          // Logcollector file loop timeout
        .open_attempts = { 8, 0, 998 },                                         // Logcollector number of attempts to open a log file
        .remote_commands = { 0, 0, 1 },                                         // Logcollector - If it should accept remote commands from the manager
        .vcheck_files = { 64, 0, 1024 },                                        // Logcollector - File checking interval (seconds)
        .max_lines = { 10000, 0, 1000000 },                                     // Logcollector - Maximum number of lines to read from the same file. 0. Disable line burst limitation
        .max_files = { 1000, 1, 100000 },                                       // Logcollector - Maximum number of files to be monitored
        .sock_fail_time = { 300, 1, 3600 },                                     // Time to reattempt a socket connection after a failure
        .input_threads = { 4, N_MIN_INPUT_THREADS, 128 },                       // Logcollector - Number of input threads for reading files
        .queue_size = { 1024, OUTPUT_MIN_QUEUE_SIZE, 220000 },                  // Logcollector - Output queue size
        .sample_log_length = { 64, 1, 4096 },                                   // Sample log length limit for errors about large message
        .rlimit_nofile = { 1100, 1024, 1048576 },                               // Maximum number of file descriptor that Logcollector can open. This value must be higher than logcollector.max_files
        .force_reload = { 0, 0, 1 },                                            // Force file handler reloading: close and reopen monitored files
        .reload_interval = { 64, 1, 86400 },                                    // File reloading interval, in seconds, if force_reload=1. This interval must be greater or equal than vcheck_files
        .reload_delay = { 1000, 0, 30000 },                                     // File reloading delay (between close and open), in milliseconds
        .exclude_files_interval = { 86400, 1, 172800 },                         // Excluded files refresh interval, in seconds
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Log collector (server, local or Unix agent)
    },
    .database_output = {
        .reconnect_attempts = { 10, 1, 9999 }                                   // Database - maximum number of reconnect attempts
    },
    .exec = {
        .request_timeout = { 60, 1, 3600 },                                     // Timeout to execute remote requests
        .max_restart_lock = { 600, 0, 3600 },                                   // Max timeout to lock the restart
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Exec daemon debug (server, local or Unix agent)
    },
    .integrator = {
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging).Integrator daemon debug (server, local or Unix agent)
    },
    .analysis = {
        .default_timeframe = { 360, 60, 3600 },                                 // Analysisd default rule timeframe
        .stats_maxdiff = { 999000, 10, 999999 },                                // Analysisd stats maximum diff
        .stats_mindiff = { 1250, 10, 999999 },                                  // Analysisd stats minimum diff
        .stats_percent_diff = { 150, 5, 9999 },                                 // Analysisd stats percentage (how much to differ from average)
        .fts_list_size = { 32, 12, 512 },                                       // Analysisd FTS list size
        .fts_min_size_for_str = { 14, 6, 128 },                                 // Analysisd FTS minimum string size
        .log_fw = { 1, 0, 1 },                                                  // Analysisd Enable the firewall log (at logs/firewall/firewall.log)
        .decoder_order_size = { 256, MIN_ORDER_SIZE, MAX_DECODER_ORDER_SIZE },  // Maximum number of fields in a decoder (order tag)
        .geoip_jsonout = { 0, 0, 1 },                                           // Output GeoIP data at JSON alerts
        .label_cache_maxage = { 1, 0, 60 },                                     // Maximum label cache age (margin seconds with no reloading)
        .show_hidden_labels = { 0, 0, 1 },                                      // Show hidden labels on alerts
        .rlimit_nofile = { 65536, 1024, 1048576 },                              // Maximum number of file descriptor that Analysisd can open
        .min_rotate_interval = { 600, 10, 86400 },                              // Minimum output rotate interval. This limits rotation by time and size
        .event_threads = { 0, 0, 32 },                                          // Number of event decoder threads
        .syscheck_threads = { 0, 0, 32 },                                       // Number of syscheck decoder threads
        .syscollector_threads = { 0, 0, 32 },                                   // Number of syscollector decoder threads
        .rootcheck_threads = { 0, 0, 32 },                                      // Number of rootcheck decoder threads
        .sca_threads = { 0, 0, 32 },                                            // Number of security configuration assessment decoder threads
        .hostinfo_threads = { 0, 0, 32 },                                       // Number of hostinfo decoder threads
        .winevt_threads = { 0, 0, 32 },                                         // Number of Windows event decoder threads
        .rule_matching_threads = { 0, 0, 32 },                                  // Number of rule matching threads
        .decode_event_queue_size = { 16384, 128, 2000000 },                     // Decoder event queue size
        .decode_syscheck_queue_size = { 16384, 128, 2000000 },                  // Decoder syscheck queue size
        .decode_syscollector_queue_size = { 16384, 128, 2000000 },              // Decoder syscollector queue size
        .decode_rootcheck_queue_size = { 16384, 128, 2000000 },                 // Decoder rootcheck queue size
        .decode_sca_queue_size = { 16384, 128, 2000000 },                       // Decoder security configuration assessment decoder queue size
        .decode_hostinfo_queue_size = { 16384, 128, 2000000 },                  // Decoder hostinfo queue size
        .decode_winevt_queue_size = { 16384, 128, 2000000 },                    // Decoder Windows event queue size
        .decode_output_queue_size = { 16384, 128, 2000000 },                    // Decoder Output queue size
        .archives_queue_size = { 16384, 128, 2000000 },                         // Archives log queue size
        .statistical_queue_size = { 16384, 128, 2000000 },                      // Statistical log queue size
        .alerts_queue_size = { 16384, 128, 2000000 },                           // Alerts log queue size
        .firewall_queue_size = { 16384, 128, 2000000 },                         // Firewall log queue size
        .fts_queue_size = { 16384, 128, 2000000 },                              // FTS log queue size
        .state_interval = { 5, 0, 86400 },                                      // Interval for analysisd status file updating (seconds). 0 means disabled
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Analysisd (server or local)
    },
    .wazuh_modules = {
        .task_nice = { 10, -20, 19 },                                           // Nice value for tasks. Lower value means higher priority
        .max_eps = { 100, 1, 1000 },                                            // Maximum number of events per second sent by each module
        .kill_timeout = { 10, 0, 3600 },                                        // Time for a process to quit before killing it
        .log_level = { 0, 0, 2 }                                                // Debug options (0: no debug, 1: first level of debug, 2: full debugging). Wazuh modules (server, local or Unix agent)
    },
    .wazuh_database = {
        .sync_agents = { 1, 0, 1 },                                             // Synchronize agent database with client.keys
        .sync_rootcheck = { 1, 0, 1 },                                          // Synchronize policy monitoring data with Rootcheck database
        .full_sync = { 0, 0, 1 },                                               // Full data synchronization (0. Synchronize only new events, Synchronize complete Syscheck/Rootcheck database (warning: this could take so much time))
        .real_time = { 1, 0, 1 },                                               // Sync data in real time (supported on Linux only)
        .interval = { 60, 0, 86400 },                                           // Time interval between cycles (used only if real time disabled)
        .max_queued_events = { 0, 0, INT_MAX },                                 // Maximum queued events (for inotify) (0. Use system default)
    },
    .wazuh_download = {
        .enabled = { 1, 0, 1 }                                                  // Enable download module
    },
    .wazuh_command = {
        .remote_commands = { 0, 0, 1 }                                          // If it should accept remote commands from the manager
    },
    .wazuh_db = {
        .worker_pool_size = { 8, 1, 32 },                                       // Number of worker threads
        .commit_time = { 60, 10, 3600 },                                        // Time margin before committings
        .open_db_limit = { 64, 1, 4096 },                                       // Number of allowed open databases before closing
        .rlimit_nofile = { 65536, 1024, 1048576 },                              // Maximum number of file descriptor that WazuhDB can open
        .log_level = { 0, 0, 2 }                                                // Wazuh DB debug level
    },
    .cluster = { 
        .log_level = { 0, 0, 2 }                                                // Wazuh Cluster debug level+
    },
    .global = { 
        .thread_stack_size = { 8192, 2048, 65536 }                               // Wazuh default stack size for child threads in KiB
    },
    .monitor = {
        .monitor_agents = { 1, 0, 1},                                            // Check and update agents' status
        .delete_old_agents = { 0, 0, 256 },                                       // Delete disconnected agents for this value (minutes)
        .log_level = { 0, 0, 2 }                                                 // Monitord debug level
    }
};
