/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 17, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __OPTIONS_H
#define __OPTIONS_H

/* Options attributes */
typedef struct _option_t {
    int def;
    int min;
    int max;
} option_t;

/* Syscheck options structure */
typedef struct _syscheck_option_t {
    option_t sleep;
    option_t sleep_after;
    option_t rt_delay;
    option_t max_fd_win_rt;
    option_t max_audit_entries;
    option_t default_max_depth;
    option_t symlink_scan_interval;
    option_t file_max_size;
    option_t log_level;
} syscheck_option_t;

/* Rootcheck options structure */
typedef struct _rootcheck_option_t {
    option_t sleep;
} rootcheck_option_t;

/* SCA options structure */
typedef struct _sca_option_t {
    option_t request_db_interval;
    option_t remote_commands;
    option_t commands_timeout;
} sca_option_t;

/* Remote options structure */
typedef struct _remote_option_t {
    option_t recv_counter_flush;
    option_t comp_average_printout;
    option_t verify_msg_id;
    option_t pass_empty_keyfile;
    option_t sender_pool;
    option_t request_pool;
    option_t request_timeout;
    option_t response_timeout;
    option_t request_rto_sec;
    option_t request_rto_msec;
    option_t max_attempts;
    option_t shared_reload;
    option_t rlimit_nofile;
    option_t recv_timeout;
    option_t send_timeout;
    option_t nocmerged;
    option_t keyupdate_interval;
    option_t worker_pool;
    option_t state_interval;
    option_t guess_agent_group;
    option_t group_data_flush;
    option_t receive_chunk;
    option_t buffer_relax;
    option_t tcp_keepidle;
    option_t tcp_keepintvl;
    option_t tcp_keepcnt;
    option_t log_level;
} remote_option_t;

/* Mail options structure */
typedef struct _mail_option_t {
    option_t strict_checking;
    option_t grouping;
    option_t full_subject;
    option_t geoip;
} mail_option_t;

/* Auth options structure */
typedef struct _auth_option_t {
    option_t timeout_sec;
    option_t timeout_usec;
    option_t log_level;
} auth_option_t;

/* Client buffer options structures */
typedef struct _client_buffer_option_t {
    option_t tolerance;
    option_t min_eps;
    option_t warn_level;
    option_t normal_level;
} client_buffer_option_t;

/* Client options structure */
typedef struct _client_option_t {
    option_t state_interval;
    option_t recv_timeout;
    option_t remote_conf;
    option_t log_level;
    option_t recv_counter_flush;
    option_t comp_average_printout;
    option_t verify_msg_id;
    option_t request_pool;
    option_t request_rto_sec;
    option_t request_rto_msec;
    option_t max_attempts;
} client_option_t;

/* Logcollector options structure */
typedef struct _logcollector_option_t {
    option_t loop_timeout;
    option_t open_attempts;
    option_t remote_commands;
    option_t vcheck_files;
    option_t max_lines;
    option_t max_files;
    option_t sock_fail_time;
    option_t input_threads;
    option_t queue_size;
    option_t sample_log_length;
    option_t rlimit_nofile;
    option_t force_reload;
    option_t reload_interval;
    option_t reload_delay;
    option_t exclude_files_interval;
    option_t log_level;
} logcollector_option_t;

/* Database output options structure */
typedef struct _database_output_option_t {
    option_t reconnect_attempts;
} database_output_option_t;

/* Exec options structure */
typedef struct _exec_option_t {
    option_t request_timeout;
    option_t max_restart_lock;
    option_t log_level;
} exec_option_t;

/* Integrator options structure */
typedef struct _integrator_option_t {
    option_t log_level;
} integrator_option_t;

/* Analysis options structure */
typedef struct _analysis_option_t {
    option_t default_timeframe;
    option_t stats_maxdiff;
    option_t stats_mindiff;
    option_t stats_percent_diff;
    option_t fts_list_size;
    option_t fts_min_size_for_str;
    option_t log_fw;
    option_t decoder_order_size;
    option_t geoip_jsonout;
    option_t label_cache_maxage;
    option_t show_hidden_labels;
    option_t rlimit_nofile;
    option_t min_rotate_interval;
    option_t event_threads;
    option_t syscheck_threads;
    option_t syscollector_threads;
    option_t rootcheck_threads;
    option_t sca_threads;
    option_t hostinfo_threads;
    option_t winevt_threads;
    option_t rule_matching_threads;
    option_t decode_event_queue_size;
    option_t decode_syscheck_queue_size;
    option_t decode_syscollector_queue_size;
    option_t decode_rootcheck_queue_size;
    option_t decode_sca_queue_size;
    option_t decode_hostinfo_queue_size;
    option_t decode_winevt_queue_size;
    option_t decode_output_queue_size;
    option_t archives_queue_size;
    option_t statistical_queue_size;
    option_t alerts_queue_size;
    option_t firewall_queue_size;
    option_t fts_queue_size;
    option_t state_interval;
    option_t log_level;
} analysis_option_t;

/* Wazuh modules options structure */
typedef struct _wazuh_modules_option_t {
    option_t task_nice;
    option_t max_eps;
    option_t kill_timeout;
    option_t log_level;
} wazuh_modules_option_t;

/* Wazuh database options structure */
typedef struct _wazuh_database_option_t {
    option_t sync_agents;
    option_t sync_rootcheck;
    option_t full_sync;
    option_t real_time;
    option_t interval;
    option_t max_queued_events;
} wazuh_database_option_t;

/* Wazuh database options structure */
typedef struct _wazuh_download_option_t {
    option_t enabled;
} wazuh_download_option_t;

/* Wazuh command options structure */
typedef struct _wazuh_command_option_t {
    option_t remote_commands;
} wazuh_command_option_t;

/* Wazuh DB options structure */
typedef struct _wazuh_db_option_t {
    option_t worker_pool_size;
    option_t commit_time;
    option_t open_db_limit;
    option_t rlimit_nofile;
    option_t log_level;
} wazuh_db_option_t;

/* Cluster options structure */
typedef struct _cluster_option_t {
    option_t log_level;
} cluster_option_t;

/* Global options structure */
typedef struct _global_option_t {
    option_t thread_stack_size;
} global_option_t;

typedef struct _monitor_option_t {
    option_t monitor_agents;
    option_t delete_old_agents;
    option_t thread_stack_size;
    option_t log_level;
} monitor_option_t;

/* Options structure */
typedef struct _option_set_t {
    syscheck_option_t syscheck;
    rootcheck_option_t rootcheck;
    sca_option_t sca;
    remote_option_t remote;
    mail_option_t mail;
    auth_option_t auth;
    client_buffer_option_t client_buffer;
    client_option_t client;
    logcollector_option_t logcollector;
    database_output_option_t database_output;
    exec_option_t exec;
    integrator_option_t integrator;
    analysis_option_t analysis;
    wazuh_modules_option_t wazuh_modules;
    wazuh_database_option_t wazuh_database;
    wazuh_download_option_t wazuh_download;
    wazuh_command_option_t wazuh_command;
    wazuh_db_option_t wazuh_db;
    cluster_option_t cluster;
    global_option_t global;
    monitor_option_t monitor;
} option_set_t;

extern const option_set_t options;

#endif
