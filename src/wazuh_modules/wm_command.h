/*
 * Wazuh Module for custom command execution
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October 26, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_COMMAND_H
#define WM_COMMAND_H

#define WM_COMMAND_LOGTAG ARGV0 ":command"
#define WM_COMMAND_DEFAULT_INTERVAL 2

typedef struct wm_command_state_t {
    time_t next_time;               // Absolute time for next scan
} wm_command_state_t;

typedef struct wm_command_t {
    char * tag;
    char * command;
    char * full_command;
    unsigned long interval;
    char *md5_hash;
    char *sha1_hash;
    char *sha256_hash;
    int queue_fd;
    wm_command_state_t state;
    unsigned int enabled:1;
    unsigned int run_on_start:1;
    unsigned int ignore_output:1;
    unsigned int agent_cfg:1;
    unsigned int skip_verification:1;
    int timeout;
} wm_command_t;

extern const wm_context WM_COMMAND_CONTEXT;   // Context

// Parse XML
int wm_command_read(xml_node **nodes, wmodule *module, int agent_cfg);

#endif // WM_COMMAND_H
