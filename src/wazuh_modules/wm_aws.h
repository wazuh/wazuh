/*
 * Wazuh Module for AWS CloudTrail integration
 * Copyright (C) 2017 Wazuh Inc.
 * January 08, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AWS_H
#define WM_AWS_H

#define WM_AWS_LOGTAG ARGV0 ":aws-cloudtrail"
#define WM_AWS_DEFAULT_INTERVAL 1
#define WM_AWS_DEFAULT_DIR WM_DEFAULT_DIR "/aws"
#define WM_AWS_SCRIPT_PATH WM_AWS_DEFAULT_DIR "/aws.py"

typedef struct wm_aws_state_t {
    time_t next_time;               // Absolute time for next scan
} wm_aws_state_t;

typedef struct wm_aws_t {
    char * bucket;
    char * access_key;
    char * secret_key;
    unsigned long interval;
    int queue_fd;
    wm_aws_state_t state;
    unsigned int enabled:1;
    unsigned int run_on_start:1;
    unsigned int remove_from_bucket:1;
    unsigned int agent_cfg:1;
} wm_aws_t;

extern const wm_context WM_AWS_CONTEXT;   // Context

// Parse XML
int wm_aws_read(xml_node **nodes, wmodule *module, int agent_cfg);

#endif // WM_AWS_H
