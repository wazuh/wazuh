/*
 * Wazuh Module for Security Configuration Assessment
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_GCP_H
#define WM_GCP_H

#define WM_GCP_LOGTAG ARGV0 ":gcp-pubsub"
#define WM_GCP_DEFAULT_DIR WM_DEFAULT_DIR "/gcp-pubsub"
#define WM_GCP_SCRIPT_PATH WM_GCP_DEFAULT_DIR "/__main__.py"

typedef struct wm_gcp {
    int enabled:1;
    int pull_on_start:1;
    int logging;
    int max_messages;
    char *project_id;
    char *subscription_name;
    char *credentials_file;
    unsigned int interval;
    time_t time_interval;
} wm_gcp;

extern const wm_context WM_GCP_CONTEXT;   // Context

int wm_gcp_read(xml_node **nodes, wmodule *module);

#endif
