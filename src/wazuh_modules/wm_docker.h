/*
 * Wazuh Module for Docker
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_DOCKER
#define WM_DOCKER
#ifndef WIN32

#define WM_DOCKER_LOGTAG ARGV0 ":docker-listener"
#define WM_DOCKER_SCRIPT_PATH WM_DEFAULT_DIR "/docker/DockerListener"

#define WM_DOCKER_DEF_INTERVAL 600

typedef struct wm_docker_flags_t {
    unsigned int enabled:1;
    unsigned int run_on_start:1;
} wm_docker_flags_t;

typedef struct wm_docker_t {
    unsigned int interval;             // Time interval to retry to run the listener
    int attempts;                      // Maximum attempts to run the module after fails
    wm_docker_flags_t flags;           // Default flags
} wm_docker_t;

extern const wm_context WM_DOCKER_CONTEXT;   // Context

// Parse XML configuration
int wm_docker_read(xml_node **nodes, wmodule *module);

#endif
#endif
