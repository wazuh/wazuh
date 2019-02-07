/*
 * Wazuh Module for remote key requests
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_KEY_REQUEST_H
#define WM_KEY_REQUEST_H

#define WM_KEY_REQUEST_LOGTAG ARGV0 ":" KEY_WM_NAME

typedef struct wm_krequest_t {
    int enabled;
    int force_insert;
    unsigned int timeout;
    unsigned int threads;
    unsigned int queue_size;
    char* exec_path;
    char* socket;
} wm_krequest_t;

extern const wm_context WM_KEY_REQUEST_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_key_request_read(xml_node **nodes, wmodule *module);

#endif // WM_KEY_REQUEST_H
