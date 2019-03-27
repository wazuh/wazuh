/*
 * Wazuh Module for Fluent Forwarder
 * Copyright (C) 2015-2019, Wazuh Inc.
 * March 26, 2019.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_FLUENT_H
#define WM_FLUENT_H

#define WM_FLUENT_LOGTAG FLUENT_WM_NAME

typedef struct wm_fluent_t {
    int enabled:1;
    char *tag;
    char *socket_path;
    char *address;
    unsigned int port;
    char *shared_key;
    char *ca_file;
    char *user;
    char *password;
} wm_fluent_t;

extern const wm_context WM_FLUENT_CONTEXT;

// Read configuration and return a module (if enabled) or NULL (if disabled)
int wm_fluent_read(xml_node **nodes, wmodule *module);


#endif // WM_FLUENT_H
