/*
 * Copyright (C) 2015-2019, Wazuh Inc.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../headers/shared.h"

#ifndef WM_OSQUERYMONITOR
#define WM_OSQUERYMONITOR

#define WM_OSQUERYMONITOR_LOGTAG ARGV0 ":osquery"

extern const wm_context WM_OSQUERYMONITOR_CONTEXT;

typedef struct wm_osquery_pack_t {
    char * name;
    char * path;
} wm_osquery_pack_t;

typedef struct wm_osquery_monitor_t {
   char* bin_path;
   char* log_path;
   char* config_path;
   int disable;
   int msg_delay;
   int queue_fd;
   wm_osquery_pack_t ** packs;
   unsigned int add_labels:1;
   unsigned int run_daemon:1;
} wm_osquery_monitor_t;

int wm_osquery_monitor_read(xml_node **nodes, wmodule *module);

#endif
