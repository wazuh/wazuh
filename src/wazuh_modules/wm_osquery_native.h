/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../headers/shared.h"

#ifndef WM_OSQUERYNATIVE
#define WM_OSQUERYNATIVE

#define WM_OSQUERYNATIVE_LOGTAG ARGV0 ":osquery_native"

extern const wm_context WM_OSQUERYNATIVE_CONTEXT;

typedef struct wm_osquery_native_t {
   char *bin_path;
   char *config_path;
   int disable;
   int run_daemon;
   int disable_process_events;
   unsigned long interval_process_events;
   int msg_delay;
   int queue_fd;
   void *remote_ondemand_call;
} wm_osquery_native_t;

int wm_osquery_native_configuration_reader(xml_node **nodes, wmodule *module);

#endif