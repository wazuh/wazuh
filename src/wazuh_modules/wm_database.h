/*
 * Wazuh Module for SQLite database syncing
 * Copyright (C) 2015-2019, Wazuh Inc.
 * November 29, 2016
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_DATABASE
#define WM_DATABASE

#define WM_DATABASE_LOGTAG ARGV0 ":database"

typedef struct wm_database {
    int sync_agents;
    int sync_syscheck;
    int sync_rootcheck;
    int full_sync;
    int real_time;
    int interval;
    int max_queued_events;
} wm_database;

// Read configuration and return a module (if enabled) or NULL (if disabled)
wmodule* wm_database_read();

#endif // WM_DATABASE
