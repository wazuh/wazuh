/*
 * Wazuh Module for SQLite database syncing
 * Copyright (C) 2015, Wazuh Inc.
 * November 29, 2016
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_DATABASE
#define WM_DATABASE

#define WM_DATABASE_LOGTAG ARGV0 ":database"

typedef struct wm_database {
    int sync_agents;
    int real_time;
    int interval;
    int max_queued_events;
} wm_database;

extern int wdb_wmdb_sock;

// Read configuration and return a module (if enabled) or NULL (if disabled)
wmodule* wm_database_read();

/**
 * @brief Synchronizes a keystore with the agent table of global.db.
 *
 * @param keys The keystore structure to be synchronized
 * @param wdb_sock The socket to be used in the calls to Wazuh DB
 */
void sync_keys_with_wdb(keystore *keys, int *wdb_sock);

#endif /* WM_DATABASE */
