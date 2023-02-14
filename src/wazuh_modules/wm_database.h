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
 * @brief Synchronizes a keystore with the agent table of global.db. It will insert
 *        the agents that are in the keystore and are not in global.db.
 *        In addition it will remove from global.db in wazuh-db all the agents that
 *        are not in the keystore. Also it will remove all the artifacts for those
 *        agents.
 *
 * @param keys The keystore structure to be synchronized
 */
void sync_keys_with_wdb(keystore *keys);

/**
 * @brief This function removes the wazuh-db agent DB and the diff folder of an agent.
 *
 * @param agent_id The ID of the agent.
 * @param agent_name The name of the agent.
 */
void wm_clean_agent_artifacts(int agent_id, const char* agent_name);

/**
 * @brief This method will read the legacy GROUPS_DIR folder to insert in the global.db the groups information it founds.
 *        After every successful insertion, the legacy file is deleted. If we are in a worker, the files are deleted without inserting.
 *        If the folder is empty, it will be removed.
 */
void wm_sync_legacy_groups_files();

/**
 * @brief Method to insert a single group file in the global.db. The group insertion overrides any existent group assignment.
 *
 * @param group_file The name of the group file.
 * @param group_file_path The full path of the group file.
 * @return int OS_SUCCESS if successful, OS_INVALID otherwise.
 */
int wm_sync_group_file(const char* group_file, const char* group_file_path);

#endif /* WM_DATABASE */
