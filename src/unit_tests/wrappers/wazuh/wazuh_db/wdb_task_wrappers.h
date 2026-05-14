/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_TASK_WRAPPERS_H
#define WDB_TASK_WRAPPERS_H

#include "../wazuh_db/wdb.h"

int __wrap_wdb_task_insert_task(__attribute__((unused)) wdb_t* wdb, int agent_id, const char *node, const char *module, const char *command);
int __wrap_wdb_task_get_upgrade_task_status(__attribute__((unused)) wdb_t* wdb, int agent_id, const char *node, char **status);
int __wrap_wdb_task_update_upgrade_task_status(__attribute__((unused)) wdb_t* wdb, int agent_id, const char *node, const char *status, const char *error);
int __wrap_wdb_task_get_upgrade_task_by_agent_id(__attribute__((unused)) wdb_t* wdb, int agent_id, char **node, char **module, char **command, char **status, char **error, int *create_time, int *last_update_time);
int __wrap_wdb_task_cancel_upgrade_tasks(__attribute__((unused)) wdb_t* wdb, const char *node);
int __wrap_wdb_task_set_timeout_status(__attribute__((unused)) wdb_t* wdb, time_t now, int interval, time_t *next_timeout);
int __wrap_wdb_task_delete_old_entries(__attribute__((unused)) wdb_t* wdb, int timestamp);

#endif
