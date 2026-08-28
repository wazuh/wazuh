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

#include "wdb.h"

int __wrap_wdb_task_create(__attribute__((unused)) wdb_t* wdb,
                           const char *task_id,
                           const char *agent_id,
                           const char *task_type,
                           const char *payload);

int __wrap_wdb_task_get_pending(__attribute__((unused)) wdb_t* wdb,
                                const char *agent_id,
                                int max_tasks,
                                cJSON **tasks_json);

int __wrap_wdb_task_mark_delivered(__attribute__((unused)) wdb_t* wdb,
                                   const char *task_id,
                                   time_t delivery_time);

int __wrap_wdb_task_cleanup_expired(__attribute__((unused)) wdb_t* wdb,
                                    int ttl);

int __wrap_wdb_task_delete_old(__attribute__((unused)) wdb_t* wdb,
                               time_t timestamp);

#endif
