/*
 * Wazuh Module for Task management.
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 13, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT

#ifndef WM_TASK_MANAGER_DB
#define WM_TASK_MANAGER_DB

#define TASKS_PATH              "queue/tasks/"
#define TASKS_DB TASKS_PATH     "tasks.db"

#define TASKS_TABLE             "TASKS"
#define MAX_SQL_ATTEMPTS        1000

typedef enum _task_query {
    VU_INSERT_TASK,
    VU_GET_MAX_TASK_ID,
} task_query;

static const char *task_queries[] = {
    [VU_INSERT_TASK] = "INSERT INTO " TASKS_TABLE " VALUES(NULL,?,?,?,?);",
    [VU_GET_MAX_TASK_ID] = "SELECT MAX(TASK_ID) FROM " TASKS_TABLE ";"
};

extern char *schema_task_manager_sql;

#endif
#endif
