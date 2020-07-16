/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "wm_agent_upgrade_tasks.h"
#include "os_net/os_net.h"
#include "shared.h"

/* Hash table of current tasks based on agent_id */
static OSHash *task_table_by_agent_id;

wm_upgrade_task* wm_agent_init_upgrade_task() {
    wm_upgrade_task *task;
    os_malloc(sizeof(wm_upgrade_task), task);
    task->custom_file_path = NULL;
    task->custom_installer = NULL;
    task->custom_version = NULL;
    task->wpk_repository = NULL;
    task->force_upgrade = false;
    task->use_http = false;
    task->state = NOT_STARTED;
    return task;
}

void wm_agent_free_upgrade_task(wm_upgrade_task* task) {
    os_free(task->custom_file_path);
    os_free(task->custom_installer);
    os_free(task->custom_version);
    os_free(task->wpk_repository);
    os_free(task);
}

void wm_agent_init_task_map() {
    task_table_by_agent_id = OSHash_Create();
}


void wm_agent_destroy_task_map() {
    OSHash_Free(task_table_by_agent_id);
}

void wm_agent_insert_tasks_id(const int task_id, const int agent_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    wm_task *agent_task = (wm_task *)OSHash_Get_ex(task_table_by_agent_id, agent_id_string);
    if (agent_task) {
        agent_task->task_id = task_id;
        OSHash_Update_ex(task_table_by_agent_id, agent_id_string, agent_task);
    }
}

int wm_agent_create_task_entry(const int agent_id, wm_task* agent_task) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    return OSHash_Add_ex(task_table_by_agent_id, agent_id_string, agent_task);
}

void wm_agent_remove_entry(const int agent_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    OSHash_Delete_ex(task_table_by_agent_id, agent_id_string);
}

int wm_agent_task_present(const int agent_id) {
    char agent_id_string[128];
    sprintf(agent_id_string, "%d", agent_id);
    wm_task *agent_task = (wm_task *)OSHash_Get_ex(task_table_by_agent_id, agent_id_string);
    if (agent_task) {
        return agent_task->task_id;
    }
    return -1;
}
