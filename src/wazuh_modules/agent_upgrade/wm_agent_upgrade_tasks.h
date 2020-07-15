/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 15, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WM_AGENT_UPGRADE_TASKS_H
#define WM_AGENT_UPGRADE_TASKS_H

#include "wm_agent_upgrade.h"

/**
 * Initialization of upgrade task
 * @param return an initialized upgrade task structure
 * */
wm_upgrade_task* wm_agent_init_upgrade_task();
/**
 * Deallocate wm_upgrade_task structure
 * @param task  task to be deallocated
 * */
void wm_agent_free_upgrade_task(wm_upgrade_task* task);

/**
 * Tasks hashmap initialization
 * */
void wm_agent_init_task_map();

/**
 * Tasks hashmap destructor
 * */
void wm_agent_destroy_task_map();

/**
 * Inserts a task_id into an already existent agent entry
 * @param task_id id of the task
 * @param agent_id id of the agent
 * */
void wm_agent_insert_taks_id(const int task_id, const int agent_id);

/**
 * Creates an new entry into the table with the agent_id and task
 * @param agent_id id of the agent
 * @param agent_task pointer to the task
 * */
int wm_agent_create_task_entry(const int agent_id, wm_agent_task*  agent_task);

#endif
