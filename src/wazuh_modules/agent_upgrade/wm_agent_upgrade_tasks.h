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
 * Initialization of upgrade_task
 * @param return an initialized upgrade task structure
 * */
wm_upgrade_task* wm_agent_upgrade_init_upgrade_task();

/**
 * Initialization of upgrade_custom_task
 * @param return an initialized upgrade_custom task structure
 * */
wm_upgrade_custom_task* wm_agent_upgrade_init_upgrade_custom_task();

/**
 * Deallocate wm_upgrade_task structure
 * @param task task to be deallocated
 * */
void wm_agent_upgrade_free_upgrade_task(wm_upgrade_task* task);

/**
 * Deallocate wm_upgrade_custom_task structure
 * @param task task to be deallocated
 * */
void wm_agent_upgrade_free_upgrade_custom_task(wm_upgrade_custom_task* task);

/**
 * Tasks hashmap initialization
 * */
void wm_agent_upgrade_init_task_map();

/**
 * Tasks hashmap destructor
 * */
void wm_agent_upgrade_destroy_task_map();

/**
 * Receives the cJSON with the agents_id and creates the tasks structure for each agent
 * @param agents cJSON array with the agents_id
 * @param task pointer to a task structure
 * @param command command corresponding to the task
 * @return cJSON array where the responses for each agent will be stored
 * */
cJSON* wm_agent_upgrade_create_agent_tasks(const cJSON *agents, void *task, wm_upgrade_command command);

#endif
