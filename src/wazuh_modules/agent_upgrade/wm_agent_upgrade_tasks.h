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
 * Initialization of wm_upgrade_task
 * @param return an initialized wm_upgrade_task structure
 * */
wm_upgrade_task* wm_agent_upgrade_init_upgrade_task();

/**
 * Initialization of wm_upgrade_custom_task
 * @param return an initialized wm_upgrade_custom_task structure
 * */
wm_upgrade_custom_task* wm_agent_upgrade_init_upgrade_custom_task();

/**
 * Initialization of wm_task_info
 * @param return an initialized wm_task_info structure
 * */
wm_task_info* wm_agent_upgrade_init_task_info();

/**
 * Initialization of wm_agent_info
 * @param return an initialized wm_agent_info structure
 * */
wm_agent_info* wm_agent_upgrade_init_agent_info();

/**
 * Deallocate wm_upgrade_task structure
 * @param task wm_upgrade_task structure to be deallocated
 * */
void wm_agent_upgrade_free_upgrade_task(wm_upgrade_task* upgrade_task);

/**
 * Deallocate wm_upgrade_custom_task structure
 * @param task wm_upgrade_custom_task structure to be deallocated
 * */
void wm_agent_upgrade_free_upgrade_custom_task(wm_upgrade_custom_task* upgrade_custom_task);

/**
 * Deallocate wm_task_info structure
 * @param task wm_task_info structure to be deallocated
 * */
void wm_agent_upgrade_free_task_info(wm_task_info* task_info);

/**
 * Deallocate wm_agent_info structure
 * @param agent wm_agent_info structure to be deallocated
 * */
void wm_agent_upgrade_free_agent_info(wm_agent_info* agent_info);

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
 * @param json_response cJSON array where the task responses will be stored
 * @param agent_ids array with the list of agents id
 * @param command command related to the task
 * @param task pointer to a task structure
 * */
void wm_agent_upgrade_create_agents_tasks(cJSON* json_response, const int* agent_ids, int command, void *task);

#endif
