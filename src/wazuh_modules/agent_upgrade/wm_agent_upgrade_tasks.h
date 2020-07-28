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
 * Initialization of wm_agent_task
 * @param return an initialized wm_agent_task structure
 * */
wm_agent_task* wm_agent_upgrade_init_agent_task();

/**
 * Deallocate wm_upgrade_task structure
 * @param upgrade_task wm_upgrade_task structure to be deallocated
 * */
void wm_agent_upgrade_free_upgrade_task(wm_upgrade_task* upgrade_task);

/**
 * Deallocate wm_upgrade_custom_task structure
 * @param upgrade_custom_task wm_upgrade_custom_task structure to be deallocated
 * */
void wm_agent_upgrade_free_upgrade_custom_task(wm_upgrade_custom_task* upgrade_custom_task);

/**
 * Deallocate wm_task_info structure
 * @param task_info wm_task_info structure to be deallocated
 * */
void wm_agent_upgrade_free_task_info(wm_task_info* task_info);

/**
 * Deallocate wm_agent_info structure
 * @param agent_info wm_agent_info structure to be deallocated
 * */
void wm_agent_upgrade_free_agent_info(wm_agent_info* agent_info);

/**
 * Deallocate wm_upgrade_task structure
 * @param agent_task wm_upgrade_task structure to be deallocated
 * */
void wm_agent_upgrade_free_agent_task(wm_agent_task* agent_task);

/**
 * Tasks hashmap initialization
 * */
void wm_agent_upgrade_init_task_map();

/**
 * Tasks hashmap destructor
 * */
void wm_agent_upgrade_destroy_task_map();

/**
 * Creates an new entry into the table with the agent_id and task
 * @param agent_id id of the agent
 * @param task pointer to the task
 * */
int wm_agent_upgrade_create_task_entry(int agent_id, wm_agent_task* agent_task);

/**
 * Inserts a task_id into an already existent agent entry
 * @param agent_id id of the agent
 * @param task_id id of the task
 * */
void wm_agent_upgrade_insert_task_id(int agent_id, int task_id);

/**
 * Remoes a entry based on the agent_id
 * @param agent_id id of the agent
 * */
void wm_agent_upgrade_remove_entry(int agent_id);

/**
 * Sends the JSON information to the task module and retrieves the answer
 * @param message_object JSON to be sent. Example:
 *  [{
 *       "module" : "upgrade_module",
 *       "command": "upgrade",
 *       "agent" : 1
 *   }, {
 *       "module" : "upgrade_module",
 *       "command": "upgrade",
 *       "agent" : 2
 *  }]
 * @return json response
 * @retval NULL if connection problem or incorrect response format
 * @retval JSON with the task information. Example:
 *  [{
 *       "error": 0,
 *       "data": "Task created successfully",
 *       "agent": 1,
 *       "task_id": {{tid1}}
 *   }, {
 *       "error": 0,
 *       "data": "Task created successfully",
 *       "agent": 2,
 *       "task_id": {{tid2}}
 *  }]
 * */
cJSON* wm_agent_upgrade_send_tasks_information(const cJSON *message_object);

#endif
