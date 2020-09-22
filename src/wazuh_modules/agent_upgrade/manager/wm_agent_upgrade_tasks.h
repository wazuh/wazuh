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

#include "wm_agent_upgrade_manager.h"

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
 * Initialization of wm_agent_task
 * @param return an initialized wm_upgrade_agent_status_task structure
 * */
wm_upgrade_agent_status_task* wm_agent_upgrade_init_agent_status_task();

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
 * Deallocate wm_upgrade_agent_status_task structure
 * @param task wm_upgrade_agent_status_task to be deallocated
 * */
void wm_agent_upgrade_free_agent_status_task(wm_upgrade_agent_status_task* task);

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
 * Removes an entry based on the agent_id
 * @param agent_id id of the agent
 * @param free whether free task or not
 * */
void wm_agent_upgrade_remove_entry(int agent_id, int free);

/**
 * Returns the first node of the tasks hash table
 * @return the first node stored
 * */
OSHashNode* wm_agent_upgrade_get_first_node(unsigned int *index);

/**
 * Returns the next node of the tasks hash table
 * @return the next node stored
 * */
OSHashNode* wm_agent_upgrade_get_next_node(unsigned int *index, OSHashNode *current);

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
cJSON* wm_agent_upgrade_send_tasks_information(const cJSON *message_object) __attribute__((nonnull));

/**
 * Send a request to the task module and executes a callback for all the given responses
 * @param data_array cJSON array where the task responses will be stored
 * @param task_module_request cJSON to be sent to the task module
 * @param success_callback function receives pointer to the error flag and a json and return the response json
 * @param error_callback function that can generate an action when the communication with task module fails
 * @return error code
 * @retval OS_SUCCESS on success
 * @retval OS_INVALID on errors
 * 
 * */
int wm_agent_upgrade_task_module_callback(cJSON *data_array, const cJSON* task_module_request, cJSON* (*success_callback)(int *error, cJSON* input_json), void (*error_callback)(int agent_id, int free)) __attribute__((nonnull(1,2)));

/**
 * Callback defined for upgrade command to process task manager information reponse
 * @param error if there is any error processing the information, it will be set to OS_INVALID
 * @param input_json response from the task manager
 * @return cJSON containing the message that should be included as part of the ugprade response
 * */
cJSON* wm_agent_upgrade_upgrade_success_callback(int *error, cJSON* input_json);

/**
 * Callback function for task manager mensaje, if task manager was able to update task status 
 * then it will send a message to the agent telling it to erase its upgrade_result file
 * @param error if there is any error processing the information, it will be set to OS_INVALID
 * @param input_json response from the task manager
 * @return cJSON containing the message that should be included as part of the ugprade response
 * */
cJSON* wm_agent_upgrade_update_status_success_callback(int *error, cJSON* input_json);

#endif
