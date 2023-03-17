/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WM_AGENT_UPGRADE_WRAPPERS_H
#define WM_AGENT_UPGRADE_WRAPPERS_H

#include "headers/shared.h"
#include "wazuh_modules/wmodules.h"
#include "wazuh_modules/agent_upgrade/manager/wm_agent_upgrade_manager.h"

int setup_hash_table(void (free_data_function)(wm_agent_task* agent_task));

int teardown_hash_table();

int __wrap_wm_agent_upgrade_check_status(const wm_agent_configs* agent_config);

void __wrap_wm_agent_upgrade_start_manager_module(const wm_manager_configs* manager_configs, const int enabled);

int __wrap_wm_agent_upgrade_parse_message(const char* buffer, void** task, int** agent_ids, char** error);

char* __wrap_wm_agent_upgrade_process_upgrade_command(const int* agent_ids, wm_upgrade_task* task, const wm_manager_configs* manager_configs);

char* __wrap_wm_agent_upgrade_process_upgrade_custom_command(const int* agent_ids, wm_upgrade_custom_task* task, const wm_manager_configs* manager_configs);

char* __wrap_wm_agent_upgrade_process_agent_result_command(const int* agent_ids, wm_upgrade_agent_status_task* task);

char* __wrap_wm_agent_upgrade_process_upgrade_result_command(const int* agent_ids);

cJSON* __wrap_wm_agent_upgrade_parse_task_module_request(wm_upgrade_command command, cJSON *agents_array, const char* status, const char* error);

int __wrap_wm_agent_upgrade_task_module_callback(cJSON *json_response, const cJSON* task_module_request);

int __wrap_wm_agent_upgrade_parse_agent_response(const char* agent_response, char **data);

int __wrap_wm_agent_upgrade_parse_agent_upgrade_command_response(const char* agent_response, char **data);

OSHashNode* __wrap_wm_agent_upgrade_get_first_node(unsigned int *index);

OSHashNode* __wrap_wm_agent_upgrade_get_next_node(unsigned int *index, OSHashNode *current);

cJSON* __wrap_wm_agent_upgrade_get_agent_ids();

bool __wrap_wm_agent_upgrade_validate_task_status_message(const cJSON *input_json, char **status, int *agent_id);

int __wrap_wm_agent_upgrade_validate_id(int agent_id);

int __wrap_wm_agent_upgrade_validate_status(const char* connection_status);

int __wrap_wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch);

int __wrap_wm_agent_upgrade_validate_version(const char *wazuh_version, const char *platform, wm_upgrade_command command, void *task);

int __wrap_wm_agent_upgrade_validate_wpk_version(const wm_agent_info *agent_info, wm_upgrade_task *task, const char *wpk_repository_config);

int __wrap_wm_agent_upgrade_validate_wpk(const wm_upgrade_task *task);

int __wrap_wm_agent_upgrade_validate_wpk_custom(const wm_upgrade_custom_task *task);

int __wrap_wm_agent_upgrade_create_task_entry(int agent_id, wm_agent_task* ag_task);

int __wrap_wm_agent_upgrade_remove_entry(int agent_id, int free);

cJSON* __wrap_wm_agent_upgrade_parse_data_response(int error_id, const char* message, const int* agent_id);

cJSON* __wrap_wm_agent_upgrade_parse_response(int error_id, cJSON *data);

bool __wrap_wm_agent_upgrade_validate_task_ids_message(const cJSON *input_json, int *agent_id, int *task_id, char** data);

char* __wrap_wm_agent_upgrade_send_command_to_agent(const char *command, const size_t command_size);

cJSON* __wrap_wm_agent_upgrade_send_tasks_information(const cJSON *message_object);

int __wrap_wm_agent_upgrade_prepare_upgrades();

int __wrap_wm_agent_upgrade_cancel_pending_upgrades();

#endif
