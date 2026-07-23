/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WM_TASK_MANAGER_WRAPPERS_H
#define WM_TASK_MANAGER_WRAPPERS_H

#include "shared.h"
#include "wmodules.h"

cJSON* __wrap_wm_task_manager_parse_message(const char* msg);

cJSON* __wrap_wm_task_manager_parse_data_response(int error_code, int agent_id, int task_id, char* status);

void __wrap_wm_task_manager_parse_data_result(cJSON* response,
                                              const char* node,
                                              const char* module,
                                              const char* command,
                                              char* status,
                                              char* error,
                                              int create_time,
                                              int last_update_time,
                                              char* request_command);

void __wrap_wm_task_cache_init(int cache_ttl);

int __wrap_w_create_thread(void *(*function_pointer)(void *), void *data);

// Task cache functions
cJSON* __wrap_wm_task_cache_get(const char *agent_id);

void __wrap_wm_task_cache_set(const char *agent_id, cJSON *tasks);

void __wrap_wm_task_cache_invalidate(const char *agent_id);

// Task ID generation
char* __wrap_wm_task_manager_generate_task_id(const char *source_id, const char *agent_id,
                                               const char *task_type, time_t create_time);

#endif
