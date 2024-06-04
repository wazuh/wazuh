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

#include "../../../../headers/shared.h"
#include "../../../../wazuh_modules/wmodules.h"

#ifndef CLIENT

cJSON* __wrap_wm_task_manager_parse_message(const char *msg);

cJSON* __wrap_wm_task_manager_process_task(const wm_task_manager_task *task, int *error_code);

cJSON* __wrap_wm_task_manager_parse_data_response(int error_code, int agent_id, int task_id, char *status);

void __wrap_wm_task_manager_parse_data_result(cJSON *response, const char *node, const char *module, const char *command, char *status, char *error, int create_time, int last_update_time, char *request_command);

#endif

#endif
