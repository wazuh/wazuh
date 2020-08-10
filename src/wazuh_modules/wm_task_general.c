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

#include "wm_task_general.h"

const char *task_manager_commands_list[] = {
    [WM_TASK_UPGRADE] = "upgrade",
    [WM_TASK_UPGRADE_CUSTOM] = "upgrade_custom",
    [WM_TASK_UPGRADE_GET_STATUS] = "upgrade_get_status",
    [WM_TASK_UPGRADE_UPDATE_STATUS] = "upgrade_update_status"
};

const char *task_manager_modules_list[] = {
    [WM_TASK_UPGRADE_MODULE] = "upgrade_module"
};

const char *task_statuses[] = {
    [WM_TASK_NEW] = "New",
    [WM_TASK_IN_PROGRESS] = "In progress",
    [WM_TASK_DONE] = "Done",
    [WM_TASK_FAILED] = "Failed"
};
