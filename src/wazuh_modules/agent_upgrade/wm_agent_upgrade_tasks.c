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
#include "wm_agent_upgrade.h"

wm_upgrade_task* init_upgrade_task() {
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

void destroy_upgrade_task(wm_upgrade_task* task) {
    os_free(task->custom_file_path);
    os_free(task->custom_installer);
    os_free(task->custom_version);
    os_free(task->wpk_repository);
    os_free(task);
}
