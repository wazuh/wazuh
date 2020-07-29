/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 20, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_db/wdb.h"
#include "wazuh_modules/wmodules.h"

static int wm_agent_upgrade_validate_non_custom_version(char *agent_version, wm_upgrade_task *task);

/**
 * Check if agent exist
 * @param agent_id Id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS_VALIDATE
 * @retval WM_UPGRADE_NOT_AGENT_IN_DB
 * */
int wm_agent_upgrade_validate_id(int agent_id) {
    char *name = NULL;
    int return_code = WM_UPGRADE_SUCCESS_VALIDATE;
    if (agent_id == MANAGER_ID) {
        return_code = WM_UPGRADE_INVALID_ACTION_FOR_MANAGER;
    } else if (name = wdb_agent_name(agent_id), name) {
        // Agent found: OK
        free(name);
    } else {
        return_code = WM_UPGRADE_NOT_AGENT_IN_DB;
    }

    return return_code;
}

/**
 * Check if agent status is active
 * @param agent_id Id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS_VALIDATE
 * @retval WM_UPGRADE_AGENT_IS_NOT_ACTIVE
 * */
int wm_agent_upgrade_validate_status(int agent_id) {
    int return_code = WM_UPGRADE_SUCCESS_VALIDATE;
    int last_keepalive = wdb_agent_last_keepalive(agent_id);

    if (last_keepalive < 0 || last_keepalive < (time(0) - DISCON_TIME)) {
        return_code = WM_UPGRADE_AGENT_IS_NOT_ACTIVE;
    }

    return return_code;
}

/**
 * Check if agent version is valid to upgrade
 * @param agent_id Id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS_VALIDATE
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_VERSION_SAME_MANAGER
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER)
 * */
int wm_agent_upgrade_validate_agent_version(int agent_id, void *task, wm_upgrade_command command) {
    char *agent_version = NULL;
    char *tmp_agent_version = NULL;
    int return_code = WM_UPGRADE_SUCCESS_VALIDATE;

    if (agent_version = wdb_agent_version(agent_id), agent_version) {
        tmp_agent_version = strchr(agent_version, 'v');
        
        if (strcmp(tmp_agent_version, WM_UPGRADE_MINIMAL_VERSION_SUPPORT) < 0) {
            return_code = WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED;
        } else if (WM_UPGRADE_UPGRADE == command) {
            task = (wm_upgrade_task *)task;
            return_code = wm_agent_upgrade_validate_non_custom_version(tmp_agent_version, task);
        }

        free(agent_version);
    }

    return return_code;
}

/**
 * Check if agent version is valid to upgrade to a non-customized version
 * @param agent_id Id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS_VALIDATE
 * @retval WM_UPGRADE_VERSION_SAME_MANAGER
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER)
 * */
static int wm_agent_upgrade_validate_non_custom_version(char *agent_version, wm_upgrade_task *task) {
    char *master_version = NULL;
    char *tmp_master_version = NULL;
    master_version = wdb_agent_version(MANAGER_ID);
    tmp_master_version = strchr(master_version, 'v');
    int return_code = WM_UPGRADE_SUCCESS_VALIDATE;

    if (task->custom_version && strcmp(agent_version, task->custom_version) >= 0 && task->force_upgrade == false) {
        return_code = WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT;
    } else if (task->custom_version && strcmp(task->custom_version, tmp_master_version) > 0 && task->force_upgrade == false) {
        return_code = WM_UPGRADE_NEW_VERSION_GREATER_MASTER;
    } else if (strcmp(agent_version, tmp_master_version) == 0 && task->force_upgrade == false) {
        return_code = WM_UPGRADE_VERSION_SAME_MANAGER;
    }

    free(master_version);
    return return_code;
}
