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

/**
 * Check if agent version is valid to upgrade to a non-customized version
 * @param agent_id Id of agent to validate
 * @param task pointer to wm_upgrade_task with the params
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_VERSION_SAME_MANAGER
 * @retval WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER)
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
static int wm_agent_upgrade_validate_non_custom_version(char *agent_version, wm_upgrade_task *task);

static const char* invalid_platforms[] = {
    "darwin",
    "solaris",
    "aix",
    "hpux",
    "bsd"
};

int wm_agent_upgrade_validate_id(int agent_id) {
    int return_code = WM_UPGRADE_SUCCESS;

    if (agent_id == MANAGER_ID) {
        return_code = WM_UPGRADE_INVALID_ACTION_FOR_MANAGER;
    }

    return return_code;
}

int wm_agent_upgrade_validate_status(int last_keep_alive) {
    int return_code = WM_UPGRADE_SUCCESS;

    if (last_keep_alive < 0 || last_keep_alive < (time(0) - DISCON_TIME)) {
        return_code = WM_UPGRADE_AGENT_IS_NOT_ACTIVE;
    }

    return return_code;
}

int wm_agent_upgrade_validate_system(char *platform, char *os_major, char *os_minor, char *arch) {
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;
    int invalid_platforms_len = 0;
    int invalid_platforms_it = 0;

    if (platform && os_major && arch) {
        if (strcmp(platform, "ubuntu") || os_minor) {
            return_code = WM_UPGRADE_SUCCESS;
            invalid_platforms_len = sizeof(invalid_platforms) / sizeof(invalid_platforms[0]);

            for(invalid_platforms_it = 0; invalid_platforms_it < invalid_platforms_len; ++invalid_platforms_it) {
                if(!strcmp(invalid_platforms[invalid_platforms_it], platform)) {
                    return_code = WM_UPGRADE_SYSTEM_NOT_SUPPORTED;
                    break;
                }
            }

            if (return_code == WM_UPGRADE_SUCCESS) {
                if ((!strcmp(platform, "sles") && !strcmp(os_major, "11")) ||
                    (!strcmp(platform, "rhel") && !strcmp(os_major, "5")) ||
                    (!strcmp(platform, "centos") && !strcmp(os_major, "5"))) {
                    return_code = WM_UPGRADE_SYSTEM_NOT_SUPPORTED;
                }
            }
        }
    }

    return return_code;
}

int wm_agent_upgrade_validate_version(const char *version, void *task, wm_upgrade_command command) {
    char *tmp_agent_version = NULL;
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;

    if (version) {
        if (tmp_agent_version = strchr(version, 'v'), tmp_agent_version) {
            return_code = WM_UPGRADE_SUCCESS;

            if (strcmp(tmp_agent_version, WM_UPGRADE_MINIMAL_VERSION_SUPPORT) < 0) {
                return_code = WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED;
            } else if (WM_UPGRADE_UPGRADE == command) {
                task = (wm_upgrade_task *)task;
                return_code = wm_agent_upgrade_validate_non_custom_version(tmp_agent_version, task);
            }
        }
    }

    return return_code;
}

int wm_agent_upgrade_validate_non_custom_version(char *agent_version, wm_upgrade_task *task) {
    char *manager_version = NULL;
    char *tmp_manager_version = NULL;
    int return_code = WM_UPGRADE_GLOBAL_DB_FAILURE;

    if (manager_version = wdb_agent_version(MANAGER_ID), manager_version) {
        if (tmp_manager_version = strchr(manager_version, 'v'), tmp_manager_version) {
            return_code = WM_UPGRADE_SUCCESS;

            if (task->custom_version && strcmp(agent_version, task->custom_version) >= 0 && task->force_upgrade == false) {
                return_code = WM_UPGRADE_NEW_VERSION_LEES_OR_EQUAL_THAT_CURRENT;
            } else if (task->custom_version && strcmp(task->custom_version, tmp_manager_version) > 0 && task->force_upgrade == false) {
                return_code = WM_UPGRADE_NEW_VERSION_GREATER_MASTER;
            } else if (strcmp(agent_version, tmp_manager_version) == 0 && task->force_upgrade == false) {
                return_code = WM_UPGRADE_VERSION_SAME_MANAGER;
            }
        }

        free(manager_version);
    }

    return return_code;
}
