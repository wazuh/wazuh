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

#ifndef WM_TASK_GENERAL_H
#define WM_TASK_GENERAL_H

/**
 * Enumeration of the available commands
 * */
typedef enum _command_list {
    WM_TASK_UPGRADE = 0,
    WM_TASK_UPGRADE_CUSTOM,
    WM_TASK_UPGRADE_GET_STATUS,
    WM_TASK_UPGRADE_UPDATE_STATUS
} command_list;

/**
 * List containing all the command names
 * */
extern const char *task_manager_commands_list[];

#endif
