/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WM_AGENT_UPGRADE_UPGRADES_H
#define WM_AGENT_UPGRADE_UPGRADES_H

#include "wm_agent_upgrade_manager.h"
#include <semaphore.h>

/**
 * Upgrade queue initialization
 * */
void wm_agent_upgrade_init_upgrade_queue();

/**
 * Upgrade queue destructor
 * */
void wm_agent_upgrade_destroy_upgrade_queue();

/**
 * Insert the agents ready to be upgraded into the upgrade queue
 * */
void wm_agent_upgrade_prepare_upgrades();

/**
 * Dispatcher of upgrade tasks
 * @param arg Module configuration
 * */
void* wm_agent_upgrade_dispatch_upgrades(void *arg) __attribute__((nonnull));

/**
 * Send a command to the agent and return the response
 * @param command request command to agent
 * @param command_size size of the command
 * @return response from agent
 * */
char* wm_agent_upgrade_send_command_to_agent(const char *command, const size_t command_size) __attribute__((nonnull));

#endif
