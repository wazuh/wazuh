/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WM_AGENT_UPGRADE_TASKS_H
#define WM_AGENT_UPGRADE_TASKS_H

#include "wm_task_manager.h"

/**
 * Initialization of wm_task_manager_upgrade
 * @param return an initialized wm_task_manager_upgrade structure
 * */
//wm_task_manager_upgrade* wm_task_manager_init_upgrade_parameters();

/**
 * Initialization of wm_task_manager_upgrade_get_status
 * @param return an initialized wm_task_manager_upgrade_get_status structure
 * */
wm_task_manager_upgrade_get_status* wm_task_manager_init_upgrade_get_status_parameters();

/**
 * Initialization of wm_task_manager_upgrade_update_status
 * @param return an initialized wm_task_manager_upgrade_update_status structure
 * */
wm_task_manager_upgrade_update_status* wm_task_manager_init_upgrade_update_status_parameters();

/**
 * Initialization of wm_task_manager_result
 * @param return an initialized wm_task_manager_result structure
 * */
wm_task_manager_result* wm_task_manager_init_result_parameters();

/**
 * Initialization of wm_task_manager_upgrade_cancel_tasks
 * @param return an initialized wm_task_manager_upgrade_cancel_tasks structure
 * */
wm_task_manager_upgrade_cancel_tasks* wm_task_manager_init_upgrade_cancel_tasks_parameters();

/**
 * Initialization of wm_task_manager_task
 * @param return an initialized wm_task_manager_task structure
 * */
wm_task_manager_task* wm_task_manager_init_task();

/**
 * Deallocate wm_task_manager_upgrade structure
 * @param parameters wm_task_manager_upgrade structure to be deallocated
 * */
//void wm_task_manager_free_upgrade_parameters(wm_task_manager_upgrade* parameters);

/**
 * Deallocate wm_task_manager_upgrade_get_status structure
 * @param parameters wm_task_manager_upgrade_get_status structure to be deallocated
 * */
void wm_task_manager_free_upgrade_get_status_parameters(wm_task_manager_upgrade_get_status* parameters);

/**
 * Deallocate wm_task_manager_upgrade_update_status structure
 * @param parameters wm_task_manager_upgrade_update_status structure to be deallocated
 * */
void wm_task_manager_free_upgrade_update_status_parameters(wm_task_manager_upgrade_update_status* parameters);

/**
 * Deallocate wm_task_manager_result structure
 * @param parameters wm_task_manager_result structure to be deallocated
 * */
void wm_task_manager_free_result_parameters(wm_task_manager_result* parameters);

/**
 * Deallocate wm_task_manager_upgrade_cancel_tasks structure
 * @param parameters wm_task_manager_upgrade_cancel_tasks structure to be deallocated
 * */
void wm_task_manager_free_upgrade_cancel_tasks_parameters(wm_task_manager_upgrade_cancel_tasks* parameters);

/**
 * Deallocate wm_task_manager_task structure
 * @param task wm_task_manager_task structure to be deallocated
 * */
void wm_task_manager_free_task(wm_task_manager_task* task);

void wm_task_manager_free_syscollector_tasks_parameters(wm_task_manager_syscollector *parameters);
void wm_task_manager_free_status_tasks_parameters(wm_task_manager_status *parameters);
void wm_task_manager_free_generic_task_parameters(wm_task_manager_generic *parameters);
wm_task_manager_syscollector* wm_task_manager_init_syscollector_parameters();
wm_task_manager_status* wm_task_manager_init_status_parameters();
wm_task_manager_generic* wm_task_manager_init_generic_parameters();

#endif
