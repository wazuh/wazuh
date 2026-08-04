/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * August 10, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WM_AGENT_UPGRADE_VALIDATE_H
#define WM_AGENT_UPGRADE_VALIDATE_H

#include "wm_agent_upgrade_manager.h"

/**
 * Check if agent exist
 * @param agent_id id of agent to validate
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_UPGRADE_ERROR
 * */
int wm_agent_upgrade_validate_id(int agent_id);

/**
 * Check if WPK exists for this agent
 * @param platform platform of agent to validate
 * @param os_major OS major version of agent to validate
 * @param os_minor OS minor version of agent to validate
 * @param arch architecture of agent to validate
 * @param package_type variable used to store package type
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
int wm_agent_upgrade_validate_system(const char *platform, const char *os_major, const char *os_minor, const char *arch, char **package_type);

/**
 * Check if agent is valid to upgrade
 * @param wazuh_version wazuh version of agent
 * @param platform platform of agent to validate
 * @param command wm_upgrade_command with the selected upgrade type
 * @param task pointer to task with the params
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_NOT_MINIMAL_VERSION_SUPPORTED
 * @retval WM_UPGRADE_NEW_VERSION_LESS_OR_EQUAL_THAN_CURRENT
 * @retval WM_UPGRADE_NEW_VERSION_GREATER_MASTER
 * @retval WM_UPGRADE_GLOBAL_DB_FAILURE
 * */
int wm_agent_upgrade_validate_version(const char *wazuh_version, const char *platform, wm_upgrade_command command, void *task)  __attribute__((nonnull(4)));

/**
 * Extract the target version token from a canonical WPK filename of the form
 * "wazuh_agent_v<VERSION>_<rest>.wpk", prefixed with 'v' for direct use with
 * compare_wazuh_versions(). Shared with wm_agent_upgrade_commands.c's
 * verification_mode/force gate, which needs the same resolved target
 * version this function already computes for the intermediate-version check.
 * @param file_path Full path or basename of the WPK file.
 * @param out Output buffer for the version token (e.g. "v5.0.0").
 * @param out_size Capacity of out.
 * @return true if a version token was found, false if the filename does not
 * follow the canonical pattern (renamed file, missing tokens, etc.).
 */
bool wm_agent_upgrade_parse_wpk_custom_version(const char *file_path, char *out, size_t out_size);

/**
 * Translate architecture based on platform and package type if necessary
 * @param platform Agent platform
 * @param package_type Package type
 * @param arch Agent architecture
 * @return Translated architecture
*/
char *wm_agent_upgrade_translate_arch(const char *platform, const char *package_type, char *arch);

/**
 * Check if a WPK exist for the upgrade version
 * @param agent_info structure with the agent information
 * @param task structure with the task information
 * @param wpk_repository_config char pointer with the repository url set in module config
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_URL_NOT_FOUND
 * @retval WM_UPGRADE_WPK_VERSION_DOES_NOT_EXIST
 * @retval WM_UPGRADE_SYSTEM_NOT_SUPPORTED
 * */
int wm_agent_upgrade_validate_wpk_version(wm_agent_info *agent_info, wm_upgrade_task *task, const char *wpk_repository_config) __attribute__((nonnull(1, 2)));

/**
 * Check if WPK file exist or download it
 * @param task pointer to task with the params
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST
 * @retval WM_UPGRADE_WPK_SHA1_DOES_NOT_MATCH
 * */
int wm_agent_upgrade_validate_wpk(const wm_upgrade_task *task) __attribute__((nonnull));

/**
 * Check if WPK custom file exists and calculate its SHA1 hash
 * @param task pointer to task with the params
 * @return return_code
 * @retval WM_UPGRADE_SUCCESS
 * @retval WM_UPGRADE_WPK_FILE_DOES_NOT_EXIST
 * */
int wm_agent_upgrade_validate_wpk_custom(wm_upgrade_custom_task *task) __attribute__((nonnull));

#endif
