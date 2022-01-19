/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYSINFO_UTILS_H_
#define SYSINFO_UTILS_H_

#include "../data_provider/include/sysInfo.h"
#include "shared.h"

/**
 * @brief Store helpers to execute stateless requests to SysInfo
 *
 */
typedef struct {
    void * module;                        ///< Opaque reference to sysinfo library
    sysinfo_processes_func processes;     ///< `sysinfo_processes` helper
    sysinfo_free_result_func free_result; ///< `sysinfo_free_result` helper
    sysinfo_os_func os;                   ///< `sysinfo_os_func` helper
} w_sysinfo_helpers_t;

/**
 * @brief Initialize Sysinfo library and helpers
 *
 * @param sysinfo struct to store helpers references
 * @return true on success. false otherwise
 */
bool w_sysinfo_init(w_sysinfo_helpers_t * sysinfo);

/**
 * @brief Release Sysinfo library and helpers resources
 *
 * @param sysinfo struct that store helpers references
 * @return true on success. false otherwise
 */
bool w_sysinfo_deinit(w_sysinfo_helpers_t * sysinfo);

/**
 * @brief Get all processes information
 *
 * @param sysinfo sysinfo helpers reference
 * @return cJSON* list of cJSON objects containing all processes information. NULL otherwise
 */
cJSON * w_sysinfo_get_processes(w_sysinfo_helpers_t * sysinfo);

/**
 * @brief Get OS information
 *
 * @param sysinfo sysinfo helpers reference
 * @return cJSON* cJSON object containing OS information. NULL otherwise
 */
cJSON * w_sysinfo_get_os(w_sysinfo_helpers_t * sysinfo);

/**
 * @brief Get array of child processes
 *
 * @param sysinfo sysinfo helpers to be used
 * @param parent_pid parent process pid
 * @param max_count max count of processes to find. Zero to find all you can
 * @return pid_t* zero-terminated array of child processes. NULL if no children were found
 */
pid_t * w_get_process_childs(w_sysinfo_helpers_t * sysinfo, pid_t parent_pid, unsigned int max_count);

/**
 * @brief Get OS codename
 *
 * @param sysinfo sysinfo helpers to be used
 * @return char* Allocated string with OS codename. NULL otherwise
 */
char * w_get_os_codename(w_sysinfo_helpers_t * sysinfo);

#endif
