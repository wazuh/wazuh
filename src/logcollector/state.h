/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef LOGCOLLECTOR_STAT_H
#define LOGCOLLECTOR_STAT_H

#include "shared.h"

#ifdef WIN32
#define LOGCOLLECTOR_STATE      "wazuh-logcollector.state"
#else
#define LOGCOLLECTOR_STATE      "var/run/wazuh-logcollector.state"
#endif

#define LOGCOLLECTOR_STATE_FILES_MAX   40                   ///< Size of the statistics hash table
#define LOGCOLLECTOR_STATE_DESCRIPTION "logcollector_state" ///< String identifier for errors

// Macros to add files/targets node to states
#define w_logcollector_state_add_file(x)      w_logcollector_state_update_file(x, 0)
#define w_logcollector_state_add_target(x, y) w_logcollector_state_update_target(x, y, false)

/**
 * @brief state storage structure
 * key: location option value. value: w_lc_state_file_t
 */
typedef struct {
    time_t start;    ///< initial state timestamp
    OSHash * states; ///< state storage
} w_lc_state_storage_t;

/**
 * @brief target state storage
 *
 */
typedef struct {
    char * name;    ///< target name
    uint64_t drops; ///< drop count
} w_lc_state_target_t;

/**
 * @brief file state storage
 *
 */
typedef struct {
    uint64_t bytes;               ///< bytes count
    uint64_t events;              ///< events count
    w_lc_state_target_t ** targets; ///< array of poiters to file's different targets
} w_lc_state_file_t;

/**
 * @brief statistics types
 *
 */
typedef enum {
    LC_STATE_GLOBAL = 0x1 << 0,  ///< statistics since the begining of program execution
    LC_STATE_INTERVAL = 0x1 << 1 ///< periodically calculated statistic
} w_lc_state_type_t;

/**
 * @brief Initialize storing structures
 *
 * @param state_type statistics to calculate
 * @param state_file_enabled enable saving state to file
 */
void w_logcollector_state_init(w_lc_state_type_t state_type, bool state_file_enabled);

/**
 * @brief Logcollector state main thread function
 * @param args optional parameter. state interval value
 * @return void* default return value for thread function prototype (unused)
 */
#ifdef WIN32
DWORD WINAPI w_logcollector_state_main(void * args);
#else
void * w_logcollector_state_main(void * args);
#endif

/**
 * @brief Update/register current drop count for a target belonging to a particular file
 *
 * @param fpath file path or locafile location value
 * @param target target name
 * @param dropped true if want to register a drop.
 */
void w_logcollector_state_update_target(char * fpath, char * target, bool dropped);

/**
 * @brief Update/register current event and byte count for a particular file/location
 *
 * @param fpath file path or locafile location value
 * @param bytes amount of bytes. If bigger than zero, event counter will increment.
 */
void w_logcollector_state_update_file(char * fpath, uint64_t bytes);

/**
 * @brief Removes the `fpath` file from statistics
 * 
 * @param fpath file path or locafile location value
 */
void w_logcollector_state_delete_file(char * fpath);

/**
 * @brief Get current state in JSON format
 *
 * @return cJSON* allocated object with current state.
 * The cJSON* is heap allocated memory that must be freed by the caller using cJSON_Delete.
 */
cJSON * w_logcollector_state_get();

#endif /* LOGCOLLECTOR_STAT_H */
