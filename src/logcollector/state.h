/* Copyright (C) 2015-2021, Wazuh Inc.
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
#define LOGCOLLECTOR_STATE_PATH "wazuh-logcollector.state"
#else
#define LOGCOLLECTOR_STATE      "/var/run/wazuh-logcollector.state"
#define LOGCOLLECTOR_STATE_PATH DEFAULTDIR LOGCOLLECTOR_STATE
#endif

// Double of max value of logcollector.queue_size
#define LOGCOLLECTOR_STATE_FILES_MAX   440000               ///< max amount of localfiles location for states
#define LOGCOLLECTOR_STATE_DESCRIPTION "logcollector_state" ///< String identifier for errors

/**
 * @brief Initialize storing structures
 *
 */
void w_logcollector_state_init();

/**
 * @brief Logcollector state main thread function
 * @param args optional parameter. state interval value
 * @return void* default return value for thread function prototype (unused)
 */
#ifdef WIN32
DWORD WINAPI w_logcollector_state_main(__attribute__((unused)) void * args);
#else
void * w_logcollector_state_main(__attribute__((unused)) void * args);
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
 * @param bytes amount of bytes
 */
void w_logcollector_state_update_file(char * fpath, uint64_t bytes);

/**
 * @brief Get a string with current state in JSON format
 *
 * @return cJSON* allocated object with current state.
 * The string is heap allocated memory that must be freed by the caller.
 */
cJSON * w_logcollector_state_get();

#endif /* LOGCOLLECTOR_STAT_H */
