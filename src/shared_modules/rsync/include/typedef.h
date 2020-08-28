/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 24, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSYNC_TYPEDEF_H_
#define _RSYNC_TYPEDEF_H_


/**
 * @brief Represents the handle associated with remote sync creation.
 */
typedef void* RSYNC_HANDLE;

/**
 * @brief Callback function for user defined logging.
 *
 * @param msg Message to be logged.
 *
 * @details Useful to get deeper information during the rsync interaction.
 */
typedef void((*log_fnc_t)(const char* msg));

#endif // _RSYNC_TYPEDEF_H_