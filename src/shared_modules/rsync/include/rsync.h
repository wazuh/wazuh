/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * August 20, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RSYNC_H_
#define _RSYNC_H_

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "typedef.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initializes the shared library.
 *
 * @param log_function pointer to log function to be used by the rsync.
 */
EXPORTED void rsync_initialize(log_fnc_t log_function);

/**
 * @brief Turns off the services provided by the shared library.
 */
EXPORTED void rsync_teardown(void);

/**
 * @brief Creates a new RSync instance.
 *
 * @return Handle instance to be used for synchronization between the manager and the agent.
 */
EXPORTED RSYNC_HANDLE rsync_create();

/**
 * @brief Turns off an specific rsync instance.
 * 
 * @param handle Handle instance to be close.
 */
EXPORTED int rsync_close(const RSYNC_HANDLE handle);



#ifdef __cplusplus
}
#endif

#endif // _RSYNC_H_