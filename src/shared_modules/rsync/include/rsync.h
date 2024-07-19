/*
 * Wazuh RSYNC
 * Copyright (C) 2015, Wazuh Inc.
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
#ifndef EXPORTED
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
#endif

#include "commonDefs.h"

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
 * @brief Initialize the shared library with a full log function.
 *
 * @param logFunc Pointer to full log function to be used by the rsync.
 */
EXPORTED void rsync_initialize_full_log_function(full_log_fnc_t logFunc);

/**
 * @brief Turns off the services provided by the shared library.
 */
EXPORTED void rsync_teardown(void);

/**
 * @brief Creates a new RSync instance.
 *
 * @param thread_pool_size Size of the thread pool.
 * @param max_queue_size Size of the message dispatch queue, if the value is 0, it is unlimited.
 * @return Handle instance to be used for synchronization between the manager and the agent.
 */
EXPORTED RSYNC_HANDLE rsync_create(const unsigned int thread_pool_size, const size_t max_queue_size);

/**
 * @brief Initializes the \p handle instance.
 * @param handle              Current rsync handle being used.
 * @param dbsync_handle       DBSync handle to synchronize databases.
 * @param start_configuration Statement used as a synchronization start.
 * @param callback_data       This callback will be called for each result
 *                            and user data space returned in each callback call.
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int rsync_start_sync(const RSYNC_HANDLE handle,
                              const DBSYNC_HANDLE dbsync_handle,
                              const cJSON* start_configuration,
                              sync_callback_data_t callback_data);

/**
 * @brief Stablishes a message-id to be processed in the agent-manager sync.
 *
 * @param handle             Current rsync handle being used.
 * @param message_header_id  Message ID associated to procees messages between
 *                           agent and manager.
 * @param dbsync_handle      DBSync handle to synchronize databases.
 * @param sync_configuration Statement used as a configuration.
 * @param callback_data      This callback will be called for each result
 *                           and user data space returned in each callback call.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int rsync_register_sync_id(const RSYNC_HANDLE handle,
                                    const char* message_header_id,
                                    const DBSYNC_HANDLE dbsync_handle,
                                    const cJSON* sync_configuration,
                                    sync_callback_data_t callback_data);

/**
 * @brief Pushes the \p payload message within a queue to process it in an async
 *  dispatch queue.
 *
 * @param handle  Current rsync handle being used.
 * @param payload Message to be queued and processed.
 * @param size    Size of the message to be queued and processed.
 *
 * @return 0 if succeeded,
 *         specific error code (OS dependent) otherwise.
 */
EXPORTED int rsync_push_message(const RSYNC_HANDLE handle,
                                const void* payload,
                                const size_t size);

/**
 * @brief Turns off an specific rsync instance.
 *
 * @param handle Handle instance to be closed.
 */
EXPORTED int rsync_close(const RSYNC_HANDLE handle);



#ifdef __cplusplus
}
#endif

#endif // _RSYNC_H_
