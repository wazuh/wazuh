/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _COMMON_DEFS_H_
#define _COMMON_DEFS_H_

#include "cJSON.h"
#include <stdarg.h>

/**
 * @brief Represents the different host types to be used.
 */
typedef enum
{
    MANAGER = 0,
    AGENT   = 1
} HostType;

/**
 * @brief Represents the database type to be used.
 */
typedef enum
{
    UNDEFINED = 0,  /*< Undefined database. */
    SQLITE3   = 1,  /*< SQLite3 database.   */
} DbEngineType;

/**
 * @brief Configures how the engine manages the database at startup.
 */
typedef enum
{
    VOLATILE   = 0,  /*< Removes the DB every time .                          */
    PERSISTENT = 1,  /*< The DB is kept and the correct version is checked.   */
} DbManagement;


/**
 * @brief Represents the database operation events.
 */
typedef enum
{
    MODIFIED = 0,   /*< Database modificaton operation.         */
    DELETED  = 1,   /*< Database deletion operation.            */
    INSERTED = 2,   /*< Database insertion operation.           */
    MAX_ROWS = 3,   /*< Database has reached max rows number.   */
    DB_ERROR = 4,   /*< Internal failure.                       */
    SELECTED = 5,   /*< Database select operation.              */
    GENERIC = 6     /*< Generic result for reuse.               */
} ReturnTypeCallback;

/**
 * @brief Represents the handle associated with database creation.
 */
typedef void* DBSYNC_HANDLE;

/**
 * @brief Represents the transaction handle associated with a database instance.
 */
typedef void* TXN_HANDLE;

/**
 * @brief Represents the handle associated with the remote synch.
 */
typedef void* RSYNC_HANDLE;

/**
 * @brief Callback function for results
 *
 * @param result_type Enumeration value indicating what action was taken.
 * @param result_json Json which describe the change.
 * @param user_data   User data space returned.
 *
 * @details Callback called for each obtained result, after evaluating changes between two snapshots.
 */
typedef void((*result_callback_t)(ReturnTypeCallback result_type, const cJSON* result_json, void* user_data));

/**
 * @brief Callback function for agent-manager sync.
 *
 * @param buffer      Buffer used to sync between agent and manager.
 * @param buffer_size Buffer's size.
 * @param user_data   User data space returned.
 *
 * @details Callback called for each obtained result, after evaluating changes between two snapshots.
 */
typedef void((*sync_id_callback_t)(const void* buffer, size_t buffer_size, void* user_data));

/**
 *  @struct callback_data_t
 *  This struct contains the result callback will be called for each result
 *  and user data space returned in each callback call.
 *  The instance of this structure lives in the library's consumer ecosystem.
 */
typedef struct
{
    /*@{*/
    result_callback_t callback;     /**< Result callback. */
    void* user_data;                /**< User data space returned in each callback. */
    /*@}*/
} callback_data_t;

/**
 *  @struct sync_callback_data_t
 *  This struct contains a callback used to synchronize the information between agent and manager
 *  and user data space returned in each callback call.
 *  The instance of this structure lives in the library's consumer ecosystem.
 */
typedef struct
{
    /*@{*/
    sync_id_callback_t callback;     /**< Sync ID callback. */
    void* user_data;                 /**< User data space returned in each callback. */
    /*@}*/
} sync_callback_data_t;

/**
 * @brief Callback function for user defined logging.
 *
 * @param msg Message to be logged.
 *
 * @details Useful to get deeper information during the dbsync interaction.
 */
typedef void((*log_fnc_t)(const char* msg));

/**
 * @brief Callback function for user defined logging but adding a tag, the file name,
 * the line number and the name of the function where the log was generated.
 *
 * @param level    Level of the log.
 * @param tag      Tag to identify the log.
 * @param file     File name where the log is generated.
 * @param line     Line number where the log is generated.
 * @param func     Function name where the log is generated.
 * @param msg      Message to be logged.
 * @param args     Variable list args.
 */
typedef void ((*full_log_fnc_t)(int level, const char* tag, const char* file, int line, const char* func, const char* msg, va_list args));

/**
* @brief Definition to indicate the unlimited queue.
*
* @details It's used to define the unlimited queue size.
*/
#define UNLIMITED_QUEUE_SIZE 0

#endif // _COMMON_DEFS_H_
