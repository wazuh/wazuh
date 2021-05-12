/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2021, Wazuh Inc.
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

/**
 * @brief Represents the different host types to be used.
 */
typedef enum 
{
    MANAGER = 0,
    AGENT   = 1
}HostType;

/**
 * @brief Represents the database type to be used.
 */
typedef enum 
{
    UNDEFINED = 0,  /*< Undefined database. */
    SQLITE3   = 1,  /*< SQLite3 database.   */
}DbEngineType;

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
    SELECTED = 5    /*< Database select operation.              */
}ReturnTypeCallback;

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

#endif // _COMMON_DEFS_H_