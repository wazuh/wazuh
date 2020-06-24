/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/**
 * @file typedef.h
 * @author Dwordcito
 * @date 17 May 2020
 * @brief File containing declaration for common types for the usage of this module
 *
 */

#pragma once

#include "cJSON.h"

typedef enum {
    MANAGER = 0,
    AGENT = 1
}HostType;

typedef enum {
    SQLITE3 = 0
}DbEngineType;

typedef enum {
    MODIFIED = 0,
    DELETED = 1,
    INSERTED = 2
}ReturnTypeCallback;

typedef void* DBSYNC_HANDLE;

/**
 * \brief Callback function for results
 *
 * This callback is called for each result obtained, after evaluating changes between two snapshots.
 * \param result_type Enumeration value indicating what action was taken.
 * \param result_json Json which describe the change.
 */
typedef void((*result_callback)(ReturnTypeCallback result_type, cJSON* result_json));