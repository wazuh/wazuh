/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 6, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef DB_COMMONDEFS_H
#define DB_COMMONDEFS_H
#include "logging_helper.h"
#include "commonDefs.h"

#define FIMDB_FILE_TABLE_NAME "file_entry"
#define FIMDB_FILE_TXN_TABLE "{\"table\": \"file_entry\"}"
#define FILE_PRIMARY_KEY "path"

#define FIMDB_REGISTRY_KEY_TABLENAME "registry_key"
#define FIMDB_REGISTRY_KEY_TXN_TABLE "{\"table\": \"registry_key\"}"
#define FIMDB_REGISTRY_VALUE_TABLENAME "registry_data"
#define FIMDB_REGISTRY_VALUE_TXN_TABLE "{\"table\": \"registry_data\"}"

typedef enum FIMDBErrorCode
{
    FIMDB_OK = 0,
    FIMDB_ERR = -1,
    FIMDB_FULL = -2
} FIMDBErrorCode;

typedef void((*logging_callback_t)(const modules_log_level_t level, const char* log));
typedef void((*callback_t)(void *return_data, void *user_data));

/**
 * @brief callback context.
 */
typedef struct
{
    callback_t callback;
    void *context;
} callback_context_t;

enum OSType
{
    OTHERS,
    WINDOWS
};


#endif // DB_COMMONDEFS_H
