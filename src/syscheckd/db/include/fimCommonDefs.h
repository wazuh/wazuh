/**
 * @file fimCommonDefs.h
 * @brief Common definitions for FIM
 * @date 2021-09-06
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef DB_COMMONDEFS_H
#define DB_COMMONDEFS_H
#include "logging_helper.h"
#include "commonDefs.h"

#define FIMBD_FILE_TABLE_NAME "file_entry"
#define FIMDB_FILE_TXN_TABLE "{\"table\": \"file_entry\"}"
#define FILE_PRIMARY_KEY "path"

typedef enum FIMDBErrorCodes
{
    FIMDB_OK = 0,
    FIMDB_ERR = -1,
    FIMDB_FULL = -2
} FIMDBErrorCodes;

typedef void((*fim_sync_callback_t)(const char *tag, const char* buffer));
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


#endif // DB_COMMONDEFS_H
