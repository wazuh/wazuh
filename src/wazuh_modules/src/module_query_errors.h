/*
 * Wazuh Module Query Error Codes
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef MODULE_QUERY_ERRORS_H
#define MODULE_QUERY_ERRORS_H

#include "cJSON.h"

/**
 * @brief Standard error codes for module query operations
 *
 * These error codes are used consistently across all modules (SCA, Syscollector, FIM)
 * to provide unified error handling in the AgentInfo coordination flow.
 */

// Success
#define MQ_SUCCESS                      0   // Operation completed successfully

// Client errors (1-49)
#define MQ_ERR_UNKNOWN_COMMAND          1   // Command not recognized by the module
#define MQ_ERR_INVALID_JSON             2   // JSON format is invalid or cannot be parsed
#define MQ_ERR_INVALID_PARAMS           3   // Required parameters are missing or invalid

// Module state errors (50-79)
#define MQ_ERR_MODULE_DISABLED          50  // Module is explicitly disabled in configuration
#define MQ_ERR_MODULE_NOT_FOUND         51  // Module is not found or not configured
#define MQ_ERR_MODULE_NOT_RUNNING       52  // Module is not running (socket/process not available)
#define MQ_ERR_MODULE_NOT_SUPPORTED     53  // Module does not support query operations

// Internal errors (80-99)
#define MQ_ERR_INTERNAL                 98  // Internal error during command execution
#define MQ_ERR_EXCEPTION                99  // Unhandled exception occurred

/**
 * @brief Standard error messages for module query operations
 *
 * These messages correspond to the error codes above and provide
 * consistent error descriptions across all modules.
 */

// Success messages
#define MQ_MSG_SUCCESS                  "Operation completed successfully"

// Client error messages
#define MQ_MSG_UNKNOWN_COMMAND          "Unknown command"
#define MQ_MSG_INVALID_JSON             "Invalid JSON format"
#define MQ_MSG_INVALID_PARAMS           "Missing or invalid parameters"

// Module state error messages
#define MQ_MSG_MODULE_DISABLED          "Module is disabled"
#define MQ_MSG_MODULE_NOT_FOUND         "Module not found or not configured"
#define MQ_MSG_MODULE_NOT_RUNNING       "Module is not running"
#define MQ_MSG_MODULE_NOT_SUPPORTED     "Module does not support queries"

// Internal error messages
#define MQ_MSG_INTERNAL                 "Internal error"
#define MQ_MSG_EXCEPTION                "Exception occurred"

/**
 * @brief Macro to check if an error code indicates the module is unavailable
 *
 * Used by AgentInfo::coordinateModules to determine if a module should be
 * skipped during coordination (not an error, just not available).
 */
#define MQ_IS_MODULE_UNAVAILABLE(code) \
    ((code) >= MQ_ERR_MODULE_DISABLED && (code) <= MQ_ERR_MODULE_NOT_SUPPORTED)

/**
 * @brief Parses the top-level "error" field out of a response using this envelope
 *
 * Shared by every client of this envelope (agentd's in-process module-query clients on
 * Windows, its socket-based ones on POSIX) so each one does not reimplement the same few
 * lines of cJSON lookup.
 *
 * @param root Parsed JSON response.
 * @param out_error Set to the error code when present and numeric; untouched otherwise.
 * @return true if an "error" field was found and is numeric, false otherwise.
 */
static inline bool mq_parse_error_field(const cJSON *root, int *out_error) {
    const cJSON *error = cJSON_GetObjectItem(root, "error");

    if (!error || !cJSON_IsNumber(error)) {
        return false;
    }

    *out_error = error->valueint;
    return true;
}

#endif /* MODULE_QUERY_ERRORS_H */
