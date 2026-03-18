/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef FIREWALL_HELPERS_H
#define FIREWALL_HELPERS_H

#include "shared.h"

/**
 * Enumeration of firewall operation results
 */
typedef enum {
    FIREWALL_SUCCESS = 0,           // Operation completed successfully
    FIREWALL_NOT_AVAILABLE,         // Binary/tool not found on system
    FIREWALL_EXECUTION_FAILED,      // Command execution failed
    FIREWALL_INVALID_STATE          // Service/firewall in invalid state
} firewall_result_t;

/**
 * Log levels for firewall operations
 */
typedef enum {
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_DEBUG
} log_level_t;

/**
 * Configuration for retry logic
 */
typedef struct {
    int max_retries;                // Maximum number of retry attempts
    int backoff_base_seconds;       // Base seconds for backoff
    bool exponential_backoff;       // Use exponential vs linear backoff
} retry_config_t;

/**
 * Lock context for managing concurrent execution
 */
typedef struct {
    const char *lock_path;          // Path to lock directory
    const char *lock_pid_path;      // Path to lock PID file
    const char *log_prefix;         // Prefix for log messages
    bool acquired;                  // Lock acquisition status
} lock_context_t;

/**
 * Firewall method function pointer type
 * @param srcip Source IP address to block/unblock
 * @param action ADD_COMMAND or DELETE_COMMAND
 * @param ip_version 4 for IPv4, 6 for IPv6
 * @param argv0 Program name for logging
 * @return firewall_result_t indicating operation result
 */
typedef firewall_result_t (*firewall_method_func_t)(
    const char *srcip,
    int action,
    int ip_version,
    const char *argv0
);

/**
 * Firewall method descriptor
 */
typedef struct {
    const char *name;               // Method name (e.g., "firewalld", "iptables")
    firewall_method_func_t execute; // Function to execute this method
    bool requires_lock;             // Whether this method needs locking
} firewall_method_t;

/**
 * @brief Check if a binary is available on the system
 * @param binary_name Name of the binary to check
 * @param path_out Output parameter for binary path (caller must free)
 * @param log_prefix Prefix for log messages
 * @return FIREWALL_SUCCESS if found, FIREWALL_NOT_AVAILABLE otherwise
 */
firewall_result_t check_binary_available(
    const char *binary_name,
    char **path_out,
    const char *log_prefix
);

/**
 * @brief Execute a command with retry logic and exponential backoff
 * @param binary_path Full path to binary
 * @param args Command arguments (NULL-terminated array)
 * @param bind_flags Flags for wpopenv (W_BIND_STDIN, W_BIND_STDOUT, etc.)
 * @param config Retry configuration
 * @param log_prefix Prefix for log messages
 * @return FIREWALL_SUCCESS if command succeeded, FIREWALL_EXECUTION_FAILED otherwise
 */
firewall_result_t execute_with_retry(
    const char *binary_path,
    char **args,
    int bind_flags,
    const retry_config_t *config,
    const char *log_prefix
);

/**
 * @brief Acquire a lock for concurrent execution control
 * @param ctx Lock context structure
 * @return OS_SUCCESS if lock acquired, OS_INVALID otherwise
 */
int acquire_ar_lock(lock_context_t *ctx);

/**
 * @brief Release a previously acquired lock
 * @param ctx Lock context structure
 */
void release_ar_lock(lock_context_t *ctx);

/**
 * @brief Log a firewall action with structured format
 * @param ar_name Active response name (argv[0])
 * @param level Log level
 * @param method Method name (e.g., "firewalld")
 * @param action Action description (e.g., "start", "execute", "success")
 * @param details Additional details about the action
 */
void log_firewall_action(
    const char *ar_name,
    log_level_t level,
    const char *method,
    const char *action,
    const char *details
);

/**
 * @brief Convert firewall_result_t to string for logging
 * @param result Firewall result code
 * @return String representation of result
 */
const char* firewall_result_to_string(firewall_result_t result);

/**
 * @brief Execute a chain of firewall methods with fallback
 * @param methods NULL-terminated array of firewall methods
 * @param srcip Source IP address to block/unblock
 * @param action ADD_COMMAND or DELETE_COMMAND
 * @param ip_version 4 for IPv4, 6 for IPv6
 * @param argv0 Program name for logging
 * @return OS_SUCCESS (always, to avoid retry loops in execd)
 */
int execute_firewall_chain(
    const firewall_method_t *methods,
    const char *srcip,
    int action,
    int ip_version,
    const char *argv0
);

#endif /* FIREWALL_HELPERS_H */
