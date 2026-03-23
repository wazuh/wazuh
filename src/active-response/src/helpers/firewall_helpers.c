/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "firewall_helpers.h"
#include "active_responses.h"
#include <errno.h>

firewall_result_t check_binary_available(
    const char *binary_name,
    char **path_out,
    const char *log_prefix
) {
    char log_msg[OS_MAXSTR];
    char *binary_path = NULL;

    if (get_binary_path(binary_name, &binary_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1,
                 "Binary '%s' not found in default paths: %s (%d)",
                 binary_name,
                 binary_path ? binary_path : "null",
                 errno);
        write_debug_file(log_prefix, log_msg);
        os_free(binary_path);
        return FIREWALL_NOT_AVAILABLE;
    }

    if (path_out) {
        *path_out = binary_path;
    } else {
        os_free(binary_path);
    }

    return FIREWALL_SUCCESS;
}

firewall_result_t execute_with_retry(
    const char *binary_path,
    char **args,
    int bind_flags,
    const retry_config_t *config,
    const char *log_prefix
) {
    int count = 0;
    bool flag = true;
    char log_msg[OS_MAXSTR];

    while (flag && count <= config->max_retries) {
        wfd_t *wfd = wpopenv(binary_path, args, bind_flags);

        if (wfd) {
            // Read and discard output if STDOUT/STDERR bound
            if (bind_flags & (W_BIND_STDOUT | W_BIND_STDERR)) {
                char buffer[4096];
                while (fgets(buffer, sizeof(buffer), wfd->file_out));
            }

            int wp_closefd = wpclose(wfd);

#ifndef WIN32
            if (WIFEXITED(wp_closefd)) {
                int wstatus = WEXITSTATUS(wp_closefd);
                if (wstatus == 0) {
                    return FIREWALL_SUCCESS;
                }
            }
#else
            // On Windows, wpclose returns the exit code directly
            if (wp_closefd == 0) {
                return FIREWALL_SUCCESS;
            }
#endif
        }

        count++;
        if (count > config->max_retries) {
            flag = false;
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1,
                     "Command failed after %d retry attempts",
                     config->max_retries);
            write_debug_file(log_prefix, log_msg);
        } else {
            // Calculate backoff sleep time
            int sleep_time = config->exponential_backoff ?
                           (config->backoff_base_seconds * count) :
                           config->backoff_base_seconds;

            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR - 1,
                     "Retry attempt %d after %d seconds",
                     count, sleep_time);
            write_debug_file(log_prefix, log_msg);

            sleep(sleep_time);
        }
    }

    return FIREWALL_EXECUTION_FAILED;
}

int acquire_ar_lock(lock_context_t *ctx) {
#ifndef WIN32
    char log_msg[OS_MAXSTR];

    if (lock(ctx->lock_path, ctx->lock_pid_path, ctx->log_prefix, "block-ip") == OS_INVALID) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1, "Unable to acquire lock at %s", ctx->lock_path);
        write_debug_file(ctx->log_prefix, log_msg);
        ctx->acquired = false;
        return OS_INVALID;
    }

    ctx->acquired = true;
    return OS_SUCCESS;
#else
    // Windows: no locking needed for this implementation
    (void)ctx;
    return OS_SUCCESS;
#endif
}

void release_ar_lock(lock_context_t *ctx) {
#ifndef WIN32
    if (ctx->acquired) {
        unlock(ctx->lock_path, ctx->log_prefix);
        ctx->acquired = false;
    }
#else
    // Windows: no locking needed
    (void)ctx;
#endif
}

void log_firewall_action(
    const char *ar_name,
    log_level_t level,
    const char *method,
    const char *action,
    const char *details
) {
    char log_msg[OS_MAXSTR];
    const char *level_str[] = {"INFO", "WARNING", "ERROR", "DEBUG"};

    memset(log_msg, '\0', OS_MAXSTR);
    snprintf(log_msg, OS_MAXSTR - 1,
             "[%s] Method=%s Action=%s Details=%s",
             level_str[level],
             method ? method : "unknown",
             action ? action : "unknown",
             details ? details : "");

    write_debug_file(ar_name, log_msg);
}

const char* firewall_result_to_string(firewall_result_t result) {
    switch (result) {
        case FIREWALL_SUCCESS:
            return "SUCCESS";
        case FIREWALL_NOT_AVAILABLE:
            return "NOT_AVAILABLE";
        case FIREWALL_EXECUTION_FAILED:
            return "EXECUTION_FAILED";
        case FIREWALL_INVALID_STATE:
            return "INVALID_STATE";
        default:
            return "UNKNOWN";
    }
}

int execute_firewall_chain(
    const firewall_method_t *methods,
    const char *srcip,
    int action,
    int ip_version,
    const char *argv0
) {
    char log_msg[OS_MAXSTR];
    int methods_attempted = 0;
    int methods_unavailable = 0;
    int methods_failed = 0;

    for (int i = 0; methods[i].name != NULL; i++) {
        methods_attempted++;

        // Log attempt
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR - 1,
                 "Attempting method: %s (lock=%s)",
                 methods[i].name,
                 methods[i].requires_lock ? "yes" : "no");
        log_firewall_action(argv0, LOG_LEVEL_INFO, methods[i].name, "start", log_msg);

        // Execute method
        firewall_result_t result = methods[i].execute(srcip, action, ip_version, argv0);

        switch (result) {
            case FIREWALL_SUCCESS:
                memset(log_msg, '\0', OS_MAXSTR);
                snprintf(log_msg, OS_MAXSTR - 1,
                         "IP %s successfully %s",
                         srcip,
                         action == ADD_COMMAND ? "blocked" : "unblocked");
                log_firewall_action(argv0, LOG_LEVEL_INFO, methods[i].name, "success", log_msg);
                write_debug_file(argv0, "Ended");
                return OS_SUCCESS;  // Early exit on first success

            case FIREWALL_NOT_AVAILABLE:
                methods_unavailable++;
                log_firewall_action(argv0, LOG_LEVEL_WARNING, methods[i].name, "skipped",
                                  "Method not available on this system - trying next");
                break;

            case FIREWALL_EXECUTION_FAILED:
                methods_failed++;
                log_firewall_action(argv0, LOG_LEVEL_WARNING, methods[i].name, "failed",
                                  "Command execution failed - trying next");
                break;

            case FIREWALL_INVALID_STATE:
                methods_failed++;
                log_firewall_action(argv0, LOG_LEVEL_WARNING, methods[i].name, "invalid_state",
                                  "Service or firewall in invalid state - trying next");
                break;
        }
    }

    // All methods exhausted without success
    memset(log_msg, '\0', OS_MAXSTR);
    snprintf(log_msg, OS_MAXSTR - 1,
             "WARNING: All %d firewall methods failed or unavailable (%d unavailable, %d execution errors)",
             methods_attempted,
             methods_unavailable,
             methods_failed);
    write_debug_file(argv0, log_msg);

    write_debug_file(argv0, "Ended");

    // Always return OS_SUCCESS to avoid retry loops in execd
    return OS_SUCCESS;
}
