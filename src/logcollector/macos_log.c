/* Copyright (C) 2015-2021, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#define Darwin
#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
#include "macos_log.h"

// Removes STATIC/INLINE qualifiers from the tests
#ifdef WAZUH_UNIT_TESTING
#define STATIC
#define INLINE
#else
#define STATIC static
#define INLINE inline
#endif

STATIC w_macos_log_vault_t macos_log_vault = { .mutex = PTHREAD_RWLOCK_INITIALIZER, .timestamp = "", .settings = NULL};

/**
 * @brief Validates whether the predicate is valid or not
 * @param predicate Contains the `log`'s predicate filter to be used as a string
 * @return true if valid, otherwise false
 */
STATIC INLINE bool w_macos_is_log_predicate_valid(char * predicate) {

    // todo : improve this function? or remove it?
    if (strlen(predicate) > 0) {
        return true;
    }
    return false;
}

/**
 * @brief Generates the `log show` command array with its arguments
 * @param predicate Contains the `log show`'s predicate filter to be used as a string
 * @param level Contains, or not, the `log show`'s level filter to be used as a string (default/info/debug)
 * @param type Contains the `log show`'s type filters to be used (as combined bit flags)
 * @return A pointer to an array containing the executable arguments
 */
STATIC char ** w_macos_create_log_show_array(char * start_date, char * query, char * level, int type) {

    char * predicate = NULL;
    char * type_predicate = NULL;

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    // Adding `log` and `show` to the array
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    // Adding the style lines to the array (`--style syslog`)
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    // Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`)
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(start_date, log_cmd_array[log_cmd_array_idx++]);

    // Log Show's Level section: adds, or not, the `--debug` and/or `--info`. This that assumes `debug` contains `info`
    if (level != NULL) {
        if (strcmp(level, MACOS_LOG_LEVEL_DEFAULT_STR) != 0) {
            // If the level is not `default`, because it is set to `info` or `debug`, then the info logs are acquired
            w_strdup(SHOW_INFO_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
            if (strcmp(level, MACOS_LOG_LEVEL_DEBUG_STR) == 0) {
                // Only when the level is set to `debug` the debug logs are acquired
                w_strdup(SHOW_DEBUG_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
            }
        }
    }

    // Log Stream's Type section
    if (type != 0) {
        if (type & MACOS_LOG_TYPE_ACTIVITY) {
            w_strdup(SHOW_TYPE_ACTIVITY_STR, type_predicate);
        }
        if (type & MACOS_LOG_TYPE_LOG) {
            if (type_predicate == NULL) {
                w_strdup(SHOW_TYPE_LOG_STR, type_predicate);
            } else {
                type_predicate = w_strcat(type_predicate, SHOW_OR_TYPE_LOG_STR, strlen(SHOW_OR_TYPE_LOG_STR));
            }
        }
        if (type & MACOS_LOG_TYPE_TRACE) {
            if (type_predicate == NULL) {
                w_strdup(SHOW_TYPE_TRACE_STR, type_predicate);
            } else {
                type_predicate = w_strcat(type_predicate, SHOW_OR_TYPE_TRACE_STR, strlen(SHOW_OR_TYPE_TRACE_STR));
            }
        }
    }

    // Log Stream's (full) Predicate section
    if (query != NULL) {
        if (w_macos_is_log_predicate_valid(query)) {
            w_strdup(PREDICATE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

            if (type_predicate != NULL) {
                const int PREDICATE_SIZE = strlen(query) + strlen(type_predicate) + strlen(QUERY_AND_TYPE_PREDICATE);
                os_calloc(PREDICATE_SIZE, sizeof(char), predicate);
                snprintf(predicate, PREDICATE_SIZE, QUERY_AND_TYPE_PREDICATE, query, type_predicate);
            }
            w_strdup(predicate, log_cmd_array[log_cmd_array_idx++]);

        } else if (type_predicate != NULL) {
            w_strdup(PREDICATE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
            w_strdup(type_predicate, log_cmd_array[log_cmd_array_idx++]);
        }
    } else if (type_predicate != NULL) {
        w_strdup(PREDICATE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
        w_strdup(type_predicate, log_cmd_array[log_cmd_array_idx++]);
    }

    os_free(predicate);
    os_free(type_predicate);

    return log_cmd_array;
}

/**
 * @brief Generates the `log stream` command array with its arguments
 * @param predicate Contains the `log stream`'s predicate filter to be used as a string
 * @param level Contains, or not, the `log stream`'s level filter to be used as a string (default/info/debug)
 * @param type Contains the `log stream`'s type filters to be used (as combined bit flags)
 * @return A pointer to an array containing the executable arguments
 */
STATIC char ** w_macos_create_log_stream_array(char * predicate, char * level, int type) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_STREAM_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    // Adding `log` and `stream` to the array
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_STREAM_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    // Adding the style lines to the array (`--style syslog`)
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    // Log Stream's Type section (`--type`)
    if (type != 0) {
        if (type & MACOS_LOG_TYPE_ACTIVITY) {
            w_strdup(TYPE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
            w_strdup(MACOS_LOG_TYPE_ACTIVITY_STR, log_cmd_array[log_cmd_array_idx++]);
        }
        if (type & MACOS_LOG_TYPE_LOG) {
            w_strdup(TYPE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
            w_strdup(MACOS_LOG_TYPE_LOG_STR, log_cmd_array[log_cmd_array_idx++]);
        }
        if (type & MACOS_LOG_TYPE_TRACE) {
            w_strdup(TYPE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
            w_strdup(MACOS_LOG_TYPE_TRACE_STR, log_cmd_array[log_cmd_array_idx++]);
        }
    }

    // Log Stream's Level section  (`--level`)
    if (level != NULL) {
        w_strdup(LEVEL_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
        w_strdup(level, log_cmd_array[log_cmd_array_idx++]);
    }

    // Log Stream's Predicate section
    if (predicate != NULL) {
        if (w_macos_is_log_predicate_valid(predicate)) {
            w_strdup(PREDICATE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

            w_strdup(predicate, log_cmd_array[log_cmd_array_idx++]);
        }
    }

    return log_cmd_array;
}

/**
 * @brief Executes the `log stream/show` command with its arguments and sets to non-blocking the output pipe
 * @param log_cmd_array Contains the arguments of the command to be executed
 * @param flags Are the flags to be used along with wpopenv()
 * @return A pointer to a fulfilled wfd_t structure, on success, or NULL
 */
STATIC wfd_t * w_macos_log_exec(char ** log_cmd_array, u_int32_t flags) {

    int log_pipe_fd = -1;
    int log_pipe_fd_flags = 0;
    wfd_t * macos_log_wfd = wpopenv(*log_cmd_array, log_cmd_array, flags);

    if (macos_log_wfd == NULL) {
        merror(WPOPENV_ERROR, strerror(errno), errno);
    } else {
        // The file descriptor, from which the output of `log stream` will be read, is set to non-blocking
        log_pipe_fd = fileno(macos_log_wfd->file);                  // Gets the file descriptor from a file pointer

        if (log_pipe_fd <= 0) {
            merror(FP_TO_FD_ERROR, strerror(errno), errno);
            wpclose(macos_log_wfd);
            macos_log_wfd = NULL;
        } else {
            log_pipe_fd_flags = fcntl(log_pipe_fd, F_GETFL, 0);     // Gets current flags

            if (log_pipe_fd_flags < 0) {
                merror(GET_FLAGS_ERROR, strerror(errno), errno);
                wpclose(macos_log_wfd);
                macos_log_wfd = NULL;
            } else {
                log_pipe_fd_flags |= O_NONBLOCK;                    // Adds the NON-BLOCKING flag to current flags
                const int set_flags_retval = fcntl(log_pipe_fd, F_SETFL, log_pipe_fd_flags);  // Sets the new Flags

                if (set_flags_retval < 0) {
                    merror(SET_FLAGS_ERROR, strerror(errno), errno);
                    wpclose(macos_log_wfd);
                    macos_log_wfd = NULL;
                }
            }
        }
    }

    return macos_log_wfd;
}

/**
 * @brief Checks whether the `log` command can be executed or not by using the access() function
 * 
 * @return true when `log` command can be executed, false otherwise.
 */
STATIC INLINE bool w_macos_is_log_executable(void) {

    const int retval = access(LOG_CMD_STR, X_OK);
    if (retval == 0) {
        return true;
    }
    merror(ACCESS_ERROR, LOG_CMD_STR, strerror(errno), errno);
    return false;
}

/**
 * @brief Creates the environment for collecting "show" logs on MacOS Systems
 * @param current logreader structure with `log show`'s input arguments and w_macos_log_config_t structure to be set
 */
STATIC INLINE void w_macos_create_log_show_env(logreader * current) {

    char ** log_show_array = NULL;

    char * timestamp = w_macos_get_last_log_timestamp();

    if (timestamp == NULL) {
        return;
    }

    current->macos_log->show_wfd = NULL;

    log_show_array = w_macos_create_log_show_array(timestamp, current->query, current->query_level, current->query_type);

    current->macos_log->show_wfd = w_macos_log_exec(log_show_array, W_BIND_STDOUT | W_BIND_STDERR);

    if (current->macos_log->show_wfd != NULL) {
        current->macos_log->state = LOG_RUNNING_SHOW;
        minfo(LOGCOLLECTOR_MACOS_LOG_SHOW_INFO, MACOS_GET_LOG_PARAMS(log_show_array));
    } else {
        merror(LOGCOLLECTOR_MACOS_LOG_SHOW_EXEC_ERROR, MACOS_GET_LOG_PARAMS(log_show_array));
    }

    os_free(timestamp);
    free_strarray(log_show_array);
}

/**
 * @brief Creates the environment for collecting "stream" logs on MacOS Systems
 * @param log_cmd_array logreader structure with `log stream`'s input arguments and w_macos_log_config_t structure to be set
 */
STATIC INLINE void w_macos_create_log_stream_env(logreader * current) {

    char ** log_stream_array = NULL;

    current->macos_log->stream_wfd = NULL;

    log_stream_array = w_macos_create_log_stream_array(current->query, current->query_level, current->query_type);

    current->macos_log->stream_wfd = w_macos_log_exec(log_stream_array, W_BIND_STDOUT | W_BIND_STDERR);

    if (current->macos_log->stream_wfd != NULL) {
        if (current->macos_log->state == LOG_NOT_RUNNING) {
            current->macos_log->state = LOG_RUNNING_STREAM;
        }
        minfo(LOGCOLLECTOR_MACOS_LOG_STREAM_INFO, MACOS_GET_LOG_PARAMS(log_stream_array));
    } else {
        merror(LOGCOLLECTOR_MACOS_LOG_STREAM_EXEC_ERROR, MACOS_GET_LOG_PARAMS(log_stream_array));
    }

    free_strarray(log_stream_array);
}

void w_macos_create_log_env(logreader * current) {

    current->macos_log->state = LOG_NOT_RUNNING;

    if (w_macos_is_log_executable()) {

        /* If only-future-events is disabled, so past events are retrieved, then `log show` is also executed */
        if (!current->future) {
            char ** current_settings_list = w_macos_create_log_stream_array(current->query, current->query_level, current->query_type);
            char * current_settings = w_strcat_list(current_settings_list, ' ');
            char * last_settings = w_macos_get_log_settings();

            if (last_settings == NULL) {
                w_macos_set_log_settings(current_settings);
            } else if (strcmp(current_settings, last_settings) != 0) {
                mdebug1("Current predicate differs from last one used. Discarding old events");
                w_macos_set_log_settings(current_settings);
            } else {
                w_macos_create_log_show_env(current);
            }
            os_free(last_settings);
            os_free(current_settings);
            free_strarray(current_settings_list);
        }

        w_macos_create_log_stream_env(current);
    }
    os_free(current->file);
    current->fp = NULL;
}

void w_macos_set_last_log_timestamp(char * timestamp) {

    w_rwlock_wrlock(&macos_log_vault.mutex);
    strncpy(macos_log_vault.timestamp, timestamp, OS_LOGCOLLECTOR_TIMESTAMP_SHORT_LEN);
    w_rwlock_unlock(&macos_log_vault.mutex);
}

char * w_macos_get_last_log_timestamp(void) {

    char * short_timestamp = NULL;
    w_rwlock_rdlock(&macos_log_vault.mutex);
    w_strdup(macos_log_vault.timestamp, short_timestamp);
    w_rwlock_unlock(&macos_log_vault.mutex);
    return short_timestamp;
}

void w_macos_set_log_settings(char * settings) {

    w_rwlock_wrlock(&macos_log_vault.mutex);
    os_free(macos_log_vault.settings)
    w_strdup(settings, macos_log_vault.settings);
    w_rwlock_unlock(&macos_log_vault.mutex);
}

char * w_macos_get_log_settings(void) {

    char * settings = NULL;
    w_rwlock_rdlock(&macos_log_vault.mutex);
    w_strdup(macos_log_vault.settings, settings);
    w_rwlock_unlock(&macos_log_vault.mutex);
    return settings;
}

#endif
