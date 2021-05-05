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
#include "oslog.h"

// Removes STATIC/INLINE qualifiers from the tests
#ifdef WAZUH_UNIT_TESTING
#define STATIC
#define INLINE
#else
#define STATIC static
#define INLINE inline
#endif

STATIC w_oslog_status_t oslog_status = { .mutex = PTHREAD_RWLOCK_INITIALIZER, .timestamp = "", .settings = NULL};

/**
 * @brief Validates whether the predicate is valid or not
 * @param predicate Contains the `log`'s predicate filter to be used as a string
 * @return true if valid, otherwise false
 */
STATIC INLINE bool w_oslog_is_predicate_valid(char * predicate) {

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
STATIC char ** w_oslog_create_show_array(char * start_date, char * query, char * level, int type) {

    char * predicate = NULL;
    char * type_predicate = NULL;

    size_t oslog_array_idx = 0;
    char ** oslog_array = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), oslog_array);

    // Adding `log` and `show` to the array
    w_strdup(LOG_CMD_STR, oslog_array[oslog_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, oslog_array[oslog_array_idx++]);

    // Adding the style lines to the array (`--style syslog`)
    w_strdup(STYLE_OPT_STR, oslog_array[oslog_array_idx++]);
    w_strdup(SYSLOG_STR, oslog_array[oslog_array_idx++]);

    // Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`)
    w_strdup(SHOW_START_OPT_STR, oslog_array[oslog_array_idx++]);
    w_strdup(start_date, oslog_array[oslog_array_idx++]);

    // Log Show's Level section: adds, or not, the `--debug` and/or `--info`. This that assumes `debug` contains `info`
    if (level != NULL) {
        if (strcmp(level, OSLOG_LEVEL_DEFAULT_STR) != 0) {
            // If the level is not `default`, because it is set to `info` or `debug`, then the info logs are acquired
            w_strdup(SHOW_INFO_OPT_STR, oslog_array[oslog_array_idx++]);
            if (strcmp(level, OSLOG_LEVEL_DEBUG_STR) == 0) {
                // Only when the level is set to `debug` the debug logs are acquired
                w_strdup(SHOW_DEBUG_OPT_STR, oslog_array[oslog_array_idx++]);
            }
        }
    }

    // Log Stream's Type section
    if (type != 0) {
        if (type & OSLOG_TYPE_ACTIVITY) {
            w_strdup(SHOW_TYPE_ACTIVITY_STR, type_predicate);
        }
        if (type & OSLOG_TYPE_LOG) {
            if (type_predicate == NULL) {
                w_strdup(SHOW_TYPE_LOG_STR, type_predicate);
            } else {
                type_predicate = w_strcat(type_predicate, SHOW_OR_TYPE_LOG_STR, strlen(SHOW_OR_TYPE_LOG_STR));
            }
        }
        if (type & OSLOG_TYPE_TRACE) {
            if (type_predicate == NULL) {
                w_strdup(SHOW_TYPE_TRACE_STR, type_predicate);
            } else {
                type_predicate = w_strcat(type_predicate, SHOW_OR_TYPE_TRACE_STR, strlen(SHOW_OR_TYPE_TRACE_STR));
            }
        }
    }

    // Log Stream's (full) Predicate section
    if (query != NULL) {
        if (w_oslog_is_predicate_valid(query)) {
            w_strdup(PREDICATE_OPT_STR, oslog_array[oslog_array_idx++]);

            if (type_predicate != NULL) {
                const int PREDICATE_SIZE = strlen(query) + strlen(type_predicate) + strlen(QUERY_AND_TYPE_PREDICATE);
                os_calloc(PREDICATE_SIZE, sizeof(char), predicate);
                snprintf(predicate, PREDICATE_SIZE, QUERY_AND_TYPE_PREDICATE, query, type_predicate);
            }
            w_strdup(predicate, oslog_array[oslog_array_idx++]);

        } else if (type_predicate != NULL) {
            w_strdup(PREDICATE_OPT_STR, oslog_array[oslog_array_idx++]);
            w_strdup(type_predicate, oslog_array[oslog_array_idx++]);
        }
    } else if (type_predicate != NULL) {
        w_strdup(PREDICATE_OPT_STR, oslog_array[oslog_array_idx++]);
        w_strdup(type_predicate, oslog_array[oslog_array_idx++]);
    }

    os_free(predicate);
    os_free(type_predicate);

    return oslog_array;
}

/**
 * @brief Generates the `log stream` command array with its arguments
 * @param predicate Contains the `log stream`'s predicate filter to be used as a string
 * @param level Contains, or not, the `log stream`'s level filter to be used as a string (default/info/debug)
 * @param type Contains the `log stream`'s type filters to be used (as combined bit flags)
 * @return A pointer to an array containing the executable arguments
 */
STATIC char ** w_oslog_create_stream_array(char * predicate, char * level, int type) {

    size_t oslog_array_idx = 0;
    char ** oslog_array = NULL;

    os_calloc(MAX_LOG_STREAM_CMD_ARGS + 1, sizeof(char *), oslog_array);

    // Adding `log` and `stream` to the array
    w_strdup(LOG_CMD_STR, oslog_array[oslog_array_idx++]);
    w_strdup(LOG_STREAM_OPT_STR, oslog_array[oslog_array_idx++]);

    // Adding the style lines to the array (`--style syslog`)
    w_strdup(STYLE_OPT_STR, oslog_array[oslog_array_idx++]);
    w_strdup(SYSLOG_STR, oslog_array[oslog_array_idx++]);

    // Log Stream's Type section (`--type`)
    if (type != 0) {
        if (type & OSLOG_TYPE_ACTIVITY) {
            w_strdup(TYPE_OPT_STR, oslog_array[oslog_array_idx++]);
            w_strdup(OSLOG_TYPE_ACTIVITY_STR, oslog_array[oslog_array_idx++]);
        }
        if (type & OSLOG_TYPE_LOG) {
            w_strdup(TYPE_OPT_STR, oslog_array[oslog_array_idx++]);
            w_strdup(OSLOG_TYPE_LOG_STR, oslog_array[oslog_array_idx++]);
        }
        if (type & OSLOG_TYPE_TRACE) {
            w_strdup(TYPE_OPT_STR, oslog_array[oslog_array_idx++]);
            w_strdup(OSLOG_TYPE_TRACE_STR, oslog_array[oslog_array_idx++]);
        }
    }

    // Log Stream's Level section  (`--level`)
    if (level != NULL) {
        w_strdup(LEVEL_OPT_STR, oslog_array[oslog_array_idx++]);
        w_strdup(level, oslog_array[oslog_array_idx++]);
    }

    // Log Stream's Predicate section
    if (predicate != NULL) {
        if (w_oslog_is_predicate_valid(predicate)) {
            w_strdup(PREDICATE_OPT_STR, oslog_array[oslog_array_idx++]);

            w_strdup(predicate, oslog_array[oslog_array_idx++]);
        }
    }

    return oslog_array;
}

/**
 * @brief Executes the `log stream/show` command with its arguments and sets to non-blocking the output pipe
 * @param oslog_array Contains the arguments of the command to be executed
 * @param flags Are the flags to be used along with wpopenv()
 * @return A pointer to a fulfilled wfd_t structure, on success, or NULL
 */
STATIC wfd_t * w_oslog_exec(char ** oslog_array, u_int32_t flags) {

    int oslog_fd = -1;
    int oslog_fd_flags = 0;
    wfd_t * oslog_wfd = wpopenv(*oslog_array, oslog_array, flags);

    if (oslog_wfd == NULL) {
        merror(WPOPENV_ERROR, strerror(errno), errno);
    } else {
        // The file descriptor, from which the output of `log stream` will be read, is set to non-blocking
        oslog_fd = fileno(oslog_wfd->file);                 // Gets the file descriptor from a file pointer

        if (oslog_fd <= 0) {
            merror(FP_TO_FD_ERROR, strerror(errno), errno);
            wpclose(oslog_wfd);
            oslog_wfd = NULL;
        } else {
            oslog_fd_flags = fcntl(oslog_fd, F_GETFL, 0);   // Gets current flags

            if (oslog_fd_flags < 0) {
                merror(GET_FLAGS_ERROR, strerror(errno), errno);
                wpclose(oslog_wfd);
                oslog_wfd = NULL;
            } else {
                oslog_fd_flags |= O_NONBLOCK;               // Adds the NON-BLOCKING flag to current flags
                const int set_flags_retval = fcntl(oslog_fd, F_SETFL, oslog_fd_flags);  // Sets the new Flags

                if (set_flags_retval < 0) {
                    merror(SET_FLAGS_ERROR, strerror(errno), errno);
                    wpclose(oslog_wfd);
                    oslog_wfd = NULL;
                }
            }
        }
    }

    return oslog_wfd;
}

/**
 * @brief Checks whether the `log` command can be executed or not by using the access() function
 * 
 * @return true when `log` command can be executed, false otherwise.
 */
STATIC INLINE bool w_oslog_is_log_executable(void) {

    const int retval = access(LOG_CMD_STR, X_OK);
    if (retval == 0) {
        return true;
    }
    merror(ACCESS_ERROR, LOG_CMD_STR, strerror(errno), errno);
    return false;
}

/**
 * @brief Creates the environment for collecting "show" logs on MacOS Systems
 * @param oslog_array logreader structure with `log show`'s input arguments and w_oslog_config_t structure to be set
 */
STATIC INLINE void w_oslog_create_show_env(logreader * current) {

    char ** log_show_array = NULL;

    char * timestamp = w_oslog_get_timestamp();

    if (timestamp == NULL) {
        return;
    }

    current->oslog->show_wfd = NULL;

    log_show_array = w_oslog_create_show_array(timestamp, current->query, current->query_level, current->query_type);

    current->oslog->show_wfd = w_oslog_exec(log_show_array, W_BIND_STDOUT | W_BIND_STDERR);

    if (current->oslog->show_wfd != NULL) {
        current->oslog->ctxt.state = LOG_RUNNING_SHOW;
        minfo(LOGCOLLECTOR_LOG_SHOW_INFO, OSLOG_GET_LOG_PARAMS(log_show_array));
    } else {
        merror(LOGCOLLECTOR_OSLOG_SHOW_EXEC_ERROR, OSLOG_GET_LOG_PARAMS(log_show_array));
    }

    os_free(timestamp);
    free_strarray(log_show_array);
}

/**
 * @brief Creates the environment for collecting "stream" logs on MacOS Systems
 * @param oslog_array logreader structure with `log stream`'s input arguments and w_oslog_config_t structure to be set
 */
STATIC INLINE void w_oslog_create_stream_env(logreader * current) {

    char ** log_stream_array = NULL;

    current->oslog->stream_wfd = NULL;

    log_stream_array = w_oslog_create_stream_array(current->query, current->query_level, current->query_type);

    current->oslog->stream_wfd = w_oslog_exec(log_stream_array, W_BIND_STDOUT | W_BIND_STDERR);

    if (current->oslog->stream_wfd != NULL) {
        if (current->oslog->ctxt.state == LOG_NOT_RUNNING) {
            current->oslog->ctxt.state = LOG_RUNNING_STREAM;
        }
        minfo(LOGCOLLECTOR_LOG_STREAM_INFO, OSLOG_GET_LOG_PARAMS(log_stream_array));
    } else {
        merror(LOGCOLLECTOR_OSLOG_STREAM_EXEC_ERROR, OSLOG_GET_LOG_PARAMS(log_stream_array));
    }

    free_strarray(log_stream_array);
}

void w_oslog_create_env(logreader * current) {

    current->oslog->ctxt.state = LOG_NOT_RUNNING;

    if (w_oslog_is_log_executable()) {

        /* If only-future-events is disabled, so past events are retrieved, then `log show` is also executed */
        if (!current->future) {
            char ** current_settings_list = w_oslog_create_stream_array(current->query, current->query_level, current->query_type);
            char * current_settings = w_strcat_list(current_settings_list, ' ');
            char * last_settings = w_oslog_get_settings();

            if (last_settings == NULL) {
                w_oslog_set_settings(current_settings);
            } else if (strcmp(current_settings, last_settings) != 0) {
                mdebug1("Current predicate differs from last one used. Discarding old events");
                w_oslog_set_settings(current_settings);
            } else {
                w_oslog_create_show_env(current);
            }
            os_free(last_settings);
            os_free(current_settings);
            free_strarray(current_settings_list);
        }

        w_oslog_create_stream_env(current);
    }
    os_free(current->file);
    current->fp = NULL;
}

void w_oslog_set_timestamp(char * timestamp) {

    w_rwlock_wrlock(&oslog_status.mutex);
    strncpy(oslog_status.timestamp, timestamp, OS_LOGCOLLECTOR_TIMESTAMP_SHORT_LEN);
    w_rwlock_unlock(&oslog_status.mutex);
}

char * w_oslog_get_timestamp() {

    char * short_timestamp = NULL;
    w_rwlock_rdlock(&oslog_status.mutex);
    w_strdup(oslog_status.timestamp, short_timestamp);
    w_rwlock_unlock(&oslog_status.mutex);
    return short_timestamp;
}

void w_oslog_set_settings(char * settings) {

    w_rwlock_wrlock(&oslog_status.mutex);
    os_free(oslog_status.settings)
    w_strdup(settings, oslog_status.settings);
    w_rwlock_unlock(&oslog_status.mutex);
}

char * w_oslog_get_settings() {

    char * settings = NULL;
    w_rwlock_rdlock(&oslog_status.mutex);
    w_strdup(oslog_status.settings, settings);
    w_rwlock_unlock(&oslog_status.mutex);
    return settings;
}

#endif
