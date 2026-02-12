/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
#include "macos_log.h"

/* Removes STATIC/INLINE qualifiers from the tests */
#ifdef WAZUH_UNIT_TESTING
#define STATIC
#define INLINE
#else
#define STATIC static
#define INLINE inline
#endif

STATIC w_macos_log_vault_t macos_log_vault = { .mutex = PTHREAD_RWLOCK_INITIALIZER, .timestamp = "",
                                               .settings = NULL, .is_valid_data = false };

STATIC char * macos_codename = NULL;

STATIC w_sysinfo_helpers_t * sysinfo = NULL;
/**
 * @brief Check if agent is running on macOS Sierra
 *
 * @return true if agent is running in macOS Sierra. false otherwise
 */
bool w_is_macos_sierra() {

    if (macos_codename != NULL && strcmp(macos_codename, MACOS_SIERRA_CODENAME_STR) == 0) {
        return true;
    }
    return false;
}

/**
 * @brief Prepend `script` command arguments when macOS Sierra is being used
 *
 * @param log_cmd_array array of arguments
 * @param log_cmd_array_idx index of the array
 */
STATIC INLINE void w_macos_add_sierra_support(char ** log_cmd_array, size_t * log_cmd_array_idx) {

    w_strdup(SCRIPT_CMD_STR, log_cmd_array[(*log_cmd_array_idx)++]);
    w_strdup(SCRIPT_CMD_ARGS, log_cmd_array[(*log_cmd_array_idx)++]);
    w_strdup(SCRIPT_CMD_SINK, log_cmd_array[(*log_cmd_array_idx)++]);
}

/**
 * @brief Validates whether the predicate is valid or not
 * @param predicate Contains the `log`'s predicate filter to be used as a string
 * @return true if valid, otherwise false
 */
STATIC INLINE bool w_macos_is_log_predicate_valid(char * predicate) {

    if (strlen(predicate) > 0) {
        return true;
    }
    return false;
}

/**
 * @brief Adds to the `log show` aguments array the level arguments
 *
 * @param log_cmd_array `log show` array of arguments
 * @param log_cmd_array_idx Index of the `log show` array
 * @param level String that contains the `log show` levels
 */
STATIC INLINE void w_macos_log_show_array_add_level(char ** log_cmd_array, size_t * log_cmd_array_idx, char * level) {

    /* Log Show's Level section: adds, or not, `--debug` and/or `--info`. This that assumes `debug` contains `info` */
    if (level != NULL && strcmp(level, MACOS_LOG_LEVEL_DEFAULT_STR) != 0) {

        /* If the level is not `default`, because it is set to `info` or `debug`, then the info logs are acquired */
        w_strdup(SHOW_INFO_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);

        if (strcmp(level, MACOS_LOG_LEVEL_DEBUG_STR) == 0) {
            /* Only when the level is set to `debug` the debug logs are acquired */
            w_strdup(SHOW_DEBUG_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);
        }
    }
}

/**
 * @brief Creates the predicate fragment related to the type that will be then concatenated with the rest of the filter
 *
 * @param type Contains the `log show`'s type filters to be used (as combined bit flags)
 * @return char * containing a string with the predicate fragment related to the type or NULL if no type filter was set
 */
STATIC INLINE char * w_macos_log_show_create_type_predicate(int type) {

    char * type_predicate = NULL;

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

    return type_predicate;
}

/**
 * @brief Adds to the `log show` aguments array the predicate arguments by joining user's predicate with the "type" one
 *
 * @param log_cmd_array `log show` array of arguments
 * @param log_cmd_array_idx index of the `log show` array
 * @param query String containing the user's raw predicate
 * @param type_predicate String containing the predicate's type fragment
 */
STATIC INLINE void w_macos_log_show_array_add_predicate(char ** log_cmd_array, size_t * log_cmd_array_idx, char * query,
                                                        char * type_predicate) {

    char * predicate = NULL;

    if (query != NULL) {
        if (w_macos_is_log_predicate_valid(query)) {
            w_strdup(PREDICATE_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);

            if (type_predicate != NULL) {
                const int PREDICATE_SIZE = strlen(query) + strlen(type_predicate) + strlen(QUERY_AND_TYPE_PREDICATE);
                os_calloc(PREDICATE_SIZE, sizeof(char), predicate);
                snprintf(predicate, PREDICATE_SIZE, QUERY_AND_TYPE_PREDICATE, query, type_predicate);

            } else {
                w_strdup(query, predicate);
            }
            w_strdup(predicate, log_cmd_array[(*log_cmd_array_idx)++]);
            os_free(predicate);

        } else if (type_predicate != NULL) {
            w_strdup(PREDICATE_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);
            w_strdup(type_predicate, log_cmd_array[(*log_cmd_array_idx)++]);
        }
    } else if (type_predicate != NULL) {
        w_strdup(PREDICATE_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);
        w_strdup(type_predicate, log_cmd_array[(*log_cmd_array_idx)++]);
    }
}

/**
 * @brief Generates the `log show` command array with its arguments
 *
 * @param predicate Contains the `log show`'s predicate filter to be used as a string
 * @param level Contains, or not, the `log show`'s level filter to be used as a string (default/info/debug)
 * @param type Contains the `log show`'s type filters to be used (as combined bit flags)
 * @return A pointer to an array containing the executable arguments
 */
STATIC INLINE char ** w_macos_create_log_show_array(char * start_date, char * query, char * level, int type) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    char * type_predicate = NULL;

    os_calloc(MAX_LOG_SHOW_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    if (w_is_macos_sierra()) {
        w_macos_add_sierra_support(log_cmd_array, &log_cmd_array_idx);
    }

    /* Adding `log` and `show` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_SHOW_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the starting date lines to the array (`--start 2021-04-27 12:29:25-0700`) */
    w_strdup(SHOW_START_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(start_date, log_cmd_array[log_cmd_array_idx++]);

    w_macos_log_show_array_add_level(log_cmd_array, &log_cmd_array_idx, level);

    type_predicate = w_macos_log_show_create_type_predicate(type);

    w_macos_log_show_array_add_predicate(log_cmd_array, &log_cmd_array_idx, query, type_predicate);

    os_free(type_predicate);

    return log_cmd_array;
}

/**
 * @brief Adds to the `log stream` aguments array the level arguments
 *
 * @param log_cmd_array `log stream` array of arguments
 * @param log_cmd_array_idx index of the `log stream` array
 * @param level string that contains the `log stream` levels
 */
STATIC INLINE void w_macos_log_stream_array_add_level(char ** log_cmd_array, size_t * log_cmd_array_idx, char * level) {

    if (level != NULL) {
        w_strdup(LEVEL_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);
        w_strdup(level, log_cmd_array[(*log_cmd_array_idx)++]);
    }
}

/**
 * @brief Adds to the `log stream` aguments array the type arguments
 *
 * @param log_cmd_array `log stream` array of arguments
 * @param log_cmd_array_idx index of the `log stream` array
 * @param type Contains the `log stream`'s type filters to be used (as combined bit flags)
 */
STATIC INLINE void w_macos_log_stream_array_add_type(char ** log_cmd_array, size_t * log_cmd_array_idx, int type) {

    if (type != 0) {
        if (type & MACOS_LOG_TYPE_ACTIVITY) {
            w_strdup(TYPE_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);
            w_strdup(MACOS_LOG_TYPE_ACTIVITY_STR, log_cmd_array[(*log_cmd_array_idx)++]);
        }
        if (type & MACOS_LOG_TYPE_LOG) {
            w_strdup(TYPE_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);
            w_strdup(MACOS_LOG_TYPE_LOG_STR, log_cmd_array[(*log_cmd_array_idx)++]);
        }
        if (type & MACOS_LOG_TYPE_TRACE) {
            w_strdup(TYPE_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);
            w_strdup(MACOS_LOG_TYPE_TRACE_STR, log_cmd_array[(*log_cmd_array_idx)++]);
        }
    }
}

/**
 * @brief Adds to the `log stream` aguments array the predicate arguments
 *
 * @param log_cmd_array `log stream` array of arguments
 * @param log_cmd_array_idx index of the `log stream` array
 * @param predicate string that contains the `log stream` predicate
 */
STATIC INLINE void w_macos_log_stream_array_add_predicate(char ** log_cmd_array, size_t * log_cmd_array_idx,
                                                          char * predicate) {

    if (predicate != NULL && w_macos_is_log_predicate_valid(predicate)) {
        w_strdup(PREDICATE_OPT_STR, log_cmd_array[(*log_cmd_array_idx)++]);

        w_strdup(predicate, log_cmd_array[(*log_cmd_array_idx)++]);
    }
}

/**
 * @brief Generates the `log stream` command array with its arguments
 *
 * @param predicate Contains the `log stream`'s predicate filter to be used as a string
 * @param level Contains, or not, the `log stream`'s level filter to be used as a string (default/info/debug)
 * @param type Contains the `log stream`'s type filters to be used (as combined bit flags)
 * @return A pointer to an array containing the executable arguments
 */
STATIC char ** w_macos_create_log_stream_array(char * predicate, char * level, int type) {

    size_t log_cmd_array_idx = 0;
    char ** log_cmd_array = NULL;

    os_calloc(MAX_LOG_STREAM_CMD_ARGS + 1, sizeof(char *), log_cmd_array);

    if (w_is_macos_sierra()) {
        w_macos_add_sierra_support(log_cmd_array, &log_cmd_array_idx);
    }

    /* Adding `log` and `stream` to the array */
    w_strdup(LOG_CMD_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(LOG_STREAM_OPT_STR, log_cmd_array[log_cmd_array_idx++]);

    /* Adding the style lines to the array (`--style syslog`) */
    w_strdup(STYLE_OPT_STR, log_cmd_array[log_cmd_array_idx++]);
    w_strdup(SYSLOG_STR, log_cmd_array[log_cmd_array_idx++]);

    w_macos_log_stream_array_add_type(log_cmd_array, &log_cmd_array_idx, type);

    w_macos_log_stream_array_add_level(log_cmd_array, &log_cmd_array_idx, level);

    w_macos_log_stream_array_add_predicate(log_cmd_array, &log_cmd_array_idx, predicate);

    return log_cmd_array;
}

/**
 * @brief Executes the `log stream/show` command with its arguments and sets to non-blocking the output pipe
 *
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
        /* The file descriptor, from which the output of `log stream` will be read, is set to non-blocking */
        log_pipe_fd = fileno(macos_log_wfd->file_out); // Gets the file descriptor from a file pointer

        if (log_pipe_fd <= 0) {
            merror(FP_TO_FD_ERROR, strerror(errno), errno);
            wpclose(macos_log_wfd);
            macos_log_wfd = NULL;
        } else {
            log_pipe_fd_flags = fcntl(log_pipe_fd, F_GETFL, 0); // Gets current flags

            if (log_pipe_fd_flags < 0) {
                merror(GET_FLAGS_ERROR, strerror(errno), errno);
                wpclose(macos_log_wfd);
                macos_log_wfd = NULL;
            } else {
                log_pipe_fd_flags |= O_NONBLOCK; // Adds the NON-BLOCKING flag to current flags
                const int set_flags_retval = fcntl(log_pipe_fd, F_SETFL, log_pipe_fd_flags); // Sets the new Flags

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
 * @brief Checks whether the `log` command can be executed or not by using the waccess() function
 * @warning if macOS Sierra is beeing used, also `script` command will be checked.
 * @return true when `log` command can be executed, false otherwise.
 */
STATIC INLINE bool w_macos_is_log_executable(void) {

    if (w_is_macos_sierra() && waccess(SCRIPT_CMD_STR, X_OK) != 0) {
        merror(ACCESS_ERROR, SCRIPT_CMD_STR, strerror(errno), errno);
        return false;
    }

    const int retval = waccess(LOG_CMD_STR, X_OK);
    if (retval == 0) {
        return true;
    }
    merror(ACCESS_ERROR, LOG_CMD_STR, strerror(errno), errno);
    return false;
}

/**
 * @brief Creates the environment for collecting "show" logs on macOS Systems
 *
 * @param lf localfile's logreader structure with `log show`'s arguments and its configuration structure to be set
 */
STATIC INLINE void w_macos_create_log_show_env(logreader * lf) {

    char ** log_show_array = NULL;

    char * timestamp = w_macos_get_last_log_timestamp();

    lf->macos_log->processes.show.wfd = NULL;

    if (timestamp[0] == '\0') {
        os_free(timestamp);
        return;
    }

    log_show_array = w_macos_create_log_show_array(timestamp, lf->query, lf->query_level, lf->query_type);

    lf->macos_log->processes.show.wfd = w_macos_log_exec(log_show_array, W_BIND_STDOUT | W_BIND_STDERR);

    char * log_show_str = w_strcat_list(log_show_array, ' ');

    if (lf->macos_log->processes.show.wfd != NULL) {
        lf->macos_log->state = LOG_RUNNING_SHOW;
        minfo(LOGCOLLECTOR_MACOS_LOG_SHOW_INFO, log_show_str);
    } else {
        merror(LOGCOLLECTOR_MACOS_LOG_SHOW_EXEC_ERROR, log_show_str);
    }

    os_free(timestamp);
    os_free(log_show_str);
    free_strarray(log_show_array);
}

/**
 * @brief Creates the environment for collecting "stream" logs on MacOS Systems
 *
 * @param lf localfile's logreader structure with `log stream`'s arguments and its configuration structure to be set
 */
STATIC INLINE void w_macos_create_log_stream_env(logreader * lf) {

    char ** log_stream_array = NULL;

    lf->macos_log->processes.stream.wfd = NULL;

    log_stream_array = w_macos_create_log_stream_array(lf->query, lf->query_level, lf->query_type);

    lf->macos_log->processes.stream.wfd = w_macos_log_exec(log_stream_array, W_BIND_STDOUT | W_BIND_STDERR);

    char * log_stream_str = w_strcat_list(log_stream_array, ' ');

    if (lf->macos_log->processes.stream.wfd != NULL) {
        if (lf->macos_log->state == LOG_NOT_RUNNING) {
            lf->macos_log->state = LOG_RUNNING_STREAM;
        }
        minfo(LOGCOLLECTOR_MACOS_LOG_STREAM_INFO, log_stream_str);
    } else {
        merror(LOGCOLLECTOR_MACOS_LOG_STREAM_EXEC_ERROR, log_stream_str);
    }

    os_free(log_stream_str);
    free_strarray(log_stream_array);
}

void w_macos_create_log_env(logreader * lf, w_sysinfo_helpers_t * global_sysinfo) {

    lf->macos_log->state = LOG_NOT_RUNNING;

    sysinfo = global_sysinfo;

    macos_codename = w_get_os_codename(sysinfo);

    if (w_macos_is_log_executable()) {

        /* `log stream` command parameters are stored to keep track of the settings changes that may occur,
            and to determine whether past events should be retrieved or not */
        char ** current_settings_list = w_macos_create_log_stream_array(lf->query, lf->query_level, lf->query_type);
        lf->macos_log->current_settings = w_strcat_list(current_settings_list, ' ');
        free_strarray(current_settings_list);

        if (macos_codename != NULL) {
            mdebug1("macOS ULS: Creating environment for macOS %s.", macos_codename);
        }

        /* If only-future-events is disabled, so past events are retrieved, then `log show` is also executed */
        if (!lf->future) {
            char * previous_settings = w_macos_get_log_settings();

            if (previous_settings != NULL) {
                if (strcmp(lf->macos_log->current_settings, previous_settings) == 0) {
                    w_macos_create_log_show_env(lf);
                } else {
                    mdebug1("macOS ULS: Current predicate differs from the stored one. Discarding old events.");
                }
                os_free(previous_settings);
            }
        }

        w_macos_create_log_stream_env(lf);
    }
    os_free(lf->file);
    lf->fp = NULL;
}

pid_t w_get_first_child(pid_t parent_pid) {

    pid_t first_child = 0;
    pid_t * childs = w_get_process_childs(sysinfo, parent_pid, 1);
    if (childs != NULL && *childs != 0) {
        first_child = *childs;
    }
    os_free(childs);

    return first_child;
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
    os_free(macos_log_vault.settings);
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


bool w_macos_get_is_valid_data() {

    w_rwlock_rdlock(&macos_log_vault.mutex);
    bool retval = macos_log_vault.is_valid_data;
    w_rwlock_unlock(&macos_log_vault.mutex);

    return retval;
}

void w_macos_set_is_valid_data(bool is_valid) {

    w_rwlock_wrlock(&macos_log_vault.mutex);
    macos_log_vault.is_valid_data = is_valid;
    w_rwlock_unlock(&macos_log_vault.mutex);
}

cJSON * w_macos_get_status_as_JSON(void) {

    if (!w_macos_get_is_valid_data()) {
        return NULL;
    }

    cJSON * macos_log = NULL;
    char * timestamp = w_macos_get_last_log_timestamp();
    char * settings = w_macos_get_log_settings();

    if (w_strlen(timestamp) == OS_LOGCOLLECTOR_TIMESTAMP_SHORT_LEN && settings != NULL) {
        macos_log = cJSON_CreateObject();
        cJSON_AddItemToObject(macos_log, OS_LOGCOLLECTOR_JSON_TIMESTAMP, cJSON_CreateString(timestamp));
        cJSON_AddItemToObject(macos_log, OS_LOGCOLLECTOR_JSON_SETTINGS, cJSON_CreateString(settings));
    }
    os_free(settings);
    os_free(timestamp);

    return macos_log;
}

void w_macos_set_status_from_JSON(cJSON * global_json) {
    cJSON * macos_log = cJSON_GetObjectItem(global_json, OS_LOGCOLLECTOR_JSON_MACOS);
    char * timestamp = cJSON_GetStringValue(cJSON_GetObjectItem(macos_log, OS_LOGCOLLECTOR_JSON_TIMESTAMP));
    char * settings = cJSON_GetStringValue(cJSON_GetObjectItem(macos_log, OS_LOGCOLLECTOR_JSON_SETTINGS));
    if (w_strlen(timestamp) == OS_LOGCOLLECTOR_TIMESTAMP_SHORT_LEN && settings != NULL) {
        w_macos_set_last_log_timestamp(timestamp);
        w_macos_set_log_settings(settings);
        w_macos_set_is_valid_data(true);
    }
}

#endif
