/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))

#include "shared.h"
#include "logcollector.h"
#include "macos_log.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#define INLINE
#else
#define STATIC static
#define INLINE inline
#endif

#define LOG_ERROR_STR    "log:"
#define LOG_ERROR_LENGHT 4

/**
 * @brief Gets a log from macOS log's output
 *
 * @param [out] buffer Contains the read log
 * @param length Buffer's max length
 * @param stream File pointer to log stream's output pipe
 * @param macos_log_cfg macOS log configuration structure
 * @return  true if a new log was collected,
 *          false otherwise
 */
STATIC bool w_macos_log_getlog(char * buffer, int length, FILE * stream, w_macos_log_config_t * macos_log_cfg);

/**
 * @brief Restores the context from backup
 *
 * @warning Notice that `buffer` must be previously allocated, the function does
 * not verify nor allocate or release the buffer memory
 * @param buffer Destination buffer
 * @param ctxt Backup context
 * @return true if the context was restored, otherwise returns false
 */
STATIC bool w_macos_log_ctxt_restore(char * buffer, w_macos_log_ctxt_t * ctxt);

/**
 * @brief Generates a backup of the reading context
 *
 * @param buffer Context to backup
 * @param ctxt Context's backup destination
 */
STATIC INLINE void w_macos_log_ctxt_backup(char * buffer, w_macos_log_ctxt_t * ctxt);

/**
 * @brief Cleans the backup context
 *
 * @warning Notice that this function does not release the context memory
 * @param ctxt context backup to clean
 */
STATIC INLINE void w_macos_log_ctxt_clean(w_macos_log_ctxt_t * ctxt);

/**
 * @brief Checks if a backup context has expired
 *
 * @todo  Remove timeout and use a define
 * @param timeout A timeout that a context without updating is valid
 * @param ctxt Context to check
 * @return true if the context has expired, otherwise returns false
 */
STATIC bool w_macos_is_log_ctxt_expired(time_t timeout, w_macos_log_ctxt_t * ctxt);

/**
 * @brief Gets the pointer to the beginning of the last line contained in the string
 *
 * @warning If `str` has one line, returns NULL
 * @warning If `str` ends with a `\n`, this newline character is ignored
 * @param str String to be analyzed
 * @return Pointer to the beginning of the last line, NULL otherwise
 */
STATIC char * w_macos_log_get_last_valid_line(char * str);

/**
 * @brief Checks whether the `log stream` cli command returns a header or a log.
 *
 * Detects predicate errors and discards filtering headers and columun descriptions.
 * @param macos_log_cfg macOS log configuration structure
 * @param buffer line to check
 * @return Returns false if the read line is a log, otherwise returns true
 */
STATIC bool w_macos_is_log_header(w_macos_log_config_t * macos_log_cfg, char * buffer);

/**
 * @brief Trim milliseconds from a macOS ULS full timestamp
 *
 * @param full_timestamp Timestamp to trim
 * @warning @full_timestamp must be an array with \ref OS_LOGCOLLECTOR_TIMESTAMP_FULL_LEN +1 length
 * @warning @full_timestamp must be in format i.e 2020-11-09 05:45:08.000000-0800
 * @warning return value will be in short format timestamp i.e 2020-11-09 05:45:08-0800
 * @return Allocated short timestamp. NULL on error
 */
STATIC char * w_macos_trim_full_timestamp(const char * full_timestamp);

void * read_macos(logreader * lf, int * rc, __attribute__((unused)) int drop_it) {

    char full_timestamp[OS_LOGCOLLECTOR_TIMESTAMP_FULL_LEN + 1] = {'\0'};
    const int MAX_LINE_LEN = OS_MAXSTR - OS_LOG_HEADER;
    char read_buffer[OS_MAXSTR + 1];
    char * short_timestamp = NULL;
    unsigned long size = 0;
    int count_logs = 0;

    wfd_t * log_mode_wfd = (lf->macos_log->state == LOG_RUNNING_SHOW) ?
                            lf->macos_log->processes.show.wfd : lf->macos_log->processes.stream.wfd;

    if (can_read() == 0) {
        return NULL;
    }

    read_buffer[OS_MAXSTR] = '\0';
    *rc = 0;

    while ((maximum_lines == 0 || count_logs < maximum_lines)
            && w_macos_log_getlog(read_buffer, MAX_LINE_LEN, log_mode_wfd->file_out, lf->macos_log)) {

        size = strlen(read_buffer);
        if (size > 0) {
            /* Check ignore and restrict log regex, if configured. */
            if (check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, read_buffer)) {
                continue;
            }

            w_msg_hash_queues_push(read_buffer, MACOS_LOG_NAME, size + 1, lf->log_target, LOCALFILE_MQ);
            memcpy(full_timestamp, read_buffer, OS_LOGCOLLECTOR_TIMESTAMP_FULL_LEN);
        } else {
            mdebug2("macOS ULS: Discarding empty message.");
        }

        count_logs++;
    }

    short_timestamp = w_macos_trim_full_timestamp(full_timestamp);
    if (short_timestamp != NULL) {
        w_macos_set_last_log_timestamp(short_timestamp);
        if (!lf->macos_log->store_current_settings) {
            w_macos_set_log_settings(lf->macos_log->current_settings);
            lf->macos_log->store_current_settings = true;
        }
        os_free(short_timestamp);
    }

    /* This "if" is true when the amount of readed logs is less than the maximum allowed */
    if (count_logs < maximum_lines) {
        int status = 0;
        int retval = 0;

        /* Checks if the macOS' log process is still alive or exited */
        retval = waitpid(log_mode_wfd->pid, &status, WNOHANG);      // Tries to get the child' "soul"
        if (retval == log_mode_wfd->pid) {                          // This is true in the case that the child exited
            if (lf->macos_log->state == LOG_RUNNING_SHOW) {
                if (status == 0) {
                    // Normal process' end of execution
                    minfo(MACOS_LOG_SHOW_CHILD_EXITED, log_mode_wfd->pid, status);
                } else {
                    // Abnormal process' end of execution
                    merror(MACOS_LOG_SHOW_CHILD_EXITED, log_mode_wfd->pid, status);
                }
                w_macos_release_log_show();
                if (lf->macos_log->processes.stream.wfd != NULL) {
                    /* This variable is reseted as, by changing the log mode, stream header must be processed as well */
                    /* In case a multi-line context is still stored, it is forced to send it */
                    lf->macos_log->is_header_processed = false;
                    lf->macos_log->ctxt.force_send = (lf->macos_log->ctxt.buffer[0] != '\0');
                    lf->macos_log->state = LOG_RUNNING_STREAM;
                } else {
                    lf->macos_log->state = LOG_NOT_RUNNING;
                }
            } else {    // LOG_RUNNING_STREAM
                merror(MACOS_LOG_STREAM_CHILD_EXITED, log_mode_wfd->pid, status);
                w_macos_release_log_stream();
                lf->macos_log->state = LOG_NOT_RUNNING;
            }
        } else if (retval != 0) {
            merror(WAITPID_ERROR, errno, strerror(errno));
        }
    }

    return NULL;
}

STATIC bool w_macos_log_getlog(char * buffer, int length, FILE * stream, w_macos_log_config_t * macos_log_cfg) {

    bool retval = false; // This variable will be set to true if there is a buffered log

    int offset = 0;          // Amount of chars in the buffer
    char * str = buffer;     // Auxiliar buffer pointer, it points where the new data will be stored
    int chunk_sz = 0;        // Size of the last read data
    char * last_line = NULL; // Pointer to the last line stored in the buffer
    bool is_buffer_full;     // Will be set to true if the buffer is full (forces data to be sent)
    bool is_endline;         // Will be set to true if the last read line ends with an '\n' character
    bool do_split;           // Indicates whether the buffer will be splited (two chunks at most)

    *str = '\0';

    /* Checks if a context recover is needed for incomplete logs */
    if (w_macos_log_ctxt_restore(str, &macos_log_cfg->ctxt)) {
        offset = strlen(str);

        /* If the context is expired then frees it and returns the log */
        if (w_macos_is_log_ctxt_expired((time_t) MACOS_LOG_TIMEOUT, &macos_log_cfg->ctxt)
           || (macos_log_cfg->ctxt.force_send)) {
            w_macos_log_ctxt_clean(&macos_log_cfg->ctxt);
            /* delete last end-of-line character */
            if (buffer[offset - 1] == '\n') {
                buffer[offset - 1] = '\0';
            }
            /* Force sending the last log of `log show` */
            retval = (macos_log_cfg->is_header_processed || macos_log_cfg->ctxt.force_send);
            macos_log_cfg->ctxt.force_send = false;

            return retval;
        }

        str += offset;
    }

    /* Gets streamed data, the minimum chunk size of a log is one line */
    while (can_read() && (fgets(str, length - offset, stream) != NULL)) {

        chunk_sz = strlen(str);
        offset += chunk_sz;
        str += chunk_sz;
        last_line = NULL;
        is_buffer_full = false;
        is_endline = (*(str - 1) == '\n');
        do_split = false;

        /* Deletes CR from macOS Sierra */
        if (is_endline && offset >= 2 && *(str - 2) == '\r') {
            str--;
            offset--;
            *str = '\0';
            *(str - 1) = '\n';
        }

        /* Avoid fgets infinite loop behavior when size parameter is 1
         * If we didn't get the new line, because the size is large, send what we got so far.
         */
        if (offset + 1 == length) {
            // Cleans the context and forces to send a log
            w_macos_log_ctxt_clean(&macos_log_cfg->ctxt);
            is_buffer_full = true;
        } else if (!is_endline) {
            mdebug2("macOS ULS: Incomplete message.");
            // Saves the context
            w_macos_log_ctxt_backup(buffer, &macos_log_cfg->ctxt);
            continue;
        }

        /* Checks if the first line is the header or an error in the predicate. */
        if (!macos_log_cfg->is_header_processed) {
            /* Get child PID in case of macOS Sierra */
            if (w_is_macos_sierra()) {
                if (macos_log_cfg->processes.show.wfd != NULL && macos_log_cfg->processes.show.child == 0) {
                    macos_log_cfg->processes.show.child =
                        w_get_first_child(macos_log_cfg->processes.show.wfd->pid);
                }
                if (macos_log_cfg->processes.stream.wfd != NULL && macos_log_cfg->processes.stream.child == 0) {
                    macos_log_cfg->processes.stream.child =
                        w_get_first_child(macos_log_cfg->processes.stream.wfd->pid);
                }
            }
            /* Processes and discards lines up to the first log */
            if (w_macos_is_log_header(macos_log_cfg, buffer)) {
                // Forces to continue reading
                w_macos_log_ctxt_clean(&macos_log_cfg->ctxt);
                retval = true;
                *buffer = '\0';
                break;
            }
        }

        /* If this point has been reached, there is something to process in the buffer. */

        last_line = w_macos_log_get_last_valid_line(buffer);

        if (isDebug() == 2) {
            char * d_str_msg = (last_line == NULL) ?  buffer : (last_line +1);
            bool is_chunck_message = (int) w_strlen(d_str_msg) - 1 > sample_log_length;
            int  d_str_lenght = is_chunck_message ? sample_log_length : (int) w_strlen(d_str_msg) - 1;

            mdebug2("Reading macOS message: '%.*s'%s", d_str_lenght, d_str_msg, is_chunck_message  ? "..." : "");

        }

        /* If there are 2 logs, they should be splited before sending them */
        if (is_endline && last_line != NULL) {
            do_split = w_expression_match(macos_log_cfg->log_start_regex, last_line + 1, NULL, NULL);
        }

        if (!do_split && is_buffer_full) {
            /* If the buffer is full but the message is larger than the buffer size,
             * then the rest of the message is discarded up to the '\n' character.
             */
            if (!is_endline) {
                if (last_line == NULL) {
                    int c;
                    // Discards the rest of the log, up to the end of line
                    do {
                        c = fgetc(stream);
                    } while (c != '\n' && c != '\0' && c != EOF);
                    mdebug2("macOS ULS: Maximum message length reached. The remainder was discarded.");
                } else {
                    do_split = true;
                    mdebug2("macOS ULS: Maximum message length reached. The remainder will be send separately.");
                }
            }
        }

        /* splits the logs */
        /* If a new log is received, we store it in the context and send the previous one. */
        if (do_split) {
            w_macos_log_ctxt_clean(&macos_log_cfg->ctxt);
            *last_line = '\0';
            strncpy(macos_log_cfg->ctxt.buffer, last_line + 1, offset - (last_line - buffer) + 1);
            macos_log_cfg->ctxt.timestamp = time(NULL);
        } else if (!is_buffer_full) {
            w_macos_log_ctxt_backup(buffer, &macos_log_cfg->ctxt);
        }

        if (do_split || is_buffer_full) {
            retval = true;
            /* deletes last end-of-line character  */
            if (buffer[offset - 1] == '\n') {
                buffer[offset - 1] = '\0';
            }
            break;
        }
    }

    return retval;
}

STATIC bool w_macos_log_ctxt_restore(char * buffer, w_macos_log_ctxt_t * ctxt) {

    if (ctxt->buffer[0] == '\0') {
        return false;
    }

    strcpy(buffer, ctxt->buffer);
    return true;
}

STATIC bool w_macos_is_log_ctxt_expired(time_t timeout, w_macos_log_ctxt_t * ctxt) {

    if (time(NULL) - ctxt->timestamp > timeout) {
        return true;
    }

    return false;
}

STATIC INLINE void w_macos_log_ctxt_clean(w_macos_log_ctxt_t * ctxt) {

    ctxt->buffer[0] = '\0';
    ctxt->timestamp = 0;
}

STATIC INLINE void w_macos_log_ctxt_backup(char * buffer, w_macos_log_ctxt_t * ctxt) {

    /* Backup */
    strncpy(ctxt->buffer, buffer, OS_MAXSTR - 1);
    ctxt->timestamp = time(NULL);
}

STATIC char * w_macos_log_get_last_valid_line(char * str) {

    char * retval = NULL;
    char ignored_char = '\0';
    size_t size = 0;

    if (str == NULL || *str == '\0') {
        return retval;
    }

    /* Ignores the last character */
    size = strlen(str);

    ignored_char = str[size - 1];
    str[size - 1] = '\0';

    retval = strrchr(str, '\n');
    str[size - 1] = ignored_char;

    return retval;
}

STATIC bool w_macos_is_log_header(w_macos_log_config_t * macos_log_cfg, char * buffer) {

    bool retval = true;
    const ssize_t buffer_size = strlen(buffer);

    /* if the buffer contains a log, then there won't be headers anymore */
    if (w_expression_match(macos_log_cfg->log_start_regex, buffer, NULL, NULL)) {
        macos_log_cfg->is_header_processed = true;
        w_macos_set_is_valid_data(true);
        retval = false;
    }
    /* Error in the execution of the `log stream` cli command, probably there is an error in the predicate. */
    else if (strncmp(buffer, LOG_ERROR_STR, LOG_ERROR_LENGHT) == 0) {

        // "log: error description:\n"
        if (buffer[buffer_size - 2] == ':') {
            buffer[buffer_size - 2] = '\0';
        } else if (buffer[buffer_size - 1] == '\n') {
            buffer[buffer_size - 1] = '\0';
        }
        merror(LOGCOLLECTOR_MACOS_LOG_ERROR_AFTER_EXEC, buffer);
        w_macos_set_is_valid_data(false);
    }
    /* Rows header or remaining error lines */
    else {
        if (buffer[buffer_size - 1] == '\n') {
            buffer[buffer_size - 1] = '\0';
        }
        mdebug2("macOS ULS: Reading other log headers or errors: '%s'.", buffer);
    }

    return retval;
}

STATIC char * w_macos_trim_full_timestamp(const char * full_timestamp) {

    char * short_timestamp = NULL;

    if (w_strlen(full_timestamp) == OS_LOGCOLLECTOR_TIMESTAMP_FULL_LEN) {

        os_calloc(OS_LOGCOLLECTOR_TIMESTAMP_SHORT_LEN + 1, sizeof(char), short_timestamp);
        memcpy(short_timestamp, full_timestamp, OS_LOGCOLLECTOR_TIMESTAMP_BASIC_LEN);
        memcpy(short_timestamp + OS_LOGCOLLECTOR_TIMESTAMP_BASIC_LEN,
                full_timestamp + OS_LOGCOLLECTOR_TIMESTAMP_BASIC_LEN + OS_LOGCOLLECTOR_TIMESTAMP_MS_LEN,
                OS_LOGCOLLECTOR_TIMESTAMP_TZ_LEN);
    }

    return short_timestamp;
}

#endif
