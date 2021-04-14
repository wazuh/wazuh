/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "logcollector.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif


/**
 * @brief Get log from `log stream`.
 *
 * @param buffer readed log output
 * @param length max lenth
 * @param stream log file
 * @param oslog_cfg oslog configuration
 * @return  true if a new log was collected.
 *          false otherwise
 */
STATIC bool oslog_getlog(char * buffer, int length, FILE * stream, w_oslog_config_t * oslog_cfg);

/**
 * @brief Restore read context from backup
 *
 * Restores the buffer from a context backup
 * Buffer must be allocated, function does not check, allocate or release memory from the buffer
 * @param buffer Destination buffer
 * @param newline_offset output of the last new line offsett
 * @param ctxt context backup
 * @return true if a context was restored. Otherwise returns false
 */
STATIC bool oslog_ctxt_restore(char * buffer, int * newline_offset, w_oslog_ctxt_t * ctxt);

/**
 * @brief Generate a backup of the reading context
 *
 * If the backup exists, the new content is appended and updates the new offset
 * @param buffer to backup
 * @param ctxt backup destination
 */
STATIC void oslog_ctxt_backup(char * buffer, w_oslog_ctxt_t * ctxt);

/**
 * @brief Clean a context backup
 *
 * @param ctxt context backup to clean
 */
STATIC void oslog_ctxt_clean(w_oslog_ctxt_t * ctxt);

/**
 * @brief check if a context in a backup expired
 *
 * @param timeout A timeout that a context without updating is valid.
 * @param ctxt context to check
 * @return true if the context does not exist or expired. Otherwise returns false
 */
STATIC bool oslog_ctxt_is_expired(time_t timeout, w_oslog_ctxt_t * ctxt);

/**
 * @brief Get pointer to the beginning of the last line in the string s.
 * 
 * @warning If the `str` ends with a `\n`, it is ignored.
 * @param str to get last line
 * @return pointer to the beginning of the last line
 */
STATIC char * oslog_get_lastline(char * str);

void * read_oslog(logreader * lf, int * rc, int drop_it) {
    char read_buffer[OS_MAXSTR + 1];
    int count_lines = 0;
    bool rlog;
    const int max_line_len = OS_MAXSTR - OS_LOG_HEADER;

    if (can_read() == 0) {
        return NULL;
    }

    read_buffer[OS_MAXSTR] = '\0';
    *rc = 0;

    while (rlog = oslog_getlog(read_buffer, max_line_len, lf->fp, lf->oslog),
           rlog && (maximum_lines == 0 || count_lines < maximum_lines)) {

        if (drop_it == 0) {
            w_msg_hash_queues_push(read_buffer, lf->file, strlen(read_buffer) + 1, lf->log_target, LOCALFILE_MQ);
        }
        count_lines++;
    }

    return NULL;
}

STATIC bool oslog_getlog(char * buffer, int length, FILE * stream, w_oslog_config_t * oslog_cfg) {

    bool retval = false;

    int offset = 0;
    int newline_offset = 0;
    char * str = buffer;
    int chunk_sz = 0;
    char * retstr;

    *str = '\0';

    /* Check if a context restore is needed for incomplete logs */
    if (oslog_ctxt_restore(str, &newline_offset, &oslog_cfg->ctxt)) {
        offset = strlen(str);

        /* If the context it's expired then free it and return log */
        if (oslog_ctxt_is_expired((time_t) OSLOG_TIMEOUT_OUT, &oslog_cfg->ctxt)) {
            oslog_ctxt_clean(&oslog_cfg->ctxt);
            /* delete last end-of-line character  */
            if (offset == newline_offset) {
                buffer[newline_offset] = '\0';
            }
            retval = true;
            return retval;
        }

        str += offset;
    }

    /* Get stream data, the minimum chunk size of the log is one line */
    while (can_read() && (retstr = fgets(str, length - offset, stream)) != NULL) {

        chunk_sz = strlen(str);
        offset += chunk_sz;
        str += chunk_sz;
        bool full_buffer = false;
        bool str_endline = (*(str - 1) == '\n');
        char * last_line = NULL;
        bool split = false;

        /* Avoid fgets infinite loop behavior when size parameter is 1
         * If we didn't get the new line, because the size is large, send what we got so far.
         */
        if (offset + 1 == length) {
            // Clean context and force send the log
            oslog_ctxt_clean(&oslog_cfg->ctxt);
            full_buffer = true;
        } else if (!str_endline) {
            mdebug2("Inclomplete oslog message...");
            /* Save the context */
            oslog_ctxt_backup(buffer, &oslog_cfg->ctxt);
            continue;
        }

        /* If this point has been reached, it is because:
            - The buffer is full, one log is incomplete/complete
            - The buffer is full, there is a complete log and an incomplete log.
            - The buffer is full, there are remnants of one multiline 
            - The buffer is full, there are remnants of one multiline, and incomplete log
            - The buffer is not full, there are remnants of one multiline 
            - The buffer is not full, there are remnants of a multiline and incomplete log
            - The buffer is not full, there is a complete log and incomplete log
            - The buffer is not full, there is a log that may be multiline.
        If a new log is received, we store it in the context and send the oldest one.
        */

       last_line = oslog_get_lastline(buffer);

        /* If there are 2 logs, they are separated for sending */
        if (str_endline && last_line != NULL) {
            split =  w_expression_match(oslog_cfg->ctxt.start_log_regex, last_line, NULL, NULL);
        }

        if (!split && full_buffer) {
            /* If only one-line log in the buffer it is sent and the rest of the line is discarded, 
             * otherwise, it must be split, store the last line and send them separately.
             * If the line is incomplete, it is impossible to differentiate 
             * whether it belongs to the current log or to a new log.
             */
            if (!str_endline) {
                if (last_line == NULL) {
                    // Discard the rest of the one line log, moving the pointer to the next end of line
                    while (true) {
                        char c = fgetc(stream); // if stream its closed ?, check errno and break loop
                        if (c == '\n' || c == '\0' || c == EOF) {
                            break;
                        }
                    }
                    mdebug2("Max lenght oslog message... The remaining surplus was discarded");
                } else {
                    split = true;
                    mdebug2("Max lenght oslog message... The remaining surplus was send separately");
                }
            }
        }

        /* split the logs */
        if (w_expression_match(oslog_cfg->ctxt.start_log_regex, &buffer[newline_offset == 0 ? 0 : newline_offset + 1], NULL, NULL)) {
            buffer[newline_offset] = '\0';
            *str = '\0';
            strncpy(oslog_cfg->ctxt.buffer, &buffer[newline_offset] + 1, offset - newline_offset + 1);
            oslog_cfg->ctxt.buffer[offset - newline_offset + 1] = '\0';
            char * last_nl = strrchr (oslog_cfg->ctxt.buffer, '\n');
            if(last_nl != NULL) {
                oslog_cfg->ctxt.newline_offset = last_nl - oslog_cfg->ctxt.buffer;
            }
            retval = true;
            break;
        } else if (full_buffer) {
            break;
        }

        

    }

    /*
    if (retstr == NULL && errno == EWOULDBLOCK) {
        // no data in log stream 
    }
    */

    return retval;
}

STATIC bool oslog_ctxt_restore(char * buffer, int * newline_offset, w_oslog_ctxt_t * ctxt) {

    if (ctxt->buffer[0] == '\0') {
        return false;
    }

    strcpy(buffer, ctxt->buffer);
    *newline_offset = ctxt->newline_offset;
    return true;
}

STATIC bool oslog_ctxt_is_expired(time_t timeout, w_oslog_ctxt_t * ctxt) {

    if (time(NULL) - ctxt->timestamp > timeout) {
        return true;
    }

    return false;
}

STATIC void oslog_ctxt_clean(w_oslog_ctxt_t * ctxt) {

    ctxt->buffer[0] = '\0';
    ctxt->newline_offset = 0;
    ctxt->timestamp = 0;

}

STATIC void oslog_ctxt_backup(char * buffer, w_oslog_ctxt_t * ctxt) {

    size_t current_bsize = strlen(buffer);
    size_t old_size = strlen(ctxt->buffer);
    char * last_nl = NULL;

    /* Without new content there is nothing to do */
    if (old_size == current_bsize) {
        return;
    }
    
    last_nl = strrchr (ctxt->buffer, '\n');

    /* Backup */
    strcpy(ctxt->buffer + old_size, buffer + old_size);
    ctxt->timestamp = time(NULL);
    ctxt->newline_offset = (last_nl == NULL) ? 0 : last_nl - ctxt->buffer;
}

STATIC char * oslog_get_lastline(char * str) {
    
    char * retval = NULL;
    char ignored_char = '\0';
    size_t size = 0;

    if (str == NULL || *str == '\0') {
        return retval;
    }

    /* Ignore last character */
    size = strlen(str);

    ignored_char = str[size - 1];
    str[size - 1] = '\0';

    retval = strrchr (str, '\n');
    str[size - 1] = ignored_char;

    return retval;
}