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
#include "macos_es_log.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief Checks whether a line is exactly one JSON object, without keeping the parsed tree
 *
 * Trailing data after the object is rejected, so a fragment that merely starts like JSON never passes.
 * @param line NUL-terminated line to validate
 * @return true if `line` is a single complete JSON object, false otherwise
 */
STATIC bool w_macos_es_is_valid_json(const char * line);

/**
 * @brief Discards buffered bytes up to (and including) the next '\n'
 *
 * On a non-blocking pipe this may stop before reaching a newline if no more data is currently available.
 * @param stream eslogger's non-blocking output pipe
 * @return true if the '\n' was consumed, false if the read stopped first (the record is still unfinished)
 */
STATIC bool w_macos_es_drain_line(FILE * stream);

/**
 * @brief Assembles one complete NDJSON record from `eslogger`'s output, buffering partial lines
 *
 * Unlike ULS's `w_macos_log_getlog()`, there is no multi-line splitting, header detection or
 * timeout-driven force-send: each `eslogger` record is exactly one JSON line. The only machinery needed
 * is the partial-line accumulator, because the pipe is non-blocking and a record can span multiple
 * `fgets` reads, and the discard state that drops the rest of an oversize record across reads.
 *
 * @param [out] buffer receives the complete line (without the trailing '\n') when true is returned
 * @param length buffer's max length
 * @param stream eslogger's non-blocking output pipe
 * @param macos_es_cfg macos-es runtime config (holds the partial-line backup and the discard state)
 * @return true if a complete record was assembled into buffer, false otherwise (no data yet, the line
 *         is still incomplete, or an oversize record is being discarded)
 */
STATIC bool w_macos_es_getlog(char * buffer, int length, FILE * stream, w_macos_es_config_t * macos_es_cfg);

/**
 * @brief Checks whether the `eslogger` process has exited and, if so, releases it and schedules
 * the next spawn attempt with exponential backoff
 *
 * @param lf localfile's logreader structure; `lf->macos_es->wfd` must be non-NULL
 */
STATIC void w_macos_es_check_exit(logreader * lf);

void * read_macos_es(logreader * lf, int * rc, __attribute__((unused)) int drop_it) {

    const int MAX_LINE_LEN = OS_MAXSTR - OS_LOG_HEADER;
    char read_buffer[OS_MAXSTR + 1];
    unsigned long size = 0;
    int count_logs = 0;

    *rc = 0;

    if (lf->macos_es == NULL) {
        return NULL;
    }

    w_macos_es_ensure_running(lf);

    if (lf->macos_es->wfd == NULL) {
        return NULL; // still backing off, or the spawn attempt above just failed again
    }

    if (can_read() == 0) {
        return NULL;
    }

    read_buffer[OS_MAXSTR] = '\0';

    while ((maximum_lines == 0 || count_logs < maximum_lines)
           && w_macos_es_getlog(read_buffer, MAX_LINE_LEN, lf->macos_es->wfd->file_out, lf->macos_es)) {

        size = strlen(read_buffer);

        if (size > 0) {
            if (!check_ignore_and_restrict(lf->regex_ignore, lf->regex_restrict, read_buffer)) {
                if (w_macos_es_is_valid_json(read_buffer)) {
                    w_msg_hash_queues_push(read_buffer, MACOS_ES, size + 1, lf->log_target, LOCALFILE_MQ);
                } else {
                    mwarn(LOGCOLLECTOR_MACOS_ES_INV_JSON, read_buffer);
                }
            }
        } else {
            mdebug2("macOS ES: Discarding empty message.");
        }

        count_logs++;
    }

    /* Only check liveness once the loop stopped because the pipe had nothing left to read, not because
     * it hit the per-tick `logcollector.max_lines` cap; `maximum_lines == 0` means no cap at all. */
    if (maximum_lines == 0 || count_logs < maximum_lines) {
        w_macos_es_check_exit(lf);
    }

    return NULL;
}

STATIC bool w_macos_es_is_valid_json(const char * line) {

    cJSON * json = cJSON_ParseWithOpts(line, NULL, true);
    bool valid = cJSON_IsObject(json);

    cJSON_Delete(json);
    return valid;
}

STATIC bool w_macos_es_drain_line(FILE * stream) {

    int c;

    do {
        c = fgetc(stream);
    } while (c != '\n' && c != EOF);

    return c == '\n';
}

STATIC bool w_macos_es_getlog(char * buffer, int length, FILE * stream, w_macos_es_config_t * macos_es_cfg) {

    int offset = 0;
    char * str = buffer;

    *str = '\0';

    /* Finishes dropping an oversize record whose tail had not arrived yet on a previous read */
    if (macos_es_cfg->discarding) {
        if (!w_macos_es_drain_line(stream)) {
            return false;
        }
        macos_es_cfg->discarding = false;
    }

    /* Restores a partial line saved from a previous, non-blocking-interrupted read */
    if (macos_es_cfg->ctxt_buffer[0] != '\0') {
        strncpy(buffer, macos_es_cfg->ctxt_buffer, length - 1);
        buffer[length - 1] = '\0';
        macos_es_cfg->ctxt_buffer[0] = '\0';
        offset = strlen(buffer);
        str = buffer + offset;
    }

    if (!can_read() || fgets(str, length - offset, stream) == NULL) {
        if (offset > 0) {
            /* Nothing new arrived: keep the partial line for the next read */
            strncpy(macos_es_cfg->ctxt_buffer, buffer, OS_MAXSTR - 1);
        }
        return false;
    }

    offset += strlen(str);

    if (buffer[offset - 1] != '\n') {
        if (offset + 1 >= length) {
            /* Oversize record: drop it and resynchronize to the next line, even across reads */
            mdebug1("macOS ES: Maximum message length reached. The record was discarded.");
            macos_es_cfg->discarding = !w_macos_es_drain_line(stream);
            buffer[0] = '\0';
            return false;
        }

        /* Incomplete line: save it and wait for the rest on a later read */
        strncpy(macos_es_cfg->ctxt_buffer, buffer, OS_MAXSTR - 1);
        return false;
    }

    buffer[offset - 1] = '\0'; // Removes the trailing '\n'
    return true;
}

STATIC void w_macos_es_check_exit(logreader * lf) {

    int status = 0;
    pid_t pid = lf->macos_es->wfd->pid;
    pid_t retval = waitpid(pid, &status, WNOHANG);

    if (retval == 0) {
        return; // still running
    }

    if (retval != pid) {
        merror(WAITPID_ERROR, errno, strerror(errno));
        return;
    }

    /* The child exited. Only a run that stayed alive long enough resets the failure count: resetting
     * on every exit would let a process that dies right away restart the backoff from the 5s base forever. */
    if (time(NULL) - lf->macos_es->started_at >= MACOS_ES_HEALTHY_UPTIME_SEC) {
        lf->macos_es->failures = 0;
    }

    if (w_macos_es_note_failure(lf->macos_es)) {
        if (WIFSIGNALED(status)) {
            merror(LOGCOLLECTOR_MACOS_ES_CHILD_KILLED, pid, WTERMSIG(status));
        } else {
            merror(LOGCOLLECTOR_MACOS_ES_CHILD_EXITED, pid, WEXITSTATUS(status));
        }
    }

    w_macos_es_release_reaped(lf);
}

#endif
