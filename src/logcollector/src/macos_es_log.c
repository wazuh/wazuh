/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#if defined(Darwin) || (defined(__linux__) && defined(WAZUH_UNIT_TESTING))
#include "macos_es_log.h"

/* Removes STATIC qualifier from the tests */
#ifdef WAZUH_UNIT_TESTING
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief Checks whether the `eslogger` command can be executed or not by using waccess()
 *
 * Does not log: the caller decides, through the failure throttle, whether the error is reported.
 * @return true when `eslogger` can be executed, false otherwise (errno is set by waccess()).
 */
STATIC bool w_macos_es_is_executable(void) {

    return waccess(ESLOGGER_CMD_STR, X_OK) == 0;
}

/**
 * @brief Builds the `eslogger <event1> <event2> ...` argv from the comma-separated `events` list
 *
 * @param events comma-separated, already-validated event names (see w_logcollector_get_macos_es_events())
 * @return NULL-terminated, individually allocated argv array. Free with free_strarray().
 */
STATIC char ** w_macos_es_create_argv(const char * events) {

    size_t num_events = 1;
    size_t i;
    char ** event_tokens = NULL;
    char ** argv = NULL;

    for (const char * p = events; *p; p++) {
        if (*p == ',') {
            num_events++;
        }
    }

    event_tokens = OS_StrBreak(',', events, num_events);

    os_calloc(num_events + 2, sizeof(char *), argv);
    w_strdup(ESLOGGER_CMD_STR, argv[0]);

    for (i = 0; i < num_events; i++) {
        argv[i + 1] = event_tokens[i];
    }
    argv[num_events + 1] = NULL;

    os_free(event_tokens);

    return argv;
}

/**
 * @brief Executes `eslogger` with its arguments and sets its output pipe to non-blocking
 *
 * @param argv NULL-terminated argument array, argv[0] the executable path
 * @return A pointer to a fulfilled wfd_t structure, on success, or NULL
 */
STATIC wfd_t * w_macos_es_exec(char ** argv) {

    int pipe_fd = -1;
    int pipe_fd_flags = 0;
    wfd_t * wfd = wpopenv(*argv, argv, W_BIND_STDOUT | W_BIND_STDERR);

    if (wfd == NULL) {
        merror(WPOPENV_ERROR, strerror(errno), errno);
        return NULL;
    }

    pipe_fd = fileno(wfd->file_out); // Gets the file descriptor from a file pointer

    if (pipe_fd <= 0) {
        merror(LOGCOLLECTOR_MACOS_ES_FP_TO_FD_ERROR, strerror(errno), errno);
        wpclose(wfd);
        return NULL;
    }

    pipe_fd_flags = fcntl(pipe_fd, F_GETFL, 0); // Gets current flags

    if (pipe_fd_flags < 0) {
        merror(GET_FLAGS_ERROR, strerror(errno), errno);
        wpclose(wfd);
        return NULL;
    }

    if (fcntl(pipe_fd, F_SETFL, pipe_fd_flags | O_NONBLOCK) < 0) { // Adds the NON-BLOCKING flag
        merror(SET_FLAGS_ERROR, strerror(errno), errno);
        wpclose(wfd);
        return NULL;
    }

    return wfd;
}

/**
 * @brief Drops any partial record kept from the previous `eslogger` process
 *
 * A respawned process starts a fresh stream, so a partial line or a pending discard from the old one
 * must not be glued onto its first record.
 * @param config macos-es runtime config
 */
STATIC void w_macos_es_reset_ctxt(w_macos_es_config_t * config) {

    config->ctxt_buffer[0] = '\0';
    config->discarding = false;
}

bool w_macos_es_note_failure(w_macos_es_config_t * config) {

    time_t now = time(NULL);
    unsigned int delay = MACOS_ES_BACKOFF_BASE_SEC;
    unsigned int i;

    config->failures++;

    for (i = 1; i < config->failures && delay < MACOS_ES_BACKOFF_CAP_SEC; i++) {
        delay *= MACOS_ES_BACKOFF_MULTIPLIER;
    }
    if (delay > MACOS_ES_BACKOFF_CAP_SEC) {
        delay = MACOS_ES_BACKOFF_CAP_SEC;
    }

    config->next_spawn_at = now + delay;

    if (config->failures <= MACOS_ES_WARN_THROTTLE_AFTER || now - config->last_warn_at >= MACOS_ES_WARN_THROTTLE_SEC) {
        config->last_warn_at = now;
        return true;
    }

    return false;
}

void w_macos_es_release(logreader * lf) {

    if (lf->macos_es == NULL || lf->macos_es->wfd == NULL) {
        return;
    }

    if (lf->macos_es->wfd->pid > 0) {
        kill(lf->macos_es->wfd->pid, SIGTERM);
    }

    wpclose(lf->macos_es->wfd);
    lf->macos_es->wfd = NULL;
    w_macos_es_reset_ctxt(lf->macos_es);
}

void w_macos_es_release_reaped(logreader * lf) {

    if (lf->macos_es == NULL || lf->macos_es->wfd == NULL) {
        return;
    }

    if (lf->macos_es->wfd->file_in != NULL) {
        fclose(lf->macos_es->wfd->file_in);
    }
    if (lf->macos_es->wfd->file_out != NULL) {
        fclose(lf->macos_es->wfd->file_out);
    }

    os_free(lf->macos_es->wfd);
    w_macos_es_reset_ctxt(lf->macos_es);
}

void w_macos_es_ensure_running(logreader * lf) {

    char ** argv = NULL;
    char * cmd_str = NULL;

    if (lf->macos_es->wfd != NULL) {
        return;
    }

    if (lf->macos_es->next_spawn_at != 0 && time(NULL) < lf->macos_es->next_spawn_at) {
        return;
    }

    if (!w_macos_es_is_executable()) {
        int error = errno;

        if (w_macos_es_note_failure(lf->macos_es)) {
            merror(ACCESS_ERROR, ESLOGGER_CMD_STR, strerror(error), error);
        }
        return;
    }

    argv = w_macos_es_create_argv(lf->events);
    cmd_str = w_strcat_list(argv, ' ');

    lf->macos_es->wfd = w_macos_es_exec(argv);

    if (lf->macos_es->wfd != NULL) {
        /* Not throttled: after a failure streak (e.g. Full Disk Access granted again) this line is the only
         * sign of recovery, and the backoff already spaces it out */
        minfo(LOGCOLLECTOR_MACOS_ES_INFO, cmd_str);
        lf->macos_es->started_at = time(NULL);
        // `failures` is deliberately NOT reset here: only a run that stays alive for at least
        // MACOS_ES_HEALTHY_UPTIME_SEC (checked in w_macos_es_check_exit) may reset it. Resetting
        // on every successful spawn would let a fast crash loop (spawn, crash, spawn, crash...)
        // restart the backoff from the 5s base forever.
    } else if (w_macos_es_note_failure(lf->macos_es)) {
        merror(LOGCOLLECTOR_MACOS_ES_EXEC_ERROR, cmd_str);
    }

    os_free(cmd_str);
    free_strarray(argv);
}

/**
 * @brief Drops the `events` names that this macOS's `eslogger` does not know
 *
 * `eslogger` refuses its whole argument list when a single name is unknown, so one typo in `<events>` would
 * stop every event. The catalog comes from `eslogger --list-events`, which needs neither root nor Full Disk
 * Access. When the catalog cannot be read, the list is kept as is and `eslogger` reports an unknown name itself.
 * @param lf localfile's logreader structure; `lf->events` is replaced with the filtered list
 */
STATIC void w_macos_es_drop_unknown_events(logreader * lf) {

    char line[OS_SIZE_256];
    char needle[OS_SIZE_256 + 2];
    char * catalog = NULL;
    char * known = NULL;
    char * events = NULL;
    char * name = NULL;
    char * saveptr = NULL;
    FILE * fp = NULL;

    if (lf->events == NULL) {
        return;
    }

    if (fp = popen(ESLOGGER_CMD_STR " --list-events", "r"), fp == NULL) {
        mdebug1("macOS ES: Cannot list the eslogger events: %s (%d). The configured events are used as is.",
                strerror(errno), errno);
        return;
    }

    /* Stored as ",name1,name2,...," so that a lookup is a single strstr() for ",<name>," */
    os_strdup(",", catalog);
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\n")] = '\0';
        if (*line != '\0') {
            wm_strcat(&catalog, line, '\0');
            wm_strcat(&catalog, ",", '\0');
        }
    }

    if (pclose(fp) != 0 || strcmp(catalog, ",") == 0) {
        mdebug1("macOS ES: Cannot list the eslogger events. The configured events are used as is.");
        os_free(catalog);
        return;
    }

    os_strdup(lf->events, events);
    for (name = strtok_r(events, ",", &saveptr); name != NULL; name = strtok_r(NULL, ",", &saveptr)) {
        snprintf(needle, sizeof(needle), ",%s,", name);
        if (strstr(catalog, needle) != NULL) {
            wm_strcat(&known, name, ',');
        } else {
            mwarn(LOGCOLLECTOR_INV_ES_EVENT, name, "events");
        }
    }

    if (known == NULL) {
        mwarn(LOGCOLLECTOR_NO_VALID_ES_EVENTS, "events");
        os_strdup(MACOS_ES_DEFAULT_EVENTS, known);
    }

    os_free(lf->events);
    lf->events = known;
    os_free(events);
    os_free(catalog);
}

void w_macos_es_create_env(logreader * lf) {

    /* A missing binary is permanent: warn once and leave the collector disabled instead of retrying forever */
    if (waccess(ESLOGGER_CMD_STR, F_OK) != 0) {
        mwarn(LOGCOLLECTOR_MACOS_ES_UNAVAILABLE, ESLOGGER_CMD_STR);
    } else {
        os_calloc(1, sizeof(w_macos_es_config_t), lf->macos_es);
        w_macos_es_drop_unknown_events(lf);
        w_macos_es_ensure_running(lf);
    }

    os_free(lf->file);
    lf->fp = NULL;
}

#endif
