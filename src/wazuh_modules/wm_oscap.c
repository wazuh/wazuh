/*
 * Wazuh Module for OpenSCAP
 * Copyright (C) 2016 Wazuh Inc.
 * April 25, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static wm_oscap *oscap;                             // Pointer to configuration
static int queue_fd;                                // Output queue file descriptor

static void* wm_oscap_main(wm_oscap *oscap);        // Module main function. It won't return
static void wm_oscap_setup(wm_oscap *_oscap);       // Setup module
static void wm_oscap_cleanup();                     // Cleanup function, doesn't overwrite wm_cleanup
static void wm_oscap_check();                       // Check configuration, disable flag
static void wm_oscap_run(wm_oscap_eval *eval);      // Run an OpenSCAP policy
static void wm_oscap_info();                        // Show module info
static void wm_oscap_destroy(wm_oscap *oscap);      // Destroy data

const char *WM_OSCAP_LOCATION = "wodle_open-scap";  // Location field for event sending

// OpenSCAP module context definition

const wm_context WM_OSCAP_CONTEXT = {
    "open-scap",
    (wm_routine)wm_oscap_main,
    (wm_routine)wm_oscap_destroy
};

// OpenSCAP module main function. It won't return.

void* wm_oscap_main(wm_oscap *oscap) {
    wm_oscap_eval *eval;
    time_t time_start = 0;
    time_t time_sleep = 0;

    // Check configuration and show debug information

    wm_oscap_setup(oscap);
    verbose("%s: INFO: Module started.", WM_OSCAP_LOGTAG);

    // First sleeping

    if (!oscap->flags.scan_on_start) {
        time_start = time(NULL);

        if (oscap->state.next_time > time_start) {
            verbose("%s: INFO: Waiting for turn to evaluate.", WM_OSCAP_LOGTAG);
            sleep(oscap->state.next_time - time_start);
        }
    }

    // Main loop

    while (1) {

        verbose("%s: INFO: Starting evaluation.", WM_OSCAP_LOGTAG);

        // Get time and execute
        time_start = time(NULL);

        for (eval = oscap->evals; eval; eval = eval->next)
            if (!eval->flags.error)
                wm_oscap_run(eval);

        time_sleep = time(NULL) - time_start;

        verbose("%s: INFO: Evaluation finished.", WM_OSCAP_LOGTAG);

        if ((time_t)oscap->interval >= time_sleep) {
            time_sleep = oscap->interval - time_sleep;
            oscap->state.next_time = oscap->interval + time_start;
        } else {
            merror("%s: ERROR: Interval overtaken.", WM_OSCAP_LOGTAG);
            time_sleep = oscap->state.next_time = 0;
        }

        if (wm_state_io(&WM_OSCAP_CONTEXT, WM_IO_WRITE, &oscap->state, sizeof(oscap->state)) < 0)
            merror("%s: ERROR: Couldn't save running state.", WM_OSCAP_LOGTAG);

        // If time_sleep=0, yield CPU
        sleep(time_sleep);
    }

    return NULL;
}

// Setup module

void wm_oscap_setup(wm_oscap *_oscap) {
    int i;

    oscap = _oscap;
    wm_oscap_check();

    // Read running state

    if (wm_state_io(&WM_OSCAP_CONTEXT, WM_IO_READ, &oscap->state, sizeof(oscap->state)) < 0)
        memset(&oscap->state, 0, sizeof(oscap->state));

    if (isDebug())
        wm_oscap_info();

    // Connect to socket

    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        sleep(WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        merror("%s: ERROR: Can't connect to queue.", WM_OSCAP_LOGTAG);
        pthread_exit(NULL);
    }

    // Cleanup exiting

    atexit(wm_oscap_cleanup);
}

// Cleanup function, doesn't overwrite wm_cleanup

void wm_oscap_cleanup() {
    close(queue_fd);
    verbose("%s: INFO: Module finished.", WM_OSCAP_LOGTAG);
}

// Run an OpenSCAP policy

void wm_oscap_run(wm_oscap_eval *eval) {
    char *command = NULL;
    int status;
    char *output = NULL;
    char *line;
    char *arg_profiles = NULL;
    wm_oscap_profile *profile;

    // Create arguments

    wm_strcat(&command, WM_OSCAP_SCRIPT_PATH, '\0');

    switch (eval->type) {
    case WM_OSCAP_XCCDF:
        wm_strcat(&command, "--xccdf", ' ');
        break;
    case WM_OSCAP_OVAL:
        wm_strcat(&command, "--oval", ' ');
        break;
    default:
        merror("%s: ERROR: Unspecified content type for file '%s'. This shouln't happen.", WM_OSCAP_LOGTAG, eval->path);
        pthread_exit(NULL);
    }

    wm_strcat(&command, eval->path, ' ');

    for (profile = eval->profiles; profile; profile = profile->next)
        wm_strcat(&arg_profiles, profile->name, ',');

    if (arg_profiles) {
        wm_strcat(&command, "--profiles", ' ');
        wm_strcat(&command, arg_profiles, ' ');
    }

    if (eval->xccdf_id) {
        wm_strcat(&command, "--xccdf-id", ' ');
        wm_strcat(&command, eval->xccdf_id, ' ');
    }

    if (eval->oval_id) {
        wm_strcat(&command, "--oval-id", ' ');
        wm_strcat(&command, eval->oval_id, ' ');
    }

    if (eval->ds_id) {
        wm_strcat(&command, "--ds-id", ' ');
        wm_strcat(&command, eval->ds_id, ' ');
    }

    if (eval->cpe) {
        wm_strcat(&command, "--cpe", ' ');
        wm_strcat(&command, eval->cpe, ' ');
    }

    // Execute

    debug1("%s: DEBUG: Launching command: %s", WM_OSCAP_LOGTAG, command);

    switch (wm_exec(command, &output, &status, eval->timeout)) {
    case 0:
        if (status > 0) {
            merror("%s: WARN: Ignoring content '%s' due to error (%d).", WM_OSCAP_LOGTAG, eval->path, status);
            debug2("%s: DEBUG: OUTPUT: %s", WM_OSCAP_LOGTAG, output);
            eval->flags.error = 1;
        }

        break;

    case WM_ERROR_TIMEOUT:
        free(output);
        output = NULL;
        wm_strcat(&output, "oscap: ERROR: Timeout expired.", '\0');
        merror("%s: ERROR: Timeout expired executing '%s'.", WM_OSCAP_LOGTAG, eval->path);
        break;

    default:
        merror("%s: ERROR: Internal calling. Exiting...", WM_OSCAP_LOGTAG);
        pthread_exit(NULL);
    }

    for (line = strtok(output, "\n"); line; line = strtok(NULL, "\n"))
        SendMSG(queue_fd, line, WM_OSCAP_LOCATION, WODLE_MQ);

    free(output);
    free(command);
    free(arg_profiles);
}

// Check configuration

void wm_oscap_check() {
    wm_oscap_eval *eval;

    // Check if evals

    if (!oscap->evals) {
        merror("%s: WARN: No evals defined. Exiting...", WM_OSCAP_LOGTAG);
        pthread_exit(NULL);
    }

    // Check if interval

    if (!oscap->interval)
        oscap->interval = WM_DEF_INTERVAL;

    // Check timeout and flags for evals

    for (eval = oscap->evals; eval; eval = eval->next) {
        if (!eval->timeout)
            if (!(eval->timeout = oscap->timeout))
                eval->timeout = WM_DEF_TIMEOUT;
    }
}

// Show module info

void wm_oscap_info() {
    wm_oscap_eval *eval;
    wm_oscap_profile *profile;

    verbose("%s: INFO: SHOW_MODULE_OSCAP: ----", WM_OSCAP_LOGTAG);
    verbose("%s: INFO: Timeout: %d", WM_OSCAP_LOGTAG, oscap->timeout);
    verbose("%s: INFO: Policies:", WM_OSCAP_LOGTAG);

    for (eval = (wm_oscap_eval*)oscap->evals; eval; eval = eval->next){
        verbose("%s: INFO: [%s]", WM_OSCAP_LOGTAG, eval->path);
        verbose("%s: INFO: \tProfiles:", WM_OSCAP_LOGTAG);

        for (profile = (wm_oscap_profile*)eval->profiles; profile; profile = profile->next)
            verbose("%s: INFO: \t\tName: %s", WM_OSCAP_LOGTAG, profile->name);
    }

    verbose("%s: INFO: SHOW_MODULE_OSCAP: ----", WM_OSCAP_LOGTAG);
}

// Destroy data

void wm_oscap_destroy(wm_oscap *oscap) {
    wm_oscap_eval *cur_eval;
    wm_oscap_eval *next_eval;
    wm_oscap_profile *cur_profile;
    wm_oscap_profile *next_profile;

    // Delete evals

    for (cur_eval = oscap->evals; cur_eval; cur_eval = next_eval) {

        // Delete profiles

        for (cur_profile = cur_eval->profiles; cur_profile; cur_profile = next_profile) {
            next_profile = cur_profile->next;
            free(cur_profile->name);
            free(cur_profile);
        }

        next_eval = cur_eval->next;
        free(cur_eval->path);
        free(cur_eval->xccdf_id);
        free(cur_eval->oval_id);
        free(cur_eval->ds_id);
        free(cur_eval->cpe);
        free(cur_eval);
    }

    free(oscap);
}
