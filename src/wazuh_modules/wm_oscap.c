/*
 * Wazuh Module for OpenSCAP
 * Copyright (C) 2015, Wazuh Inc.
 * April 25, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "wm_exec.h"

#ifdef WIN32
static DWORD WINAPI wm_oscap_main(wm_oscap *arg);       // Module main function. It won't return
#else
static void* wm_oscap_main(wm_oscap *oscap);        // Module main function. It won't return
#endif
static void wm_oscap_destroy(wm_oscap *oscap);      // Destroy data
cJSON *wm_oscap_dump(const wm_oscap *oscap);

// OpenSCAP module context definition

const wm_context WM_OSCAP_CONTEXT = {
    .name = "open-scap",
    .start = (wm_routine)wm_oscap_main,
    .destroy = (void(*)(void *))wm_oscap_destroy,
    .dump = (cJSON * (*)(const void *))wm_oscap_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

#ifndef WIN32

static wm_oscap *oscap;                             // Pointer to configuration
static int queue_fd;                                // Output queue file descriptor

static void wm_oscap_setup(wm_oscap *_oscap);       // Setup module
static void wm_oscap_cleanup();                     // Cleanup function, doesn't overwrite wm_cleanup
static void wm_oscap_check();                       // Check configuration, disable flag
static void wm_oscap_run(wm_oscap_eval *eval);      // Run an OpenSCAP policy
static void wm_oscap_info();                        // Show module info

const char *WM_OSCAP_LOCATION = "wodle_open-scap";  // Location field for event sending

// OpenSCAP module main function. It won't return.

void* wm_oscap_main(wm_oscap *oscap) {

    wm_oscap_eval *eval;
    // Check configuration and show debug information
    wm_oscap_setup(oscap);
    char * timestamp = NULL;
    mtinfo(WM_OSCAP_LOGTAG, "Module started.");

    // Main loop

    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(oscap->scan_config), WM_OSCAP_LOGTAG, oscap->flags.scan_on_start);

        if (oscap->state.next_time == 0) {
            oscap->state.next_time = oscap->scan_config.time_start + time_sleep;
        }

        if (wm_state_io(WM_OSCAP_CONTEXT.name, WM_IO_WRITE, &oscap->state, sizeof(oscap->state)) < 0)
            mterror(WM_OSCAP_LOGTAG, "Couldn't save running state.");

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(oscap->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_OSCAP_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }

        mtinfo(WM_OSCAP_LOGTAG, "Starting evaluation.");

        for (eval = oscap->evals; eval; eval = eval->next)
            if (!eval->flags.error)
                wm_oscap_run(eval);

        mtinfo(WM_OSCAP_LOGTAG, "Evaluation finished.");

    }  while (FOREVER());

    return NULL;
}

// Setup module

void wm_oscap_setup(wm_oscap *_oscap) {

    oscap = _oscap;
    wm_oscap_check();

    // Read running state

    if (wm_state_io(WM_OSCAP_CONTEXT.name, WM_IO_READ, &oscap->state, sizeof(oscap->state)) < 0)
        memset(&oscap->state, 0, sizeof(oscap->state));

    if (isDebug())
        wm_oscap_info();

    // Connect to socket

    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_OSCAP_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting

    atexit(wm_oscap_cleanup);
}

// Cleanup function, doesn't overwrite wm_cleanup

void wm_oscap_cleanup() {
    close(queue_fd);
    mtinfo(WM_OSCAP_LOGTAG, "Module finished.");
}

// Run an OpenSCAP policy

void wm_oscap_run(wm_oscap_eval *eval) {
    char *command = NULL;
    char *arg_profiles = NULL;
    char msg[OS_MAXSTR];
    wm_oscap_profile *profile;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Create arguments

    char * script = NULL;
    os_calloc(PATH_MAX, sizeof(char), script);
    snprintf(script, PATH_MAX, "%s", WM_OSCAP_SCRIPT_PATH);
    wm_strcat(&command, script, '\0');
    os_free(script);

    switch (eval->type) {
    case WM_OSCAP_XCCDF:
        wm_strcat(&command, "--xccdf", ' ');
        break;
    case WM_OSCAP_OVAL:
        wm_strcat(&command, "--oval", ' ');
        break;
    default:
        mterror(WM_OSCAP_LOGTAG, "Unspecified content type for file '%s'. This shouldn't happen.", eval->path);
        os_free(command);
        pthread_exit(NULL);
    }

    wm_strcat(&command, eval->path, ' ');

    for (profile = eval->profiles; profile; profile = profile->next) {
        wm_strcat(&arg_profiles, profile->name, ',');
    }

    if (arg_profiles) {
        wm_strcat(&command, "--profiles", ' ');
        wm_strcat(&command, arg_profiles, ' ');
    }

    os_free(arg_profiles);

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

    // Send rootcheck message

    snprintf(msg, OS_MAXSTR, "Starting OpenSCAP scan. File: %s. ", eval->path);
    SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);

    // Execute

    mtdebug1(WM_OSCAP_LOGTAG, "Launching command: %s", command);

    int status;
    char *output = NULL;
    switch (wm_exec(command, &output, &status, eval->timeout, NULL)) {
    case 0:
        if (status > 0) {
            if (status != 2) {
                mtwarn(WM_OSCAP_LOGTAG, "Ignoring content '%s' due to error (%d).", eval->path, status);
                mtdebug2(WM_OSCAP_LOGTAG, "OUTPUT: %s", output);
            } else {
                mterror(WM_OSCAP_LOGTAG, "OUTPUT: %s", output);
                os_free(command);
                os_free(output);
                pthread_exit(NULL);
            }
            eval->flags.error = 1;
        }

        break;

    case WM_ERROR_TIMEOUT:
        os_free(output);
        output = NULL;
        wm_strcat(&output, "oscap: ERROR: Timeout expired.", '\0');
        mterror(WM_OSCAP_LOGTAG, "Timeout expired executing '%s'.", eval->path);
        break;

    default:
        mterror(WM_OSCAP_LOGTAG, "Internal error. Exiting...");
        os_free(command);
        pthread_exit(NULL);
    }

    os_free(command);

    char *line;
    char *save_ptr = NULL;
    for (line = strtok_r(output, "\n", &save_ptr); line; line = strtok_r(NULL, "\n", &save_ptr)) {
        wm_sendmsg(usec, queue_fd, line, WM_OSCAP_LOCATION, LOCALFILE_MQ);
    }

    os_free(output);

    snprintf(msg, OS_MAXSTR, "Ending OpenSCAP scan. File: %s. ", eval->path);
    wm_sendmsg(usec, queue_fd, msg, "rootcheck", ROOTCHECK_MQ);
}

// Check configuration

void wm_oscap_check() {
    wm_oscap_eval *eval;

    // Check if disabled

    if (!oscap->flags.enabled) {
        mtinfo(WM_OSCAP_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if evals

    if (!oscap->evals) {
        mtwarn(WM_OSCAP_LOGTAG, "No evals defined. Exiting...");
        pthread_exit(NULL);
    }

    // Check timeout and flags for evals

    for (eval = oscap->evals; eval; eval = eval->next) {
        if (!eval->timeout)
            if (!(eval->timeout = oscap->timeout))
                eval->timeout = WM_OSCAP_DEF_TIMEOUT;
    }
}

// Show module info

void wm_oscap_info() {
    wm_oscap_eval *eval;
    wm_oscap_profile *profile;

    mtinfo(WM_OSCAP_LOGTAG, "SHOW_MODULE_OSCAP: ----");
    mtinfo(WM_OSCAP_LOGTAG, "Timeout: %d", oscap->timeout);
    mtinfo(WM_OSCAP_LOGTAG, "Policies:");

    for (eval = (wm_oscap_eval*)oscap->evals; eval; eval = eval->next){
        mtinfo(WM_OSCAP_LOGTAG, "[%s]", eval->path);
        mtinfo(WM_OSCAP_LOGTAG, "\tProfiles:");

        for (profile = (wm_oscap_profile*)eval->profiles; profile; profile = profile->next)
            mtinfo(WM_OSCAP_LOGTAG, "\t\tName: %s", profile->name);
    }

    mtinfo(WM_OSCAP_LOGTAG, "SHOW_MODULE_OSCAP: ----");
}

#else

DWORD WINAPI wm_oscap_main(__attribute__((unused)) wm_oscap *arg) {
    mtinfo(WM_OSCAP_LOGTAG, "OPEN-SCAP module not compatible with Windows.");
    return 0;
}
#endif


// Get read data

cJSON *wm_oscap_dump(const wm_oscap *oscap) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_scp = cJSON_CreateObject();

    sched_scan_dump(&(oscap->scan_config), wm_scp);

    if (oscap->flags.enabled) cJSON_AddStringToObject(wm_scp,"disabled","no"); else cJSON_AddStringToObject(wm_scp,"disabled","yes");
    if (oscap->flags.scan_on_start) cJSON_AddStringToObject(wm_scp,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_scp,"scan-on-start","no");
    cJSON_AddNumberToObject(wm_scp,"timeout",oscap->timeout);
    if (oscap->evals) {
        cJSON *evals = cJSON_CreateArray();
        wm_oscap_eval *ptr;
        for (ptr = oscap->evals; ptr; ptr = ptr->next) {
            cJSON *eval = cJSON_CreateObject();
            if (ptr->path) cJSON_AddStringToObject(eval,"path",ptr->path);
            if (ptr->xccdf_id) cJSON_AddStringToObject(eval,"xccdf-id",ptr->xccdf_id);
            if (ptr->ds_id) cJSON_AddStringToObject(eval,"datastream-id",ptr->ds_id);
            if (ptr->oval_id) cJSON_AddStringToObject(eval,"oval-id",ptr->oval_id);
            if (ptr->cpe) cJSON_AddStringToObject(eval,"cpe",ptr->cpe);
            cJSON_AddNumberToObject(eval,"timeout",ptr->timeout);
            cJSON_AddNumberToObject(eval,"type",ptr->type);
            if (ptr->profiles) {
                cJSON *prof = cJSON_CreateArray();
                wm_oscap_profile *ptrp;
                for (ptrp = ptr->profiles; ptrp; ptrp = ptrp->next) {
                    cJSON_AddItemToArray(prof,cJSON_CreateString(ptrp->name));
                }
                cJSON_AddItemToObject(eval,"profile",prof);
            }
            cJSON_AddItemToArray(evals,eval);
        }
        cJSON_AddItemToObject(wm_scp,"content",evals);
    }

    cJSON_AddItemToObject(root,"open-scap",wm_scp);

    return root;
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
