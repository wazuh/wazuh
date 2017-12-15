/*
 * Wazuh Module for CIS-CAT
 * Copyright (C) 2016 Wazuh Inc.
 * April 25, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static wm_ciscat *ciscat;                             // Pointer to configuration
static int queue_fd;                                // Output queue file descriptor

static void* wm_ciscat_main(wm_ciscat *ciscat);        // Module main function. It won't return
static void wm_ciscat_setup(wm_ciscat *_ciscat);       // Setup module
static void wm_ciscat_cleanup();                     // Cleanup function, doesn't overwrite wm_cleanup
static void wm_ciscat_check();                       // Check configuration, disable flag
static void wm_ciscat_run(wm_ciscat_eval *eval, char *path);      // Run a CIS-CAT policy
static void wm_ciscat_parser(wm_ciscat_eval *eval);  // Parse CIS-CAT reports
static void wm_ciscat_info();                        // Show module info
static void wm_ciscat_destroy(wm_ciscat *ciscat);      // Destroy data

const char *WM_CISCAT_LOCATION = "wodle_cis-cat";  // Location field for event sending

// CIS-CAT module context definition

const wm_context WM_CISCAT_CONTEXT = {
    "cis-cat",
    (wm_routine)wm_ciscat_main,
    (wm_routine)wm_ciscat_destroy
};

// CIS-CAT module main function. It won't return.

void* wm_ciscat_main(wm_ciscat *ciscat) {
    wm_ciscat_eval *eval;
    time_t time_start = 0;
    time_t time_sleep = 0;
    char *cis_path;

    os_calloc(OS_MAXSTR, sizeof(char), cis_path);

    // Check if Java path is defined

    if (ciscat->java_path){
        if(setenv("JAVA_HOME", ciscat->java_path, 1) < 0)
            mtwarn(WM_CISCAT_LOGTAG, "Unable to define JRE location: %s", strerror(errno));
    }

    // Define path where CIS-CAT is installed

    if (ciscat->ciscat_path){
        snprintf(cis_path, OS_MAXSTR - 1, "%s", ciscat->ciscat_path);
    } else {
        snprintf(cis_path, OS_MAXSTR - 1, "%s", WM_CISCAT_DEFAULT_DIR);
    }

    // Check configuration and show debug information

    wm_ciscat_setup(ciscat);
    mtinfo(WM_CISCAT_LOGTAG, "Module started.");

    // First sleeping

    if (!ciscat->flags.scan_on_start) {
        time_start = time(NULL);

        if (ciscat->state.next_time > time_start) {
            mtinfo(WM_CISCAT_LOGTAG, "Waiting for turn to evaluate.");
            sleep(ciscat->state.next_time - time_start);
        }
    }

    // Main loop

    while (1) {

        mtinfo(WM_CISCAT_LOGTAG, "Starting evaluation.");

        // Get time and execute
        time_start = time(NULL);

        for (eval = ciscat->evals; eval; eval = eval->next)
            if (!eval->flags.error)
                wm_ciscat_run(eval, cis_path);

        time_sleep = time(NULL) - time_start;

        mtinfo(WM_CISCAT_LOGTAG, "Evaluation finished.");

        if ((time_t)ciscat->interval >= time_sleep) {
            time_sleep = ciscat->interval - time_sleep;
            ciscat->state.next_time = ciscat->interval + time_start;
        } else {
            mterror(WM_CISCAT_LOGTAG, "Interval overtaken.");
            time_sleep = ciscat->state.next_time = 0;
        }

        if (wm_state_io(&WM_CISCAT_CONTEXT, WM_IO_WRITE, &ciscat->state, sizeof(ciscat->state)) < 0)
            mterror(WM_CISCAT_LOGTAG, "Couldn't save running state.");

        // If time_sleep=0, yield CPU
        sleep(time_sleep);
    }

    if (ciscat->java_path)
        unsetenv("JAVA_HOME");

    return NULL;
}

// Setup module

void wm_ciscat_setup(wm_ciscat *_ciscat) {
    int i;

    ciscat = _ciscat;
    wm_ciscat_check();

    // Read running state

    if (wm_state_io(&WM_CISCAT_CONTEXT, WM_IO_READ, &ciscat->state, sizeof(ciscat->state)) < 0)
        memset(&ciscat->state, 0, sizeof(ciscat->state));

    if (isDebug())
        wm_ciscat_info();

    // Connect to socket

    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        sleep(WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_CISCAT_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting

    atexit(wm_ciscat_cleanup);
}

// Cleanup function, doesn't overwrite wm_cleanup

void wm_ciscat_cleanup() {
    close(queue_fd);
    mtinfo(WM_CISCAT_LOGTAG, "Module finished.");
}

// Run a CIS-CAT policy

void wm_ciscat_run(wm_ciscat_eval *eval, char *path) {
    char *command = NULL;
    int status, child_status;
    char *output = NULL;
    char msg[OS_MAXSTR];
    char *ciscat_script = "./CIS-CAT.sh";

    // Define time to sleep between messages sent

    int usec = 1000000 / wm_max_eps;
    struct timeval timeout = {0, usec};

    // Create arguments

    wm_strcat(&command, ciscat_script, '\0');

    // Accepting Terms of Use

    wm_strcat(&command, "-a", ' ');

    switch (eval->type) {
    case WM_CISCAT_XCCDF:
        wm_strcat(&command, "-b", ' ');
        wm_strcat(&command, eval->path, ' ');

        if (eval->profile) {
            wm_strcat(&command, "-p", ' ');
            wm_strcat(&command, eval->profile, ' ');
        }
        break;
    case WM_CISCAT_OVAL:
        wm_strcat(&command, "-od", ' ');
        wm_strcat(&command, eval->path, ' ');
        break;
    default:
        mterror(WM_CISCAT_LOGTAG, "Unspecified content type for file '%s'. This shouldn't happen.", eval->path);
        pthread_exit(NULL);
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

    // Specify directory where saving reports

    wm_strcat(&command, "-r", ' ');
    wm_strcat(&command, WM_CISCAT_REPORTS, ' ');

    // Set reports file name

    wm_strcat(&command, "-rn", ' ');
    wm_strcat(&command, "ciscat-report", ' ');

    // Get txt reports

    wm_strcat(&command, "-t", ' ');

    // Not to create HTML report

    wm_strcat(&command, "-n", ' ');

    // Send rootcheck message

    snprintf(msg, OS_MAXSTR, "Starting CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);

    // Execute the scan

    pid_t pid;

    switch(pid = fork(), pid) {
        case -1:
            mterror(WM_CISCAT_LOGTAG, FORK_ERROR, errno, strerror(errno));
            exit(1);
        case 0:
            // Child process
            if (CreatePID("wazuh-modulesd:ciscat", getpid()) < 0)
                mterror_exit(WM_CISCAT_LOGTAG, "Couldn't create PID file for child process: (%s)", strerror(errno));

            if (chdir(path) < 0) {
                mterror(WM_CISCAT_LOGTAG, "Unable to change working directory: %s", strerror(errno));
                pthread_exit(NULL);
            } else
                mtdebug2(WM_CISCAT_LOGTAG, "Changing working directory to %s", path);

            mtdebug1(WM_CISCAT_LOGTAG, "Launching command: %s", command);

            switch (wm_exec(command, &output, &status, eval->timeout)) {
                case 0:
                    if (status > 0) {
                        mtwarn(WM_CISCAT_LOGTAG, "Ignoring content '%s' due to error (%d).", eval->path, status);
                        mtdebug2(WM_CISCAT_LOGTAG, "OUTPUT: %s", output);
                        exit(1);
                    }

                    mtinfo(WM_CISCAT_LOGTAG, "Scan finished successfully. File: %s", eval->path);

                    break;

                case WM_ERROR_TIMEOUT:
                    free(output);
                    output = NULL;
                    wm_strcat(&output, "ciscat: ERROR: Timeout expired.", '\0');
                    mterror(WM_CISCAT_LOGTAG, "Timeout expired executing '%s'.", eval->path);
                    break;

                default:
                    mterror(WM_CISCAT_LOGTAG, "Internal calling. Exiting...");
                    exit(0);
                    pthread_exit(NULL);
            }

            if (DeletePID("wazuh-modulesd:ciscat") < 0)
                mterror_exit(WM_CISCAT_LOGTAG, "Couldn't delete PID file for child process: (%s)", strerror(errno));

            _exit(0);

        default:
            // Parent process
            switch(waitpid(-1, &child_status, 0)) {
                case -1:
                    mterror(WM_CISCAT_LOGTAG, WAITPID_ERROR, errno, strerror(errno));
                    break;
                default:
                    if (WEXITSTATUS(child_status) == 1)
                        eval->flags.error = 1;
            }
    }

    snprintf(msg, OS_MAXSTR, "Ending CIS-CAT scan. File: %s. ", eval->path);
    timeout.tv_usec = usec;
    select(0 , NULL, NULL, NULL, &timeout);
    SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);

    wm_ciscat_parser(eval);

    free(output);
    free(command);
}

void wm_ciscat_parser(wm_ciscat_eval *eval){

    char file[OS_MAXSTR];
    FILE *fp;
    char string[OS_MAXSTR];
    int line = 0;
    int last_line = 0;
    int final = 0;
    int i;
    cJSON *object;
    cJSON *data;

    // Define report location

    snprintf(file, OS_MAXSTR - 1, "%s%s", WM_CISCAT_REPORTS, "/ciscat-report.txt");

    // Set unique ID for each scan

    int ID = os_random();
    if (ID < 0)
        ID = -ID;

    if ((fp = fopen(file, "r"))){

        while (fgets(string, OS_MAXSTR, fp) != NULL){


            // Remove '\r\n' from log lines

            if (!last_line){
                size_t length;
                length = strlen(string);
                string[length - 1] = '\0';
                string[length - 2] = '\0';
            }

            line++;

            if (line == 1){

                object = cJSON_CreateObject();
                data = cJSON_CreateObject();
                cJSON_AddStringToObject(object, "type", "scan_start");
                cJSON_AddNumberToObject(object, "scan_id", ID);
                cJSON_AddItemToObject(object, "data", data);
                char benchmark[OS_MAXSTR];
                snprintf(benchmark, OS_MAXSTR - 1, "%s", string);
                cJSON_AddStringToObject(data, "benchmark", benchmark);
                cJSON_AddStringToObject(data, "profile", eval->profile);

            } else if (line == 2) {

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 3);
                cJSON_AddStringToObject(data, "hostname", parts[2]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 3) {

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 2);
                cJSON_AddStringToObject(data, "timestamp", parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

                char *msg;

                msg = cJSON_PrintUnformatted(object);
                mtdebug2(WM_CISCAT_LOGTAG, "Sending CIS-CAT event: '%s'", msg);
                SendMSG(queue_fd, msg, WM_CISCAT_LOCATION, LOCALFILE_MQ);
                cJSON_Delete(object);

                free(msg);

            } else if (line == 4){
                continue;

            } else if ((strstr(string, "**********") != NULL)){

                line = 5;
                final = 1;
                object = cJSON_CreateObject();
                data = cJSON_CreateObject();
                cJSON_AddStringToObject(object, "type", "scan_end");
                cJSON_AddNumberToObject(object, "scan_id", ID);
                cJSON_AddItemToObject(object, "data", data);

            } else if (line == 6 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 2);
                cJSON_AddStringToObject(data, "pass", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 7 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 2);
                cJSON_AddStringToObject(data, "fail", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 8 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 2);
                cJSON_AddStringToObject(data, "error", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 9 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 2);
                cJSON_AddStringToObject(data, "unknown", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 10 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 3);
                cJSON_AddStringToObject(data, "not_selected", parts[2]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 11 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 3);
                cJSON_AddStringToObject(data, "actual_pass", parts[2]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 12 && final){

                last_line = 1;

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 3);
                cJSON_AddStringToObject(data, "max_possible", parts[2]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 13 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 2);
                cJSON_AddStringToObject(data, "score", parts[1]);
                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

                char *msg;

                msg = cJSON_PrintUnformatted(object);
                mtdebug2(WM_CISCAT_LOGTAG, "Sending CIS-CAT event: '%s'", msg);
                SendMSG(queue_fd, msg, WM_CISCAT_LOCATION, LOCALFILE_MQ);
                cJSON_Delete(object);

                free(msg);

            } else {

                object = cJSON_CreateObject();
                data = cJSON_CreateObject();
                cJSON_AddStringToObject(object, "type", "scan_result");
                cJSON_AddNumberToObject(object, "scan_id", ID);
                cJSON_AddItemToObject(object, "data", data);

                char ** parts = NULL;

                parts = OS_StrBreak(' ', string, 3);

                cJSON_AddStringToObject(data, "check_id", parts[1]);
                cJSON_AddStringToObject(data, "description", parts[2]);

                char *result = os_strip_char(parts[0], ':');
                cJSON_AddStringToObject(data, "result", result);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

                char *msg;

                msg = cJSON_PrintUnformatted(object);
                mtdebug2(WM_CISCAT_LOGTAG, "Sending CIS-CAT event: '%s'", msg);
                SendMSG(queue_fd, msg, WM_CISCAT_LOCATION, LOCALFILE_MQ);
                cJSON_Delete(object);

                free(msg);

            }
        }
        fclose(fp);
        unlink(file);
    } else {
        mterror(WM_CISCAT_LOGTAG, "Unable to read file %s: %s", file, strerror(errno));
    }
}

// Check configuration

void wm_ciscat_check() {
    wm_ciscat_eval *eval;

    // Check if disabled

    if (!ciscat->flags.enabled) {
        mtinfo(WM_CISCAT_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if evals

    if (!ciscat->evals) {
        mtwarn(WM_CISCAT_LOGTAG, "No evals defined. Exiting...");
        pthread_exit(NULL);
    }

    // Check if interval

    if (!ciscat->interval)
        ciscat->interval = WM_DEF_INTERVAL;

    // Check timeout and flags for evals

    for (eval = ciscat->evals; eval; eval = eval->next) {
        if (!eval->timeout)
            if (!(eval->timeout = ciscat->timeout))
                eval->timeout = WM_DEF_TIMEOUT;
    }
}

// Show module info

void wm_ciscat_info() {
    wm_ciscat_eval *eval;

    mtinfo(WM_CISCAT_LOGTAG, "SHOW_MODULE_CISCAT: ----");
    mtinfo(WM_CISCAT_LOGTAG, "Timeout: %d", ciscat->timeout);

    for (eval = (wm_ciscat_eval*)ciscat->evals; eval; eval = eval->next){
        mtinfo(WM_CISCAT_LOGTAG, "Benchmark: [%s]", eval->path);
        if (eval->profile) {
            mtinfo(WM_CISCAT_LOGTAG, "Profile: [%s]", eval->profile);
        }
    }

    mtinfo(WM_CISCAT_LOGTAG, "SHOW_MODULE_CISCAT: ----");
}

// Destroy data

void wm_ciscat_destroy(wm_ciscat *ciscat) {

    wm_ciscat_eval *cur_eval;
    wm_ciscat_eval *next_eval;

    if (ciscat->java_path)
        unsetenv("JAVA_HOME");

    // Delete evals

    for (cur_eval = ciscat->evals; cur_eval; cur_eval = next_eval) {

        next_eval = cur_eval->next;
        free(cur_eval->path);
        free(cur_eval->profile);
        free(cur_eval->xccdf_id);
        free(cur_eval->oval_id);
        free(cur_eval->ds_id);
        free(cur_eval->cpe);
        free(cur_eval);
    }

    free(ciscat);
}
