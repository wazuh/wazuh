/*
 * Wazuh Module for OpenSCAP
 * Wazuh Inc.
 * April 25, 2016
 */

#include "wmodules.h"

static wm_oscap *oscap;                             // Pointer to configuration
static int queue_fd;                                // Output queue file descriptor

static void wm_oscap_main(wm_oscap *_oscap);        // Module main function. It won't return
static void wm_oscap_setup(wm_oscap *_oscap);       // Setup module
static void wm_oscap_cleanup();                     // Cleanup function, doesn't overwrite wm_cleanup
static void wm_oscap_check();                       // Check configuration, disable flag
static void wm_oscap_reload();                      // Reload configuration
static void wm_oscap_run(wm_oscap_file *file);      // Run an OpenSCAP file
static void wm_oscap_info();                        // Show module info
static void wm_oscap_destroy(wm_oscap *oscap);      // Destroy data

const char *WM_OSCAP_LOCATION = "wodle:open-scap";  // Location field for event sending

// OpenSCAP module context definition

const wm_context WM_OSCAP_CONTEXT = {
    "open-scap",
    (wm_routine)wm_oscap_main,
    (wm_routine)wm_oscap_destroy
};

// OpenSCAP module main function. It won't return.

void wm_oscap_main(wm_oscap *_oscap) {
    wm_oscap_file *file;
    struct timespec tp[2];

    // Check configuration and show debug information

    wm_oscap_setup(_oscap);
    verbose("%s: INFO: Module started.", WM_OSCAP_LOGTAG);

    // Main loop

    while (1) {
        if (wm_flag_reload)
            wm_oscap_reload();

        // Get time and execute

        clock_gettime(CLOCK_MONOTONIC, &tp[0]);

        for (file = oscap->files; file; file = file->next)
            if (!file->flags.error)
                wm_oscap_run(file);

        clock_gettime(CLOCK_MONOTONIC, &tp[1]);

        /* Sleep
         * sleep = interval - (t1 - t0)
         * sleep = interval + t0 - t1
         */

        tp[0].tv_sec += oscap->interval - tp[1].tv_sec;
        tp[0].tv_nsec -= tp[1].tv_nsec;

        if (tp[0].tv_nsec < 0) {
            tp[0].tv_nsec += 1e9;
            tp[0].tv_sec--;
        }

        if (tp[0].tv_sec > 0 || (tp[0].tv_sec == 0 && tp[0].tv_nsec > 0))
            clock_nanosleep(CLOCK_MONOTONIC, 0, &tp[0], NULL);
        else
            merror("%s: ERROR: Interval overtaken.", WM_OSCAP_LOGTAG);
    }

    exit(EXIT_SUCCESS);
}

// Setup module

void wm_oscap_setup(wm_oscap *_oscap) {
    oscap = _oscap;
    wm_oscap_check();

    if (isDebug())
        wm_oscap_info();

    // Connect to socket

    if ((queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0)
        ErrorExit("%s: ERROR: Can't connect to queue.", WM_OSCAP_LOGTAG);

    // Cleanup exiting

    atexit(wm_oscap_cleanup);
}

// Cleanup function, doesn't overwrite wm_cleanup

void wm_oscap_cleanup() {
    close(queue_fd);
    verbose("%s: INFO: Module finished.", WM_OSCAP_LOGTAG);
}

// Run an OpenSCAP file

void wm_oscap_run(wm_oscap_file *file) {
    const char* cmd[10] = { "/var/ossec/wmodules/oscap/oscap.py", "--file", file->name };
    int argi = 3;
    int status;
    char *output;
    char *line;
    char *arg_profiles = NULL;
    char *arg_skip_result = NULL;
    char *arg_skip_severity = NULL;
    wm_oscap_profile *profile;

    // Create arguments

    for (profile = file->profiles; profile; profile = profile->next)
        wm_strcat(&arg_profiles, profile->name, ',');

    if (arg_profiles) {
        cmd[argi++] = "--profiles";
        cmd[argi++] = arg_profiles;
    }

    if (file->flags.skip_result_pass)
        wm_strcat(&arg_skip_result, "pass", ',');
    if (file->flags.skip_result_fail)
        wm_strcat(&arg_skip_result, "fail", ',');
    if (file->flags.skip_result_notchecked)
        wm_strcat(&arg_skip_result, "notchecked", ',');
    if (file->flags.skip_result_notapplicable)
        wm_strcat(&arg_skip_result, "notapplicable", ',');

    if (arg_skip_result) {
        cmd[argi++] = "--skip-result";
        cmd[argi++] = arg_skip_result;
    }

    if (file->flags.skip_severity_low)
        wm_strcat(&arg_skip_severity, "low", ',');
    if (file->flags.skip_severity_medium)
        wm_strcat(&arg_skip_severity, "medium", ',');
    if (file->flags.skip_severity_high)
        wm_strcat(&arg_skip_severity, "high", ',');

    if (arg_skip_severity) {
        cmd[argi++] = "--skip-severity";
        cmd[argi++] = arg_skip_severity;
    }

    // Execute

    debug1("Launching command: %s", cmd[0]);
    output = wm_exec((char * const *)cmd, &status, file->timeout);
    debug1("Command finished.");

    if (!output) {
        if (wm_exec_timeout()) {
            wm_strcat(&output, "oscap: ERROR: Timeout expired.", '\0');
            merror("%s: ERROR: Timeout expired executing '%s'.", WM_OSCAP_LOGTAG, file->name);
        } else
            merror("%s: ERROR: Internal calling.", WM_OSCAP_LOGTAG);

    } else if (status > 0) {
        merror("%s: WARN: Ignoring file '%s' due to error.", WM_OSCAP_LOGTAG, file->name);
        file->flags.error = 1;
    }

    for (line = strtok(output, "\n"); line; line = strtok(NULL, "\n"))
        SendMSG(queue_fd, line, WM_OSCAP_LOCATION, LOCALFILE_MQ);

    free(output);
    free(arg_profiles);
    free(arg_skip_result);
    free(arg_skip_severity);
}

// Check configuration

void wm_oscap_check() {
    wm_oscap_file *file;

    // Check if files

    if (!oscap->files)
        ErrorExit("%s: WARN: No files defined. Exiting...", WM_OSCAP_LOGTAG);

    // Check if interval

    if (!oscap->interval)
        oscap->interval = WM_DEF_INTERVAL;

    // Check timeout and flags for files

    for (file = oscap->files; file; file = file->next) {
        if (!file->timeout)
            if (!(file->timeout = oscap->timeout))
                file->timeout = WM_DEF_TIMEOUT;

        if (!file->flags.custom_result_flags)
            file->flags.skip_result = oscap->flags.skip_result;

        if (!file->flags.custom_severity_flags)
            file->flags.skip_severity = oscap->flags.skip_severity;
    }
}

// Reload configuration, disable flag

void wm_oscap_reload() {
    wmodule *cur_wm;

    verbose("%s: INFO: Reloading configuration...", WM_OSCAP_LOGTAG);
    wm_flag_reload = 0;
    wm_destroy();

    if (ReadConfig(CWMODULE, DEFAULTCPATH, &wmodules, NULL) < 0)
        exit(EXIT_FAILURE);

    wm_check();

    // Get new pointer to configuration

    oscap = NULL;

    for (cur_wm = wmodules; cur_wm; cur_wm = cur_wm->next) {
        if (strcmp(cur_wm->context->name, WM_OSCAP_CONTEXT.name) == 0) {
            oscap = (wm_oscap*)cur_wm->data;
            break;
        }
    }

    if (!oscap)
        ErrorExit("%s: WARN: No configuration for OpenSCAP after reloading. Exiting...", WM_OSCAP_LOGTAG);

    wm_oscap_check();
}

// Show module info

void wm_oscap_info() {
    wm_oscap_file *file;
    wm_oscap_profile *profile;

    verbose("%s: INFO: SHOW_MODULE_OSCAP: ----", WM_OSCAP_LOGTAG);
    verbose("%s: INFO: Timeout: %d", WM_OSCAP_LOGTAG, oscap->timeout);
    verbose("%s: INFO: Files:", WM_OSCAP_LOGTAG);

    for (file = (wm_oscap_file*)oscap->files; file; file = file->next){
        verbose("%s: INFO: [%s]", WM_OSCAP_LOGTAG, file->name);

        verbose("%s: INFO: \tSkip result:", WM_OSCAP_LOGTAG);
        verbose("%s: INFO: \t\t[Pass: %d] [Fail: %d] [NotChecked: %d] [NotApplicable: %d]", WM_OSCAP_LOGTAG, file->flags.skip_result_pass, file->flags.skip_result_fail, file->flags.skip_result_notchecked, file->flags.skip_result_notapplicable);

        verbose("%s: INFO: \tSkip severity:", WM_OSCAP_LOGTAG);
        verbose("%s: INFO: \t\t[Low: %d] [Medium: %d] [High: %d]", WM_OSCAP_LOGTAG, file->flags.skip_severity_low, file->flags.skip_severity_medium, file->flags.skip_severity_high);

        verbose("%s: INFO: \tProfiles:", WM_OSCAP_LOGTAG);

        for (profile = (wm_oscap_profile*)file->profiles; profile; profile = profile->next)
            verbose("%s: INFO: \t\tName: %s", WM_OSCAP_LOGTAG, profile->name);
    }

    verbose("%s: INFO: SHOW_MODULE_OSCAP: ----", WM_OSCAP_LOGTAG);
}

// Destroy data

void wm_oscap_destroy(wm_oscap *oscap) {
    wm_oscap_file *cur_file;
    wm_oscap_file *next_file;
    wm_oscap_profile *cur_profile;
    wm_oscap_profile *next_profile;

    // Delete files

    for (cur_file = oscap->files; cur_file; cur_file = next_file) {

        // Delete profiles

        for (cur_profile = cur_file->profiles; cur_profile; cur_profile = next_profile) {
            next_profile = cur_profile->next;
            free(cur_profile->name);
            free(cur_profile);
        }

        next_file = cur_file->next;
        free(cur_file->name);
        free(cur_file);
    }

    free(oscap);
}
