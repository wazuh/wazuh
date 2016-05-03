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
static void wm_oscap_run(wm_oscap_policy *policy);  // Run an OpenSCAP policy
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
    wm_oscap_policy *policy;
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

        for (policy = oscap->policies; policy; policy = policy->next)
            if (!policy->flags.error)
                wm_oscap_run(policy);

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

// Run an OpenSCAP policy

void wm_oscap_run(wm_oscap_policy *policy) {
    const char* cmd[10] = { "/var/ossec/wmodules/oscap/oscap.py", "--policy", policy->name };
    int argi = 3;
    int status;
    char *output;
    char *line;
    char *arg_profiles = NULL;
    char *arg_skip_result = NULL;
    char *arg_skip_severity = NULL;
    wm_oscap_profile *profile;

    // Create arguments

    for (profile = policy->profiles; profile; profile = profile->next)
        wm_strcat(&arg_profiles, profile->name, ',');

    if (arg_profiles) {
        cmd[argi++] = "--profiles";
        cmd[argi++] = arg_profiles;
    }

    if (policy->flags.skip_result_pass)
        wm_strcat(&arg_skip_result, "pass", ',');
    if (policy->flags.skip_result_fail)
        wm_strcat(&arg_skip_result, "fail", ',');
    if (policy->flags.skip_result_notchecked)
        wm_strcat(&arg_skip_result, "notchecked", ',');
    if (policy->flags.skip_result_notapplicable)
        wm_strcat(&arg_skip_result, "notapplicable", ',');

    if (arg_skip_result) {
        cmd[argi++] = "--skip-result";
        cmd[argi++] = arg_skip_result;
    }

    if (policy->flags.skip_severity_low)
        wm_strcat(&arg_skip_severity, "low", ',');
    if (policy->flags.skip_severity_medium)
        wm_strcat(&arg_skip_severity, "medium", ',');
    if (policy->flags.skip_severity_high)
        wm_strcat(&arg_skip_severity, "high", ',');

    if (arg_skip_severity) {
        cmd[argi++] = "--skip-severity";
        cmd[argi++] = arg_skip_severity;
    }

    // Execute

    debug1("Launching command: %s", cmd[0]);
    output = wm_exec((char * const *)cmd, &status, policy->timeout);
    debug1("Command finished.");

    if (!output) {
        if (wm_exec_timeout()) {
            wm_strcat(&output, "oscap: ERROR: Timeout expired.", '\0');
            merror("%s: ERROR: Timeout expired executing '%s'.", WM_OSCAP_LOGTAG, policy->name);
        } else
            merror("%s: ERROR: Internal calling.", WM_OSCAP_LOGTAG);

    } else if (status > 0) {
        merror("%s: WARN: Ignoring policy '%s' due to error.", WM_OSCAP_LOGTAG, policy->name);
        policy->flags.error = 1;
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
    wm_oscap_policy *policy;

    // Check if policies

    if (!oscap->policies)
        ErrorExit("%s: WARN: No policies defined. Exiting...", WM_OSCAP_LOGTAG);

    // Check if interval

    if (!oscap->interval)
        oscap->interval = WM_DEF_INTERVAL;

    // Check timeout and flags for policies

    for (policy = oscap->policies; policy; policy = policy->next) {
        if (!policy->timeout)
            if (!(policy->timeout = oscap->timeout))
                policy->timeout = WM_DEF_TIMEOUT;

        if (!policy->flags.custom_result_flags)
            policy->flags.skip_result = oscap->flags.skip_result;

        if (!policy->flags.custom_severity_flags)
            policy->flags.skip_severity = oscap->flags.skip_severity;
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
    wm_oscap_policy *policy;
    wm_oscap_profile *profile;

    verbose("%s: INFO: SHOW_MODULE_OSCAP: ----", WM_OSCAP_LOGTAG);
    verbose("%s: INFO: Timeout: %d", WM_OSCAP_LOGTAG, oscap->timeout);
    verbose("%s: INFO: Policies:", WM_OSCAP_LOGTAG);

    for (policy = (wm_oscap_policy*)oscap->policies; policy; policy = policy->next){
        verbose("%s: INFO: [%s]", WM_OSCAP_LOGTAG, policy->name);

        verbose("%s: INFO: \tSkip result:", WM_OSCAP_LOGTAG);
        verbose("%s: INFO: \t\t[Pass: %d] [Fail: %d] [NotChecked: %d] [NotApplicable: %d]", WM_OSCAP_LOGTAG, policy->flags.skip_result_pass, policy->flags.skip_result_fail, policy->flags.skip_result_notchecked, policy->flags.skip_result_notapplicable);

        verbose("%s: INFO: \tSkip severity:", WM_OSCAP_LOGTAG);
        verbose("%s: INFO: \t\t[Low: %d] [Medium: %d] [High: %d]", WM_OSCAP_LOGTAG, policy->flags.skip_severity_low, policy->flags.skip_severity_medium, policy->flags.skip_severity_high);

        verbose("%s: INFO: \tProfiles:", WM_OSCAP_LOGTAG);

        for (profile = (wm_oscap_profile*)policy->profiles; profile; profile = profile->next)
            verbose("%s: INFO: \t\tName: %s", WM_OSCAP_LOGTAG, profile->name);
    }

    verbose("%s: INFO: SHOW_MODULE_OSCAP: ----", WM_OSCAP_LOGTAG);
}

// Destroy data

void wm_oscap_destroy(wm_oscap *oscap) {
    wm_oscap_policy *cur_policy;
    wm_oscap_policy *next_policy;
    wm_oscap_profile *cur_profile;
    wm_oscap_profile *next_profile;

    // Delete policies

    for (cur_policy = oscap->policies; cur_policy; cur_policy = next_policy) {

        // Delete profiles

        for (cur_profile = cur_policy->profiles; cur_profile; cur_profile = next_profile) {
            next_profile = cur_profile->next;
            free(cur_profile->name);
            free(cur_profile);
        }

        next_policy = cur_policy->next;
        free(cur_policy->name);
        free(cur_policy);
    }

    free(oscap);
}
