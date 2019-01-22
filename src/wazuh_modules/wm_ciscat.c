/*
 * Wazuh Module for CIS-CAT
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef ENABLE_CISCAT
#include "wmodules.h"

static wm_ciscat *ciscat;                             // Pointer to configuration
static wm_rule_data *head;                            // Pointer to head of rules data

#ifndef WIN32
static int queue_fd;                                // Output queue file descriptor
#endif

static void* wm_ciscat_main(wm_ciscat *ciscat);        // Module main function. It won't return
static void wm_ciscat_setup(wm_ciscat *_ciscat);       // Setup module
static void wm_ciscat_check();                       // Check configuration, disable flag
static void wm_ciscat_run(wm_ciscat_eval *eval, char *path, int id, const char * java_path);      // Run a CIS-CAT policy
static char * wm_ciscat_get_profile();               // Read evaluated profile from the report
static void wm_ciscat_preparser();                   // Prepare report for the xml parser
static wm_scan_data* wm_ciscat_txt_parser();        // Parse CIS-CAT csv reports
static void wm_ciscat_xml_parser();                 // Parse CIS-CAT xml reports
static void wm_ciscat_send_scan(wm_scan_data *info, int id);      // Write scan result into JSON events and send them
static char* wm_ciscat_remove_tags(char* string);    // Remove xml and html tags from a string
static wm_rule_data* read_group(const OS_XML *xml, XML_NODE node, wm_rule_data *rule_info, char *group);    // Read groups information from the XML report
static wm_rule_data* read_rule_info(XML_NODE node, wm_rule_data *rule, char *group);      // Read rule information from XML report
static void wm_ciscat_info();                        // Show module info
#ifndef WIN32
static void wm_ciscat_cleanup();                     // Cleanup function, doesn't overwrite wm_cleanup
#endif
static void wm_ciscat_destroy(wm_ciscat *ciscat);      // Destroy data
cJSON *wm_ciscat_dump(const wm_ciscat *ciscat);

const char *WM_CISCAT_LOCATION = "wodle_cis-cat";  // Location field for event sending

// CIS-CAT module context definition

const wm_context WM_CISCAT_CONTEXT = {
    "cis-cat",
    (wm_routine)wm_ciscat_main,
    (wm_routine)wm_ciscat_destroy,
    (cJSON * (*)(const void *))wm_ciscat_dump
};

// CIS-CAT module main function. It won't return.

void* wm_ciscat_main(wm_ciscat *ciscat) {
    wm_ciscat_eval *eval;
    time_t time_start = 0;
    time_t time_sleep = 0;
    int skip_java = 0;
    int status = 0;
    char *cis_path = NULL;
    char java_fullpath[OS_MAXSTR];
    char bench_fullpath[OS_MAXSTR];

    // Check configuration and show debug information

    wm_ciscat_setup(ciscat);
    mtinfo(WM_CISCAT_LOGTAG, "Module started.");

#ifdef WIN32
    char* current;
    os_calloc(OS_MAXSTR, sizeof(char), current);
    if (!GetCurrentDirectory(OS_MAXSTR - 1, current)) {
        mterror(WM_CISCAT_LOGTAG, "Unable to find current directory. Please use full paths for CIS-CAT configuration.");
        ciscat->flags.error = 1;
    }
#endif

    os_calloc(OS_MAXSTR, sizeof(char), cis_path);

    // Check if Java path is defined and include it in "PATH" variable

    if (ciscat->java_path) {

        // Check if the defined path is relative or not
        switch (wm_relative_path(ciscat->java_path)) {
            case 0:
                // Full path
                snprintf(java_fullpath, OS_MAXSTR - 1, "%s", ciscat->java_path);
                break;
            case 1:
            #ifdef WIN32
                if (*current) {
                    snprintf(java_fullpath, OS_MAXSTR - 1, "%s\\%s", current, ciscat->java_path);
                } else {
                    skip_java = 1;
                }
            #else
                snprintf(java_fullpath, OS_MAXSTR - 1, "%s/%s", DEFAULTDIR, ciscat->java_path);
            #endif
                break;
            default:
                mterror(WM_CISCAT_LOGTAG, "Defined Java path is not valid. Using the default one.");
                skip_java = 1;
        }

        if (!skip_java) {
            os_strdup(java_fullpath, ciscat->java_path);
        } else {
            if (ciscat->java_path) {
                free(ciscat->java_path);
            }
            ciscat->java_path = NULL;
        }
    }

    // Define path where CIS-CAT is installed

    if (ciscat->ciscat_path) {
        switch (wm_relative_path(ciscat->ciscat_path)) {
            case 0:
                // Full path
                snprintf(cis_path, OS_MAXSTR - 1, "%s", ciscat->ciscat_path);
                break;
            case 1:
                // Relative path
            #ifdef WIN32
                if (*current) {
                    snprintf(cis_path, OS_MAXSTR - 1, "%s\\%s", current, ciscat->ciscat_path);
                }
            #else
                snprintf(cis_path, OS_MAXSTR - 1, "%s/%s", DEFAULTDIR, ciscat->ciscat_path);
            #endif
                break;
            default:
                mterror(WM_CISCAT_LOGTAG, "Defined CIS-CAT path is not valid.");
                ciscat->flags.error = 1;
        }
    } else {
    #ifdef WIN32
        if (*current)
            snprintf(cis_path, OS_MAXSTR - 1, "%s\\%s", current, WM_CISCAT_DEFAULT_DIR_WIN);
    #else
        snprintf(cis_path, OS_MAXSTR - 1, "%s", WM_CISCAT_DEFAULT_DIR);
    #endif
    }

    if (IsDir(cis_path) < 0) {
        mterror(WM_CISCAT_LOGTAG, "CIS-CAT tool not found at '%s'.", cis_path);
        ciscat->flags.error = 1;
    }

    // First sleeping

    if (!ciscat->flags.scan_on_start) {
        time_start = time(NULL);

        if (ciscat->scan_day) {
            do {
                status = check_day_to_scan(ciscat->scan_day, ciscat->scan_time);
                if (status == 0) {
                    time_sleep = get_time_to_hour(ciscat->scan_time);
                } else {
                    wm_delay(1000); // Sleep one second to avoid an infinite loop
                    time_sleep = get_time_to_hour("00:00");
                }

                mtdebug2(WM_CISCAT_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
                wm_delay(1000 * time_sleep);

            } while (status < 0);

        } else if (ciscat->scan_wday >= 0) {

            time_sleep = get_time_to_day(ciscat->scan_wday, ciscat->scan_time);
            mtinfo(WM_CISCAT_LOGTAG, "Waiting for turn to evaluate.");
            mtdebug2(WM_CISCAT_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);

        } else if (ciscat->scan_time) {

            time_sleep = get_time_to_hour(ciscat->scan_time);
            mtinfo(WM_CISCAT_LOGTAG, "Waiting for turn to evaluate.");
            mtdebug2(WM_CISCAT_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);

        } else if (ciscat->state.next_time == 0 || ciscat->state.next_time > time_start) {

            // On first run, take into account the interval of time specified
            time_sleep = ciscat->state.next_time == 0 ?
                         (time_t)ciscat->interval :
                         ciscat->state.next_time - time_start;

            mtinfo(WM_CISCAT_LOGTAG, "Waiting for turn to evaluate.");
            mtdebug2(WM_CISCAT_LOGTAG, "Sleeping for %ld seconds", (long)time_sleep);
            wm_delay(1000 * time_sleep);

        }
    }

    // Main loop

    while (1) {

        // Get time and execute
        time_start = time(NULL);

        if (!ciscat->flags.error) {
            mtinfo(WM_CISCAT_LOGTAG, "Starting evaluation.");

            // Set unique ID for each scan

        #ifndef WIN32
            int id = os_random();
            if (id < 0)
                id = -id;
        #else
            unsigned int id1 = os_random();
            unsigned int id2 = os_random();

            char random_id[OS_MAXSTR];
            snprintf(random_id, OS_MAXSTR - 1, "%u%u", id1, id2);

            int id = atoi(random_id);
            if (id < 0)
                id = -id;
        #endif

            for (eval = ciscat->evals; eval; eval = eval->next) {
                if (!eval->flags.error) {

                    switch (wm_relative_path(eval->path)) {
                        case 0:
                            break;
                        case 1:
                        #ifdef WIN32
                            snprintf(bench_fullpath, OS_MAXSTR - 1, "%s\\%s", cis_path, eval->path);
                        #else
                            snprintf(bench_fullpath, OS_MAXSTR - 1, "%s/%s", cis_path, eval->path);
                        #endif
                            os_strdup(bench_fullpath, eval->path);
                            break;
                        default:
                            mterror(WM_CISCAT_LOGTAG, "Couldn't find benchmark path. Skipping...");
                    }

                    if (IsFile(eval->path) < 0) {
                        mterror(WM_CISCAT_LOGTAG, "Benchmark file '%s' not found.", eval->path);
                    } else {
                        wm_ciscat_run(eval, cis_path, id, ciscat->java_path);
                        ciscat->flags.error = 0;
                    }
                }
            }
        }

        wm_delay(1000); // Avoid infinite loop when execution fails
        time_sleep = time(NULL) - time_start;

        mtinfo(WM_CISCAT_LOGTAG, "Evaluation finished.");

        if (ciscat->scan_day) {
            int interval = 0, i = 0;
            status = 0;
            interval = ciscat->interval / 60;   // interval in num of months

            do {
                status = check_day_to_scan(ciscat->scan_day, ciscat->scan_time);
                if (status == 0) {
                    time_sleep = get_time_to_hour(ciscat->scan_time);
                    i++;
                } else {
                    wm_delay(1000);
                    time_sleep = get_time_to_hour("00:00");     // Sleep until the start of the next day
                }

                mtdebug2(WM_CISCAT_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
                wm_delay(1000 * time_sleep);

            } while ((status < 0) && (i < interval));

        } else {

            if (ciscat->scan_wday >= 0) {
                time_sleep = get_time_to_day(ciscat->scan_wday, ciscat->scan_time);
                time_sleep += WEEK_SEC * ((ciscat->interval / WEEK_SEC) - 1);
                ciscat->state.next_time = (time_t)time_sleep + time_start;
            } else if (ciscat->scan_time) {
                time_sleep = get_time_to_hour(ciscat->scan_time);
                time_sleep += DAY_SEC * ((ciscat->interval / DAY_SEC) - 1);
                ciscat->state.next_time = (time_t)time_sleep + time_start;
            } else if ((time_t)ciscat->interval >= time_sleep) {
                time_sleep = ciscat->interval - time_sleep;
                ciscat->state.next_time = ciscat->interval + time_start;
            } else {
                mterror(WM_CISCAT_LOGTAG, "Interval overtaken.");
                time_sleep = ciscat->state.next_time = 0;
            }

            if (wm_state_io(WM_CISCAT_CONTEXT.name, WM_IO_WRITE, &ciscat->state, sizeof(ciscat->state)) < 0)
                mterror(WM_CISCAT_LOGTAG, "Couldn't save running state.");

            mtdebug2(WM_CISCAT_LOGTAG, "Sleeping for %d seconds", (int)time_sleep);
            wm_delay(1000 * time_sleep);
        }
    }

    free(cis_path);
#ifdef WIN32
    free(current);
#endif

    return NULL;
}

// Setup module

void wm_ciscat_setup(wm_ciscat *_ciscat) {

    ciscat = _ciscat;
    wm_ciscat_check();

    // Read running state

    if (wm_state_io(WM_CISCAT_CONTEXT.name, WM_IO_READ, &ciscat->state, sizeof(ciscat->state)) < 0)
        memset(&ciscat->state, 0, sizeof(ciscat->state));

    if (isDebug())
        wm_ciscat_info();

#ifndef WIN32

    int i;

    // Connect to socket

    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        wm_delay(1000 * WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_CISCAT_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting

    atexit(wm_ciscat_cleanup);
#endif

}

// Cleanup function, doesn't overwrite wm_cleanup

#ifndef WIN32
void wm_ciscat_cleanup() {
    close(queue_fd);
    mtinfo(WM_CISCAT_LOGTAG, "Module finished.");
}
#endif

// Run a CIS-CAT policy for Windows

#ifdef WIN32

void wm_ciscat_run(wm_ciscat_eval *eval, char *path, int id, const char * java_path) {
    char *command = NULL;
    int status;
    char *output = NULL;
    char msg[OS_MAXSTR];
    char *ciscat_script;
    wm_scan_data *scan_info = NULL;
    char eval_path[OS_MAXSTR];

    os_calloc(OS_MAXSTR, sizeof(char), ciscat_script);

    snprintf(ciscat_script, OS_MAXSTR - 1, "\"%s\\CIS-CAT.BAT\"", path);

    // Create arguments

    wm_strcat(&command, ciscat_script, '\0');

    // Accepting Terms of Use

    wm_strcat(&command, "-a", ' ');

    switch (eval->type) {
    case WM_CISCAT_XCCDF:

        snprintf(eval_path, OS_MAXSTR - 1, "\"%s\"", eval->path);

        wm_strcat(&command, "-b", ' ');
        wm_strcat(&command, eval_path, ' ');

        if (eval->profile) {
            wm_strcat(&command, "-p", ' ');
            wm_strcat(&command, eval->profile, ' ');
        }
        break;
    case WM_CISCAT_OVAL:
        mterror(WM_CISCAT_LOGTAG, "OVAL is an invalid content type. Exiting...");
        ciscat->flags.error = 1;
        pthread_exit(NULL);
        break;
    default:
        mterror(WM_CISCAT_LOGTAG, "Unspecified content type for file '%s'. This shouldn't happen.", eval->path);
        ciscat->flags.error = 1;
        pthread_exit(NULL);
    }

    // Specify location for reports

    wm_strcat(&command, "-r", ' ');
    wm_strcat(&command, TMP_DIR, ' ');

    // Set reports file name

    wm_strcat(&command, "-rn", ' ');
    wm_strcat(&command, "ciscat-report", ' ');

    // Get xml reports

    wm_strcat(&command, "-x", ' ');

    // Get txt reports

    wm_strcat(&command, "-t", ' ');

    // Do not create HTML report

    wm_strcat(&command, "-n", ' ');

    // Add not selected checks

    wm_strcat(&command, "-y", ' ');

    // Send rootcheck message

    snprintf(msg, OS_MAXSTR, "Starting CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(0, msg, "rootcheck", ROOTCHECK_MQ);

    // Execute the scan

    mtdebug1(WM_CISCAT_LOGTAG, "Launching command: %s", command);

    switch (wm_exec(command, &output, &status, eval->timeout, java_path)) {
        case 0:

            mtdebug1(WM_CISCAT_LOGTAG, "OUTPUT: %s", output);
            mtinfo(WM_CISCAT_LOGTAG, "Scan finished. File: %s", eval->path);

            break;

        case WM_ERROR_TIMEOUT:
            free(output);
            output = NULL;
            ciscat->flags.error = 1;
            wm_strcat(&output, "ciscat: ERROR: Timeout expired.", '\0');
            mterror(WM_CISCAT_LOGTAG, "Timeout expired executing '%s'.", eval->path);
            break;

        default:
            mterror(WM_CISCAT_LOGTAG, "Internal calling. Exiting...");
            ciscat->flags.error = 1;
            pthread_exit(NULL);
    }

    // Get assessment results

    if (!ciscat->flags.error) {
        scan_info = wm_ciscat_txt_parser();
        if (eval->profile) {
            os_strdup(eval->profile, scan_info->profile);
        } else {
            scan_info->profile = wm_ciscat_get_profile();
        }
        if (!ciscat->flags.error) {
            wm_ciscat_preparser();
            if (!ciscat->flags.error) {
                wm_ciscat_xml_parser();
                wm_ciscat_send_scan(scan_info, id);
            }
        }
    }

    snprintf(msg, OS_MAXSTR, "Ending CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(0, msg, "rootcheck", ROOTCHECK_MQ);

    free(output);
    free(command);
}

#else

// Run a CIS-CAT policy for UNIX systems

void wm_ciscat_run(wm_ciscat_eval *eval, char *path, int id, const char * java_path) {

    char *command = NULL;
    int status, child_status;
    char *output = NULL;
    char msg[OS_MAXSTR];
    char *ciscat_script = "./CIS-CAT.sh";
    wm_scan_data *scan_info = NULL;

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
        mterror(WM_CISCAT_LOGTAG, "OVAL is an invalid content type. Exiting...");
        pthread_exit(NULL);
        break;
    default:
        mterror(WM_CISCAT_LOGTAG, "Unspecified content type for file '%s'. This shouldn't happen.", eval->path);
        pthread_exit(NULL);
    }

    // Specify location for reports

    wm_strcat(&command, "-r", ' ');
    wm_strcat(&command, WM_CISCAT_REPORTS, ' ');

    // Set reports file name

    wm_strcat(&command, "-rn", ' ');
    wm_strcat(&command, "ciscat-report", ' ');

    // Get xml reports

    wm_strcat(&command, "-x", ' ');

    // Get txt reports

    wm_strcat(&command, "-t", ' ');

    // Do not create HTML report

    wm_strcat(&command, "-n", ' ');

    // Add not selected checks

    wm_strcat(&command, "-y", ' ');

    // Send rootcheck message

    snprintf(msg, OS_MAXSTR, "Starting CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);

    // Execute the scan

    pid_t pid;

    switch(pid = fork(), pid) {
        case -1:
            mterror_exit(WM_CISCAT_LOGTAG, FORK_ERROR, errno, strerror(errno));
        case 0:
            // Child process

            setsid();

            if (chdir(path) < 0) {
                ciscat->flags.error = 1;
                mterror(WM_CISCAT_LOGTAG, "Unable to change working directory: %s", strerror(errno));
                _exit(EXIT_FAILURE);
            } else
                mtdebug2(WM_CISCAT_LOGTAG, "Changing working directory to %s", path);

            mtdebug1(WM_CISCAT_LOGTAG, "Launching command: %s", command);

            switch (wm_exec(command, &output, &status, eval->timeout, java_path)) {
                case 0:
                    if (status > 0) {
                        ciscat->flags.error = 1;
                        mterror(WM_CISCAT_LOGTAG, "Ignoring content '%s' due to error (%d).", eval->path, status);
                        mterror(WM_CISCAT_LOGTAG, "OUTPUT: %s", output);
                        _exit(EXIT_FAILURE);
                    }

                    mtinfo(WM_CISCAT_LOGTAG, "Scan finished successfully. File: %s", eval->path);

                    break;

                case WM_ERROR_TIMEOUT:
                    free(output);
                    output = NULL;
                    ciscat->flags.error = 1;
                    wm_strcat(&output, "ciscat: ERROR: Timeout expired.", '\0');
                    mterror(WM_CISCAT_LOGTAG, "Timeout expired executing '%s'.", eval->path);
                    break;

                default:
                    ciscat->flags.error = 1;
                    mterror(WM_CISCAT_LOGTAG, "Internal calling. Exiting...");
                    _exit(EXIT_FAILURE);
            }

            _exit(0);

        default:
            // Parent process

            wm_append_sid(pid);

            switch(waitpid(pid, &child_status, 0)) {
                case -1:
                    mterror(WM_CISCAT_LOGTAG, WAITPID_ERROR, errno, strerror(errno));
                    break;
                default:
                    if (WEXITSTATUS(child_status) == 1){
                        eval->flags.error = 1;
                        free(output);
                        free(command);
                        return;
                    }
            }

            wm_remove_sid(pid);
    }

    // Get assessment results

    if (!ciscat->flags.error) {
        scan_info = wm_ciscat_txt_parser();
        if (eval->profile) {
            os_strdup(eval->profile, scan_info->profile);
        } else {
            scan_info->profile = wm_ciscat_get_profile();
        }
        if (!ciscat->flags.error) {
            wm_ciscat_preparser();
            if (!ciscat->flags.error) {
                wm_ciscat_xml_parser();
                wm_ciscat_send_scan(scan_info, id);
            }
        }
    }

    snprintf(msg, OS_MAXSTR, "Ending CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);

    free(output);
    free(command);
}

#endif

char * wm_ciscat_get_profile() {

    char * profile = NULL;
    char readbuff[OS_MAXSTR];
    char file[OS_MAXSTR];
    FILE *fp;
    int i;

    #ifdef WIN32
        snprintf(file, OS_MAXSTR - 1, "%s%s", TMP_DIR, "\\ciscat-report.xml");
    #else
        snprintf(file, OS_MAXSTR - 1, "%s%s", WM_CISCAT_REPORTS, "/ciscat-report.xml");
    #endif


#ifdef WIN32
    if ((fp = fopen(file, "rb"))) {
#else
    if ((fp = fopen(file, "r"))) {
#endif

        do{
            if (fgets(readbuff, OS_MAXSTR, fp)){}
        } while (!strstr(readbuff, WM_CISCAT_PROFILE) && !strstr(readbuff, WM_CISCAT_PROFILE2));

        char ** parts = NULL;

        parts = OS_StrBreak('"', readbuff, 3);
        os_strdup(parts[1], profile);

        for (i=0; parts[i]; i++){
            free(parts[i]);
        }
        free(parts);

        fclose(fp);
    }

    if (profile == NULL) {
        os_strdup("unknown", profile);
    }

    return profile;
}

wm_scan_data* wm_ciscat_txt_parser(){

    char file[OS_MAXSTR];
    FILE *fp;
    char readbuff[OS_MAXSTR];
    int line = 0;
    int last_line = 0;
    int final = 0;
    int i;
    size_t size;
    wm_scan_data *info = NULL;
    wm_rule_data *rule = NULL;

    os_calloc(1, sizeof(wm_scan_data), info);
    os_calloc(1, sizeof(wm_rule_data), rule);

    head = rule;

    // Define report location

#ifdef WIN32
    snprintf(file, OS_MAXSTR - 1, "%s%s", TMP_DIR, "\\ciscat-report.txt");
#else
    snprintf(file, OS_MAXSTR - 1, "%s%s", WM_CISCAT_REPORTS, "/ciscat-report.txt");
#endif

    if ((fp = fopen(file, "r"))){

        while (fgets(readbuff, OS_MAXSTR, fp) != NULL){

            // Remove '\r\n' from log lines

            if (!last_line){
                size_t length;
                length = strlen(readbuff);
                readbuff[length - 1] = '\0';
            #ifndef WIN32
                readbuff[length - 2] = '\0';
            #endif
            }

            line++;

            if (line == 1){
                os_strdup(readbuff, info->benchmark);

            } else if (line == 2) {

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 3);
                os_strdup(parts[2], info->hostname);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 3) {

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 2);
                os_strdup(parts[1], info->timestamp);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 4){
                continue;

            } else if ((strstr(readbuff, "**********") != NULL)){

                line = 5;
                final = 1;

            } else if (line == 6 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 2);
                info->pass = atoi(parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 7 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 2);
                info->fail = atoi(parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 8 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 2);
                info->error = atoi(parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 9 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 2);
                info->unknown = atoi(parts[1]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 10 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 3);
                info->notchecked = atoi(parts[2]);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if (line == 13 && final){

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 2);
                os_strdup(parts[1], info->score);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

            } else if ((!strncmp(readbuff, "Actual", 6))) {
                continue;

            } else if ((!strncmp(readbuff, "Maximum", 7))) {
                last_line = 1;
                continue;

            } else {

                char ** parts = NULL;

                parts = OS_StrBreak(' ', readbuff, 3);

                os_strdup(parts[1], rule->id);
                os_strdup(parts[2], rule->title);

                char result[MAX_RESULT];
                snprintf(result, MAX_RESULT - 1, "%s", parts[0]);

                size = strlen(result);
                if (result[size - 1] == ':') {
                    result[size - 1] = '\0';
                }

                os_strdup(result, rule->result);

                for (i=0; parts[i]; i++){
                    free(parts[i]);
                }
                free(parts);

                os_calloc(1, sizeof(wm_rule_data), rule->next);

                rule = rule->next;

            }
        }

        mtdebug1(WM_CISCAT_LOGTAG, "Finished parse of the TXT report.");

        fclose(fp);
    } else {
        mterror(WM_CISCAT_LOGTAG, "Unable to read file %s: %s", file, strerror(errno));
        ciscat->flags.error = 1;
    }

    unlink(file);

    return info;
}

void wm_ciscat_preparser(){

    char in_file[OS_MAXSTR];
    char out_file[OS_MAXSTR];
    size_t size;
    char* readbuff = NULL;
    char* result = NULL;
    char* string;
    char* aux_str;
    FILE *in_fp;
    FILE *out_fp;
    int inside = 0;
    int inside_rule = 0;
    int print_result = 0;

#ifdef WIN32
    snprintf(in_file, OS_MAXSTR - 1, "%s%s", TMP_DIR, "\\ciscat-report.xml");
    snprintf(out_file, OS_MAXSTR - 1, "%s%s", TMP_DIR, "\\ciscat-tmp.xml");
#else
    snprintf(in_file, OS_MAXSTR - 1, "%s%s", WM_CISCAT_REPORTS, "/ciscat-report.xml");
    snprintf(out_file, OS_MAXSTR - 1, "%s%s", WM_CISCAT_REPORTS, "/ciscat-tmp.xml");
#endif

#ifdef WIN32
    if ((in_fp = fopen(in_file, "rb"))) {
#else
    if ((in_fp = fopen(in_file, "r"))) {
#endif

        os_calloc(OS_MAXSTR, sizeof(char), readbuff);
        os_calloc(OS_MAXSTR, sizeof(char), result);

        do{
            if (fgets(readbuff, OS_MAXSTR, in_fp)){}     // We want to ignore this part
        } while (!strstr(readbuff, WM_CISCAT_GROUP_START) && !strstr(readbuff, WM_CISCAT_GROUP_START2));

        if ((out_fp = fopen(out_file, "w")) == NULL) {

            mterror(WM_CISCAT_LOGTAG, "Unable to open '%s' for writing: %s", in_file, strerror(errno));
            ciscat->flags.error = 1;
            free(readbuff);
            free(result);
            fclose(in_fp);
            unlink(in_file);
            return;
        }

        fprintf(out_fp, "%s", readbuff);

        while (fgets(readbuff, OS_MAXSTR, in_fp) && (strstr(readbuff, WM_CISCAT_RESULT_START) == NULL)) {

            if (strstr(readbuff, WM_CISCAT_RULE_START) || strstr(readbuff, WM_CISCAT_RULE_START2)) {
                inside_rule = 1;
            } else if (strstr(readbuff, WM_CISCAT_RULE_END) || strstr(readbuff, WM_CISCAT_RULE_END2)) {
                inside_rule = 0;
                print_result = 0;
            }

            if (inside_rule) {
                if (strstr(readbuff, WM_CISCAT_DESC_START) || strstr(readbuff, WM_CISCAT_DESC_START2)) {
                    print_result = 1;
                    if (strstr(readbuff, WM_CISCAT_DESC_END) || strstr(readbuff, WM_CISCAT_DESC_END2)) {
                        string = wm_ciscat_remove_tags(readbuff);
                        size = strlen(string);
                        if (string[size - 1] == '\n') {
                            string[size - 1] = '\0';
                        }
                        snprintf(result, OS_MAXSTR - 1, "<description>%s</description>", string);
                        free(string);
                    } else {
                        size = strlen(readbuff);
                        if (readbuff[size - 1] == '\n') {
                            readbuff[size - 1] = '\0';
                        }
                        snprintf(result, OS_MAXSTR - 1, "%s", readbuff);
                        inside = 1;
                        continue;
                    }
                } else if (strstr(readbuff, WM_CISCAT_RATIO_START) || strstr(readbuff, WM_CISCAT_RATIO_START2)) {
                    print_result = 1;
                    if (strstr(readbuff, WM_CISCAT_RATIO_END) || strstr(readbuff, WM_CISCAT_RATIO_END2)) {
                        string = wm_ciscat_remove_tags(readbuff);
                        size = strlen(string);
                        if (string[size - 1] == '\n') {
                            string[size - 1] = '\0';
                        }
                        snprintf(result, OS_MAXSTR - 1, "<rationale>%s</rationale>", string);
                        free(string);
                    } else {
                        size = strlen(readbuff);
                        if (readbuff[size - 1] == '\n') {
                            readbuff[size - 1] = '\0';
                        }
                        snprintf(result, OS_MAXSTR - 1, "%s", readbuff);
                        inside = 1;
                        continue;
                    }
                } else if (strstr(readbuff, WM_CISCAT_FIXTEXT_START) || strstr(readbuff, WM_CISCAT_FIXTEXT_START2)) {
                    print_result = 1;
                    if (strstr(readbuff, WM_CISCAT_FIXTEXT_END) || strstr(readbuff, WM_CISCAT_FIXTEXT_END2)) {
                        string = wm_ciscat_remove_tags(readbuff);
                        size = strlen(string);
                        if (string[size - 1] == '\n') {
                            string[size - 1] = '\0';
                        }
                        snprintf(result, OS_MAXSTR - 1, "<fixtext>%s</fixtext>", string);
                        free(string);
                    } else {
                        size = strlen(readbuff);
                        if (readbuff[size - 1] == '\n') {
                            readbuff[size - 1] = '\0';
                        }
                        snprintf(result, OS_MAXSTR - 1, "%s", readbuff);
                        inside = 1;
                        continue;
                    }
                } else if (!inside)
                    print_result = 0;
            }

            if (inside) {
                aux_str = strchr(readbuff, '<');
                if (aux_str != NULL) {
                    if (strstr(aux_str, WM_CISCAT_DESC_END) || strstr(aux_str, WM_CISCAT_RATIO_END) || strstr(aux_str, WM_CISCAT_FIXTEXT_END) || strstr(aux_str, WM_CISCAT_DESC_END2) || strstr(aux_str, WM_CISCAT_RATIO_END2) || strstr(aux_str, WM_CISCAT_FIXTEXT_END2)) {
                        wm_strcat(&result, aux_str, '\0');
                        inside = 0;
                    } else {
                        string = wm_ciscat_remove_tags(aux_str);
                        size = strlen(string);
                        if (string[size - 1] == '\n') {
                            string[size - 1] = ' ';
                        }
                        wm_strcat(&result, string, '\0');
                        free(string);
                        continue;
                    }
                }
            }

            if (print_result) {
                fprintf(out_fp, "%s", result);
            } else {
                fprintf(out_fp, "%s", readbuff);
            }
        }

        free(result);
        free(readbuff);

        fclose(in_fp);
        fclose(out_fp);

        mtdebug1(WM_CISCAT_LOGTAG, "Finished preparse of the XML report.");

    } else {
        mterror(WM_CISCAT_LOGTAG, "Unable to open '%s': %s", in_file, strerror(errno));
        ciscat->flags.error = 1;
    }

    unlink(in_file);

}

char* wm_ciscat_remove_tags(char* string){

    int i = 0, j = 0;
    int empty = 1;
    int inside = 0;
    char* result = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), result);

    while (string[i] != '\0') {

        if (string[i] == '<' || string[i] == '&') {
            inside = 1;
        } else if (inside) {
            if (string[i] == '>' || string[i] == ';') {
                inside = 0;
                i++;
                continue;
            }
        }

        if (!inside) {
            result[j] = string[i];
            j++;
        }
        i++;
    }

    for (i = 0; result[i]; i++) {
        if (result[i] != ' ' &&  result[i] != '\n'){
            empty = 0;
        }
    }

    if (empty)
        memset(result, '\0', OS_MAXSTR);

    return result;

}

void wm_ciscat_xml_parser(){

    OS_XML xml;
    XML_NODE node = NULL;
    wm_rule_data *rule_info;
    char *group = NULL;

    // Set pointer to the head of the linked list

    rule_info = head;

    char xml_file[OS_MAXSTR];
    int i = 0;

    // XML definitions

    const char *XML_GROUP = "Group";
    const char *XML_RULE = "Rule";
    const char *XML_GROUP2 = "xccdf:Group";
    const char *XML_RULE2 = "xccdf:Rule";

#ifdef WIN32
    snprintf(xml_file, OS_MAXSTR - 1, "%s%s", TMP_DIR, "\\ciscat-tmp.xml");
#else
    snprintf(xml_file, OS_MAXSTR - 1, "%s%s", WM_CISCAT_REPORTS, "/ciscat-tmp.xml");
#endif

    if (OS_ReadXML(xml_file, &xml) < 0) {
        mterror(WM_CISCAT_LOGTAG, XML_ERROR, xml_file, xml.err, xml.err_line);
        return;
    }

    node = OS_GetElementsbyNode(&xml, NULL);
    if (node == NULL) {
        mterror(WM_CISCAT_LOGTAG, "OS_GetElementsbyNode error: %s, line: %d\n", xml.err, xml.err_line);
        return;
    }

    while (node[i]){

        if (!node[i]->element) {
            mterror(WM_CISCAT_LOGTAG, "Unable to parse the XML report.");
            OS_ClearNode(node);
            OS_ClearXML(&xml);
            return;

        } else if ((strcmp(node[i]->element, XML_GROUP) == 0) || (strcmp(node[i]->element, XML_GROUP2) == 0)) {

            XML_NODE child = NULL;
            child = OS_GetElementsbyNode(&xml, node[i]);
            if (child == NULL) {
                mterror(WM_CISCAT_LOGTAG, "Invalid element in XML report: %s", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                OS_ClearNode(node);
                OS_ClearXML(&xml);
                return;
            }

            os_calloc(OS_MAXSTR, sizeof(char), group);

            if ((rule_info = read_group(&xml, child, rule_info, group)) == NULL){
                mterror(WM_CISCAT_LOGTAG, "Unable to read %s node.", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                OS_ClearNode(node);
                OS_ClearXML(&xml);
                return;
            }

            free(group);
            group = NULL;

            OS_ClearNode(child);
            child = NULL;

        } else if ((strcmp(node[i]->element, XML_RULE) == 0) || (strcmp(node[i]->element, XML_RULE2) == 0)) {

            XML_NODE child = NULL;
            child = OS_GetElementsbyNode(&xml, node[i]);
            if (child == NULL) {
                mterror(WM_CISCAT_LOGTAG, "Invalid element in XML report: %s", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                OS_ClearNode(node);
                OS_ClearXML(&xml);
                return;
            }

            if ((rule_info = read_rule_info(child, rule_info, group)) == NULL) {
                mterror(WM_CISCAT_LOGTAG, "Unable to read %s node.", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                OS_ClearNode(node);
                OS_ClearXML(&xml);
                return;
            }

            OS_ClearNode(child);
            child = NULL;
        }
        i++;
    }

    mtdebug1(WM_CISCAT_LOGTAG, "Finished parse of the XML report.");

    OS_ClearNode(node);
    node = NULL;
    OS_ClearXML(&xml);

    unlink(xml_file);

}

wm_rule_data* read_group(const OS_XML *xml, XML_NODE node, wm_rule_data *rule_info, char *group){

    const char *XML_GROUP = "Group";
    const char *XML_TITLE = "title";
    const char *XML_RULE = "Rule";
    const char *XML_GROUP2 = "xccdf:Group";
    const char *XML_TITLE2 = "xccdf:title";
    const char *XML_RULE2 = "xccdf:Rule";

    int i;

    if (*group == '\0') {
        for (i = 0; node[i]; i++) {
            if ((strcmp(node[i]->element, XML_TITLE) == 0) || (strcmp(node[i]->element, XML_TITLE2) == 0)) {
                snprintf(group, OS_MAXSTR - 1, "%s", node[i]->content);
                break;
            }
        }
    }

    for (i = 0; node[i]; i++) {

        if ((strcmp(node[i]->element, XML_GROUP) == 0) || (strcmp(node[i]->element, XML_GROUP2) == 0)) {

            XML_NODE child = NULL;
            child = OS_GetElementsbyNode(xml, node[i]);
            if (child == NULL) {
                mterror(WM_CISCAT_LOGTAG, "OS_GetElementsbyNode() error parsing %s", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                return NULL;
            }
            if ((rule_info = read_group(xml, child, rule_info, group)) == NULL) {
                mterror(WM_CISCAT_LOGTAG, "Unable to read %s node.", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                return NULL;
            }
            OS_ClearNode(child);
            child = NULL;
        } else if ((strcmp(node[i]->element, XML_RULE) == 0) || (strcmp(node[i]->element, XML_RULE2) == 0)) {

            XML_NODE child = NULL;
            child = OS_GetElementsbyNode(xml, node[i]);
            if (child == NULL) {
                mterror(WM_CISCAT_LOGTAG, "OS_GetElementsbyNode() error parsing %s", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                return NULL;
            }
            if ((rule_info = read_rule_info(child, rule_info, group)) == NULL) {
                mterror(WM_CISCAT_LOGTAG, "Unable to read %s node.", node[i]->element);
                OS_ClearNode(child);
                child = NULL;
                return NULL;
            }

            OS_ClearNode(child);
            child = NULL;
        }
    }

    return rule_info;
}

wm_rule_data* read_rule_info(XML_NODE node, wm_rule_data *rule, char *group) {

    /* XML definitions */

    const char *XML_DESCRIPTION = "description";
    const char *XML_RATIONALE = "rationale";
    const char *XML_REMEDIATION = "fixtext";
    const char *XML_DESCRIPTION2 = "xccdf:description";
    const char *XML_RATIONALE2 = "xccdf:rationale";
    const char *XML_REMEDIATION2 = "xccdf:fixtext";

    int i;
    size_t size;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            mterror(WM_CISCAT_LOGTAG, XML_ELEMNULL);
            return NULL;
        } else if (!node[i]->content) {
            mterror(WM_CISCAT_LOGTAG, XML_VALUENULL, node[i]->element);
            return NULL;
        } else if (!strcmp(node[i]->element, XML_DESCRIPTION)) {
            os_strdup(node[i]->content, rule->description);
            size = strlen(rule->description);
            if (rule->description[size - 1] == ' ') {
                rule->description[size - 1] = '\0';
            }
        } else if (!strcmp(node[i]->element, XML_RATIONALE)) {
            os_strdup(node[i]->content, rule->rationale);
            size = strlen(rule->rationale);
            if (rule->rationale[size - 1] == ' ') {
                rule->rationale[size - 1] = '\0';
            }
        } else if (!strcmp(node[i]->element, XML_REMEDIATION)) {
            os_strdup(node[i]->content, rule->remediation);
            size = strlen(rule->remediation);
            if (rule->remediation[size - 1] == ' ') {
                rule->remediation[size - 1] = '\0';
            }
        } else if (!strcmp(node[i]->element, XML_DESCRIPTION2)) {
            os_strdup(node[i]->content, rule->description);
            size = strlen(rule->description);
            if (rule->description[size - 1] == ' ') {
                rule->description[size - 1] = '\0';
            }
        } else if (!strcmp(node[i]->element, XML_RATIONALE2)) {
            os_strdup(node[i]->content, rule->rationale);
            size = strlen(rule->rationale);
            if (rule->rationale[size - 1] == ' ') {
                rule->rationale[size - 1] = '\0';
            }
        } else if (!strcmp(node[i]->element, XML_REMEDIATION2)) {
            os_strdup(node[i]->content, rule->remediation);
            size = strlen(rule->remediation);
            if (rule->remediation[size - 1] == ' ') {
                rule->remediation[size - 1] = '\0';
            }
        }
    }

    if (!group) {
        os_strdup("No group defined for this check", rule->group);
    } else {
        os_strdup(group, rule->group);
    }

    rule = rule->next;

    return rule;
}


void wm_ciscat_send_scan(wm_scan_data *info, int id){

    wm_rule_data *rule;
    wm_rule_data *next_rule;
    cJSON *object = NULL;
    cJSON *data = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Set pointer to the head of the linked list

    rule = head;

    // Send global scan information

    object = cJSON_CreateObject();
    data = cJSON_CreateObject();
    cJSON_AddStringToObject(object, "type", "scan_info");
    cJSON_AddNumberToObject(object, "scan_id", id);
    cJSON_AddItemToObject(object, "cis", data);
    cJSON_AddStringToObject(data, "benchmark", info->benchmark);
    cJSON_AddStringToObject(data, "profile", info->profile);
    cJSON_AddStringToObject(data, "hostname", info->hostname);
    cJSON_AddStringToObject(data, "timestamp", info->timestamp);
    cJSON_AddNumberToObject(data, "pass", info->pass);
    cJSON_AddNumberToObject(data, "fail", info->fail);
    cJSON_AddNumberToObject(data, "error", info->error);
    cJSON_AddNumberToObject(data, "unknown", info->unknown);
    cJSON_AddNumberToObject(data, "notchecked", info->notchecked);
    cJSON_AddStringToObject(data, "score", info->score);

    // Send event to queue

    char *msg;

    msg = cJSON_PrintUnformatted(object);
    mtdebug2(WM_CISCAT_LOGTAG, "Sending CIS-CAT event: '%s'", msg);
#ifdef WIN32
    wm_sendmsg(usec, 0, msg, WM_CISCAT_LOCATION, CISCAT_MQ);
#else
    wm_sendmsg(usec, queue_fd, msg, WM_CISCAT_LOCATION, CISCAT_MQ);
#endif
    cJSON_Delete(object);

    free(msg);
    free(info->benchmark);
    free(info->profile);
    free(info->hostname);
    free(info->timestamp);
    free(info->score);
    free(info);

    // Send scan results

    while (rule->next != NULL) {

        object = cJSON_CreateObject();
        data = cJSON_CreateObject();
        cJSON_AddStringToObject(object, "type", "scan_result");
        cJSON_AddNumberToObject(object, "scan_id", id);
        cJSON_AddItemToObject(object, "cis", data);

        cJSON_AddStringToObject(data, "rule_id", rule->id);
        cJSON_AddStringToObject(data, "rule_title", rule->title);
        cJSON_AddStringToObject(data, "group", rule->group);
        cJSON_AddStringToObject(data, "description", rule->description);
        cJSON_AddStringToObject(data, "rationale", rule->rationale);
        cJSON_AddStringToObject(data, "remediation", rule->remediation);
        cJSON_AddStringToObject(data, "result", rule->result);

        rule = rule->next;

        // Send event to queue

        char *msg;

        msg = cJSON_PrintUnformatted(object);
        mtdebug2(WM_CISCAT_LOGTAG, "Sending CIS-CAT event: '%s'", msg);
    #ifdef WIN32
        wm_sendmsg(usec, 0, msg, WM_CISCAT_LOCATION, CISCAT_MQ);
    #else
        wm_sendmsg(usec, queue_fd, msg, WM_CISCAT_LOCATION, CISCAT_MQ);
    #endif
        cJSON_Delete(object);

        free(msg);
    }

    for (rule = head; rule; rule = next_rule) {

        next_rule = rule->next;
        free(rule->id);
        free(rule->title);
        free(rule->group);
        free(rule->description);
        free(rule->rationale);
        free(rule->remediation);
        free(rule->result);
        free(rule);

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


// Get readed data

cJSON *wm_ciscat_dump(const wm_ciscat * ciscat) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_cscat = cJSON_CreateObject();

    if (ciscat->flags.enabled) cJSON_AddStringToObject(wm_cscat,"disabled","no"); else cJSON_AddStringToObject(wm_cscat,"disabled","yes");
    if (ciscat->flags.scan_on_start) cJSON_AddStringToObject(wm_cscat,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_cscat,"scan-on-start","no");
    if (ciscat->interval) cJSON_AddNumberToObject(wm_cscat, "interval", ciscat->interval);
    if (ciscat->scan_day) cJSON_AddNumberToObject(wm_cscat, "day", ciscat->scan_day);
    switch (ciscat->scan_wday) {
        case 0:
            cJSON_AddStringToObject(wm_cscat, "wday", "sunday");
            break;
        case 1:
            cJSON_AddStringToObject(wm_cscat, "wday", "monday");
            break;
        case 2:
            cJSON_AddStringToObject(wm_cscat, "wday", "tuesday");
            break;
        case 3:
            cJSON_AddStringToObject(wm_cscat, "wday", "wednesday");
            break;
        case 4:
            cJSON_AddStringToObject(wm_cscat, "wday", "thursday");
            break;
        case 5:
            cJSON_AddStringToObject(wm_cscat, "wday", "friday");
            break;
        case 6:
            cJSON_AddStringToObject(wm_cscat, "wday", "saturday");
            break;
        default:
            break;
    }
    if (ciscat->scan_time) cJSON_AddStringToObject(wm_cscat, "time", ciscat->scan_time);
    if (ciscat->java_path) cJSON_AddStringToObject(wm_cscat,"java_path",ciscat->java_path);
    if (ciscat->ciscat_path) cJSON_AddStringToObject(wm_cscat,"ciscat_path",ciscat->ciscat_path);
    cJSON_AddNumberToObject(wm_cscat,"timeout",ciscat->timeout);
    if (ciscat->evals) {
        cJSON *evals = cJSON_CreateArray();
        wm_ciscat_eval *ptr;
        for (ptr = ciscat->evals; ptr; ptr = ptr->next) {
            cJSON *eval = cJSON_CreateObject();
            if (ptr->path) cJSON_AddStringToObject(eval,"path",ptr->path);
            if (ptr->profile) cJSON_AddStringToObject(eval,"profile",ptr->profile);
            cJSON_AddNumberToObject(eval,"timeout",ptr->timeout);
            cJSON_AddNumberToObject(eval,"type",ptr->type);
            cJSON_AddItemToArray(evals,eval);
        }
        cJSON_AddItemToObject(wm_cscat,"content",evals);
    }

    cJSON_AddItemToObject(root,"cis-cat",wm_cscat);

    return root;
}


// Destroy data

void wm_ciscat_destroy(wm_ciscat *ciscat) {

    wm_ciscat_eval *cur_eval;
    wm_ciscat_eval *next_eval;

    // Delete evals

    for (cur_eval = ciscat->evals; cur_eval; cur_eval = next_eval) {

        next_eval = cur_eval->next;
        free(cur_eval->path);
        free(cur_eval->profile);
        free(cur_eval);
    }

    free(ciscat);
}
#endif
