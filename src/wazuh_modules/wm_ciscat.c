/*
 * Wazuh Module for CIS-CAT
 * Copyright (C) 2015, Wazuh Inc.
 * December, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef ENABLE_CISCAT
#include "wmodules.h"
#include "wm_exec.h"

static wm_ciscat *ciscat;                             // Pointer to configuration
static wm_rule_data *head;                            // Pointer to head of rules data

#ifndef WIN32
static int queue_fd;                                // Output queue file descriptor
#endif

#ifdef WIN32
static DWORD WINAPI wm_ciscat_main(void *arg);                  // Module main function. It won't return
#else
static void* wm_ciscat_main(wm_ciscat *ciscat);        // Module main function. It won't return
#endif
static void wm_ciscat_destroy(wm_ciscat *ciscat);      // Destroy data
static void wm_ciscat_setup(wm_ciscat *_ciscat);       // Setup module
static void wm_ciscat_check();                       // Check configuration, disable flag
static void wm_ciscat_run(wm_ciscat_eval *eval, char *path, int id, const char *java_path, const char *ciscat_binary);      // Run a CIS-CAT policy
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
cJSON *wm_ciscat_dump(const wm_ciscat *ciscat);

const char *WM_CISCAT_LOCATION = "wodle_cis-cat";  // Location field for event sending

// CIS-CAT module context definition

const wm_context WM_CISCAT_CONTEXT = {
    .name = "cis-cat",
    .start = (wm_routine)wm_ciscat_main,
    .destroy = (void(*)(void *))wm_ciscat_destroy,
    .dump = (cJSON * (*)(const void *))wm_ciscat_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

// CIS-CAT module main function. It won't return.
#ifdef WIN32
DWORD WINAPI wm_ciscat_main(void *arg) {
    wm_ciscat *ciscat = (wm_ciscat *)arg;
#else
void* wm_ciscat_main(wm_ciscat *ciscat) {
#endif
    wm_ciscat_eval *eval;
    int skip_java = 0;
    char *cis_path = NULL;
    char java_fullpath[OS_MAXSTR];
    char bench_fullpath[OS_MAXSTR];
    char * timestamp = NULL;

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
                snprintf(java_fullpath, OS_MAXSTR - 1, "%s", ciscat->java_path);
            #endif
                break;
            default:
                mterror(WM_CISCAT_LOGTAG, "Defined Java path is not valid. Using the default one.");
                skip_java = 1;
        }

        if (!skip_java) {
            os_free(ciscat->java_path);
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
                {
                    char pwd[PATH_MAX];
                    if (getcwd(pwd, sizeof(pwd)) == NULL) {
                        mterror(WM_CISCAT_LOGTAG, "Could not get the current working directory: %s (%d)", strerror(errno), errno);
                        ciscat->flags.error = 1;
                    } else {
                        os_snprintf(cis_path, OS_MAXSTR - 1, "%s/%s", pwd, ciscat->ciscat_path);
                    }
                }
            #endif
                break;
            default:
                mterror(WM_CISCAT_LOGTAG, "Defined CIS-CAT path is not valid.");
                ciscat->flags.error = 1;
        }
    } else {
    #ifdef WIN32
        if (*current) {
            snprintf(cis_path, OS_MAXSTR - 1, "%s\\%s", current, WM_CISCAT_DEFAULT_DIR_WIN);
        }
    #else
        snprintf(cis_path, OS_MAXSTR - 1, "%s", WM_CISCAT_DEFAULT_DIR);
    #endif
    }

    if (IsDir(cis_path) < 0) {
        mterror(WM_CISCAT_LOGTAG, "CIS-CAT tool not found at '%s'.", cis_path);
        ciscat->flags.error = 1;
    }

    // Main loop

    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(ciscat->scan_config), WM_CISCAT_LOGTAG, ciscat->flags.scan_on_start);

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(ciscat->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_CISCAT_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }

        if (!ciscat->flags.error) {
            mtinfo(WM_CISCAT_LOGTAG, "Starting evaluation.");

            // Set unique ID for each scan

        #ifndef WIN32
            int id = os_random();
            if (id < 0)
                id = -id;
        #else
            char random_id[RANDOM_LENGTH];
            snprintf(random_id, RANDOM_LENGTH - 1, "%u%u", os_random(), os_random());
            int id = atoi(random_id);

            if (id < 0) {
                id = -id;
            }
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
                            os_free(eval->path);
                            os_strdup(bench_fullpath, eval->path);
                            break;
                        default:
                            mterror(WM_CISCAT_LOGTAG, "Couldn't find benchmark path. Skipping...");
                    }

                    if (IsFile(eval->path) < 0) {
                        mterror(WM_CISCAT_LOGTAG, "Benchmark file '%s' not found.", eval->path);
                    } else {
                        wm_ciscat_run(eval, cis_path, id, ciscat->java_path, ciscat->ciscat_binary);
                        ciscat->flags.error = 0;
                    }
                }
            }
        }

        mtinfo(WM_CISCAT_LOGTAG, "Evaluation finished.");
    } while(FOREVER());

    free(cis_path);
#ifdef WIN32
    free(current);
    return 0;
#else
    return NULL;
#endif
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

    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
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

void wm_ciscat_run(wm_ciscat_eval *eval, char *path, int id, const char *java_path, const char *ciscat_binary) {
    char *command = NULL;
    char msg[OS_MAXSTR];
    char *ciscat_script;
    wm_scan_data *scan_info = NULL;
    char eval_path[OS_MAXSTR];

    os_calloc(OS_MAXSTR, sizeof(char), ciscat_script);

    snprintf(ciscat_script, OS_MAXSTR - 1, "\"%s\\%s\"", path, ciscat_binary);

    // Create arguments

    wm_strcat(&command, ciscat_script, '\0');

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
        os_free(command);
        os_free(ciscat_script);
        pthread_exit(NULL);
        break;
    default:
        mterror(WM_CISCAT_LOGTAG, "Unspecified content type for file '%s'. This shouldn't happen.", eval->path);
        ciscat->flags.error = 1;
        os_free(command);
        os_free(ciscat_script);
        pthread_exit(NULL);
    }

    // CIS-CAT Pro V3
    if (!strcmp(ciscat_binary, WM_CISCAT_V3_BINARY_WIN)) {
        // Accepting Terms of Use

        wm_strcat(&command, "-a", ' ');

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
    } else if (!strcmp(ciscat_binary, WM_CISCAT_V4_BINARY_WIN)) {
        // CIS-CAT Pro V4

        // Specify location for reports

        wm_strcat(&command, "-rd", ' ');
        wm_strcat(&command, TMP_DIR, ' ');

        // Set reports file name

        wm_strcat(&command, "-rp", ' ');
        wm_strcat(&command, "ciscat-report", ' ');

        // Do not include the auto-generated timestamp as part of the report name
        wm_strcat(&command, "-nts", ' ');

        // Get txt reports
        wm_strcat(&command, "-txt", ' ');
    } else {
        mterror(WM_CISCAT_LOGTAG, "CIS-CAT binary (%s) is neither %s nor %s. Exiting...", ciscat_binary, WM_CISCAT_V3_BINARY_WIN, WM_CISCAT_V4_BINARY_WIN);
        ciscat->flags.error = 1;
        os_free(ciscat_script);
        pthread_exit(NULL);
        return;
    }

    // Send rootcheck message

    snprintf(msg, OS_MAXSTR, "Starting CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(0, msg, "rootcheck", ROOTCHECK_MQ);

    // Execute the scan

    mtdebug1(WM_CISCAT_LOGTAG, "Launching command: %s", command);

    int status;
    char *output = NULL;
    switch (wm_exec(command, &output, &status, eval->timeout, java_path)) {
        case 0:
            if (status == 0) {
                mtinfo(WM_CISCAT_LOGTAG, "Scan finished successfully. File: %s", eval->path);
            } else {
                ciscat->flags.error = 1;
                mterror(WM_CISCAT_LOGTAG, "Ignoring content '%s' due to error (%d).", eval->path, status);
                mtdebug1(WM_CISCAT_LOGTAG, "OUTPUT: %s", output);
            }
            break;
        case WM_ERROR_TIMEOUT:
            ciscat->flags.error = 1;
            mterror(WM_CISCAT_LOGTAG, "Timeout expired executing '%s'.", eval->path);
            break;
        default:
            mterror(WM_CISCAT_LOGTAG, "Internal error. Exiting...");
            ciscat->flags.error = 1;
            os_free(command);
            os_free(ciscat_script);
            pthread_exit(NULL);
    }

    os_free(output);
    os_free(command);
    os_free(ciscat_script);

    // Get assessment results
    if (!ciscat->flags.error) {
        scan_info = wm_ciscat_txt_parser();
        if (!ciscat->flags.error) {
            if (eval->profile) {
                os_strdup(eval->profile, scan_info->profile);
            } else {
                scan_info->profile = wm_ciscat_get_profile();
            }
            // send scan results if the txt file is right.
            wm_ciscat_send_scan(scan_info, id);
        } else {
            wm_ciscat_preparser();
            if (!ciscat->flags.error) {
                wm_ciscat_xml_parser();
                wm_ciscat_send_scan(scan_info, id);
            }
        }

        if (ciscat->flags.error) {
            mterror(WM_CISCAT_LOGTAG, "Failed reading scan results for policy '%s'", eval->path);
        }
    }

    if (scan_info) {
        os_free(scan_info->profile);
        os_free(scan_info->benchmark);
        os_free(scan_info->hostname);
        os_free(scan_info->timestamp);
        os_free(scan_info->score);
        os_free(scan_info);
    }

    snprintf(msg, OS_MAXSTR, "Ending CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(0, msg, "rootcheck", ROOTCHECK_MQ);
}

#else

// Run a CIS-CAT policy for UNIX systems

void wm_ciscat_run(wm_ciscat_eval *eval, char *path, int id, const char *java_path, const char *ciscat_binary) {

    char *command = NULL;
    int status, child_status;
    char *output = NULL;
    char msg[OS_MAXSTR];
    wm_scan_data *scan_info = NULL;
    char pwd[PATH_MAX];

    if (getcwd(pwd, sizeof(pwd)) == NULL) {
        mterror(WM_CISCAT_LOGTAG, "Could not get the current working directory: %s (%d)", strerror(errno), errno);
        pthread_exit(NULL);
    }

    // Create arguments
    wm_strcat(&command, path, '/');
    wm_strcat(&command, ciscat_binary, '/');

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
        os_free(command);
        pthread_exit(NULL);
        break;
    default:
        mterror(WM_CISCAT_LOGTAG, "Unspecified content type for file '%s'. This shouldn't happen.", eval->path);
        os_free(command);
        pthread_exit(NULL);
    }

    char reports_path[PATH_MAX];
    os_snprintf(reports_path, sizeof(reports_path), "%s/%s", pwd, WM_CISCAT_REPORTS);

    // CIS-CAT Pro V3
    if (!strcmp(ciscat_binary, WM_CISCAT_V3_BINARY)) {
        // Accepting Terms of Use

        wm_strcat(&command, "-a", ' ');

        // Specify location for reports

        wm_strcat(&command, "-r", ' ');
        wm_strcat(&command, reports_path, ' ');

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
    } else if (!strcmp(ciscat_binary, WM_CISCAT_V4_BINARY)) {
        // CIS-CAT Pro V4

        // Specify location for reports

        wm_strcat(&command, "-rd", ' ');
        wm_strcat(&command, reports_path, ' ');

        // Set reports file name

        wm_strcat(&command, "-rp", ' ');
        wm_strcat(&command, "ciscat-report", ' ');

        // Do not include the auto-generated timestamp as part of the report name
        wm_strcat(&command, "-nts", ' ');

        // Get txt reports
        wm_strcat(&command, "-txt", ' ');
    } else {
        mterror(WM_CISCAT_LOGTAG, "CIS-CAT binary (%s) is neither %s nor %s. Exiting...", ciscat_binary, WM_CISCAT_V3_BINARY, WM_CISCAT_V4_BINARY);
        ciscat->flags.error = 1;
        pthread_exit(NULL);
    }

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

            if (!strcmp(ciscat_binary, WM_CISCAT_V3_BINARY)) {
                if (chdir(path) < 0) {
                    ciscat->flags.error = 1;
                    mterror(WM_CISCAT_LOGTAG, "Unable to change working directory: %s", strerror(errno));
                    os_free(command);
                    _exit(EXIT_FAILURE);
                }
            }

            mtdebug2(WM_CISCAT_LOGTAG, "Changing working directory to %s", path);
            mtdebug1(WM_CISCAT_LOGTAG, "Launching command: %s", command);

            switch (wm_exec(command, &output, &status, eval->timeout, java_path)) {
                case 0:
                    if (status == 0) {
                        mtinfo(WM_CISCAT_LOGTAG, "Scan finished successfully. File: %s", eval->path);
                    } else {
                        ciscat->flags.error = 1;
                        mterror(WM_CISCAT_LOGTAG, "Ignoring content '%s' due to error (%d).", eval->path, status);
                        mterror(WM_CISCAT_LOGTAG, "OUTPUT: %s", output);
                    }
                    break;
                case WM_ERROR_TIMEOUT:
                    ciscat->flags.error = 1;
                    mterror(WM_CISCAT_LOGTAG, "Timeout expired executing '%s'.", eval->path);
                    break;
                default:
                    ciscat->flags.error = 1;
                    mterror(WM_CISCAT_LOGTAG, "Internal error. Exiting...");
                    os_free(command);
                    _exit(EXIT_FAILURE);
            }
            os_free(output);
            os_free(command);
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
                        os_free(output);
                        os_free(command);
                        return;
                    }
            }

            wm_remove_sid(pid);
    }

    os_free(output);
    os_free(command);

    // Get assessment results
    if (!ciscat->flags.error) {
        scan_info = wm_ciscat_txt_parser();
        if (!ciscat->flags.error) {
            if (eval->profile) {
                os_strdup(eval->profile, scan_info->profile);
            } else {
                scan_info->profile = wm_ciscat_get_profile();
            }
            // send scan results if the txt file is right.
            wm_ciscat_send_scan(scan_info, id);
        } else {
            wm_ciscat_preparser();
            if (!ciscat->flags.error) {
                wm_ciscat_xml_parser();
                wm_ciscat_send_scan(scan_info, id);
            }
        }

        if (ciscat->flags.error) {
            mterror(WM_CISCAT_LOGTAG, "Failed reading scan results for policy '%s'", eval->path);
        }
    }

    if (scan_info) {
        os_free(scan_info->profile);
        os_free(scan_info->benchmark);
        os_free(scan_info->hostname);
        os_free(scan_info->timestamp);
        os_free(scan_info->score);
        os_free(scan_info);
    }

    snprintf(msg, OS_MAXSTR, "Ending CIS-CAT scan. File: %s. ", eval->path);
    SendMSG(queue_fd, msg, "rootcheck", ROOTCHECK_MQ);
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
    if ((fp = wfopen(file, "rb"))) {
#else
    if ((fp = wfopen(file, "r"))) {
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

    // Define report location

#ifdef WIN32
    snprintf(file, OS_MAXSTR - 1, "%s%s", TMP_DIR, "\\ciscat-report.txt");
#else
    snprintf(file, OS_MAXSTR - 1, "%s%s", WM_CISCAT_REPORTS, "/ciscat-report.txt");
#endif

    if ((fp = wfopen(file, "r"))){

        os_calloc(1, sizeof(wm_scan_data), info);
        os_calloc(1, sizeof(wm_rule_data), rule);

        head = rule;

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

            } else if ((readbuff[0] == '\0')) {
                // Jump the empty line
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
        mterror(WM_CISCAT_LOGTAG, "Report result file '%s' missing: %s", file, strerror(errno));
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
    if ((in_fp = wfopen(in_file, "rb"))) {
#else
    if ((in_fp = wfopen(in_file, "r"))) {
#endif

        os_calloc(OS_MAXSTR, sizeof(char), readbuff);
        os_calloc(OS_MAXSTR, sizeof(char), result);

        do{
            if (fgets(readbuff, OS_MAXSTR, in_fp)){}     // We want to ignore this part
        } while (!strstr(readbuff, WM_CISCAT_GROUP_START) && !strstr(readbuff, WM_CISCAT_GROUP_START2));

        if ((out_fp = wfopen(out_file, "w")) == NULL) {

            mterror(WM_CISCAT_LOGTAG, "Unable to open '%s' for writing: %s", in_file, strerror(errno));
            ciscat->flags.error = 1;
            free(readbuff);
            free(result);
            fclose(in_fp);
            unlink(in_file);
            return;
        }

        fprintf(out_fp, "%s", readbuff);

        while (fgets(readbuff, OS_MAXSTR, in_fp) && (strstr(readbuff, WM_CISCAT_RESULT_START) == NULL && strstr(readbuff, WM_CISCAT_RESULT_START2) == NULL)) {

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
                        if (size > 0) {
                            if (string[size - 1] == '\n') {
                                string[size - 1] = '\0';
                            }
                            snprintf(result, OS_MAXSTR - 1, "<description>%s</description>", string);
                        }
                        free(string);
                    } else {
                        size = strlen(readbuff);
                        if (size > 0) {
                            if (readbuff[size - 1] == '\n') {
                                readbuff[size - 1] = '\0';
                            }
                            snprintf(result, OS_MAXSTR - 1, "%s", readbuff);
                        }
                        inside = 1;
                        continue;
                    }
                } else if (strstr(readbuff, WM_CISCAT_RATIO_START) || strstr(readbuff, WM_CISCAT_RATIO_START2)) {
                    print_result = 1;
                    if (strstr(readbuff, WM_CISCAT_RATIO_END) || strstr(readbuff, WM_CISCAT_RATIO_END2)) {
                        string = wm_ciscat_remove_tags(readbuff);
                        size = strlen(string);
                        if (size > 0) {
                            if (string[size - 1] == '\n') {
                                string[size - 1] = '\0';
                            }
                            snprintf(result, OS_MAXSTR - 1, "<rationale>%s</rationale>", string);
                        }
                        free(string);
                    } else {
                        size = strlen(readbuff);
                        if (size > 0) {
                            if (readbuff[size - 1] == '\n') {
                                readbuff[size - 1] = '\0';
                            }
                            snprintf(result, OS_MAXSTR - 1, "%s", readbuff);
                        }
                        inside = 1;
                        continue;
                    }
                } else if (strstr(readbuff, WM_CISCAT_FIXTEXT_START) || strstr(readbuff, WM_CISCAT_FIXTEXT_START2)) {
                    print_result = 1;
                    if (strstr(readbuff, WM_CISCAT_FIXTEXT_END) || strstr(readbuff, WM_CISCAT_FIXTEXT_END2)) {
                        string = wm_ciscat_remove_tags(readbuff);
                        size = strlen(string);
                        if (size > 0) {
                            if (string[size - 1] == '\n') {
                                string[size - 1] = '\0';
                            }
                            snprintf(result, OS_MAXSTR - 1, "<fixtext>%s</fixtext>", string);
                        }
                        free(string);
                    } else {
                        size = strlen(readbuff);
                        if (size > 0) {
                            if (readbuff[size - 1] == '\n') {
                                readbuff[size - 1] = '\0';
                            }
                            snprintf(result, OS_MAXSTR - 1, "%s", readbuff);
                        }
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
                        if (size > 0) {
                            if (string[size - 1] == '\n') {
                                string[size - 1] = ' ';
                            }
                            wm_strcat(&result, string, '\0');
                        }
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
                free(group);
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


// Get read data

cJSON *wm_ciscat_dump(const wm_ciscat * ciscat) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_cscat = cJSON_CreateObject();

    if (ciscat->flags.enabled) cJSON_AddStringToObject(wm_cscat,"disabled","no"); else cJSON_AddStringToObject(wm_cscat,"disabled","yes");
    if (ciscat->flags.scan_on_start) cJSON_AddStringToObject(wm_cscat,"scan-on-start","yes"); else cJSON_AddStringToObject(wm_cscat,"scan-on-start","no");


    sched_scan_dump(&(ciscat->scan_config), wm_cscat);

    if (ciscat->java_path) cJSON_AddStringToObject(wm_cscat,"java_path",ciscat->java_path);
    if (ciscat->ciscat_path) cJSON_AddStringToObject(wm_cscat,"ciscat_path",ciscat->ciscat_path);
    if (ciscat->ciscat_binary) cJSON_AddStringToObject(wm_cscat,"ciscat_binary",ciscat->ciscat_binary);
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

    free(ciscat->java_path);
    free(ciscat->ciscat_path);
    free(ciscat->ciscat_binary);
    free(ciscat);
}
#endif
