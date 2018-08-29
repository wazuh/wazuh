/*
 * Wazuh Module for AWS S3 integration
 * Copyright (C) 2017 Wazuh Inc.
 * January 08, 2018.
 *
 * Updated by Jeremy Phillips <jeremy@uranusbytes.com>
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static wm_aws *aws_config;                              // Pointer to aws_configuration
static int queue_fd;                                    // Output queue file descriptor

static void* wm_aws_main(wm_aws *aws_config);           // Module main function. It won't return
static void wm_aws_setup(wm_aws *_aws_config);          // Setup module
static void wm_aws_cleanup();                           // Cleanup function, doesn't overwrite wm_cleanup
static void wm_aws_check();                             // Check configuration, disable flag
static void wm_aws_run_s3(wm_aws_bucket *bucket);       // Run a s3
static void wm_aws_destroy(wm_aws *aws_config);         // Destroy data

// Command module context definition

const wm_context WM_AWS_CONTEXT = {
    "aws-s3",
    (wm_routine)wm_aws_main,
    (wm_routine)wm_aws_destroy
};

// Module module main function. It won't return.

void* wm_aws_main(wm_aws *aws_config) {
    wm_aws_bucket *cur_bucket;
    time_t time_start;
    time_t time_sleep = 0;

    wm_aws_setup(aws_config);
    mtinfo(WM_AWS_LOGTAG, "Module AWS started");

    // First sleeping

    if (!aws_config->run_on_start) {
        time_start = time(NULL);

        if (aws_config->state.next_time > time_start) {
            mtinfo(WM_AWS_LOGTAG, "Waiting interval to start fetching.");
            sleep(aws_config->state.next_time - time_start);
        }
    }

    // Main loop

    while (1) {

        mtinfo(WM_AWS_LOGTAG, "Starting fetching of logs.");

        // Get time and execute
        time_start = time(NULL);

        for (cur_bucket = aws_config->buckets; cur_bucket; cur_bucket = cur_bucket->next) {
            if (cur_bucket->aws_account_id && cur_bucket->aws_account_alias) {
                mtinfo(WM_AWS_LOGTAG, "Executing Bucket Analisys: %s (%s)", cur_bucket->aws_account_alias, cur_bucket->aws_account_id);
            } else if (cur_bucket->aws_account_id) {
                mtinfo(WM_AWS_LOGTAG, "Executing Bucket Analisys: %s", cur_bucket->aws_account_id);
            } else {
                mtinfo(WM_AWS_LOGTAG, "Executing Bucket Analisys: %s", cur_bucket->bucket);
            }
            wm_aws_run_s3(cur_bucket);
        }

        mtinfo(WM_AWS_LOGTAG, "Fetching logs finished.");

        if (aws_config->interval) {
            time_sleep = time(NULL) - time_start;

            if ((time_t)aws_config->interval >= time_sleep) {
                time_sleep = aws_config->interval - time_sleep;
                aws_config->state.next_time = aws_config->interval + time_start;
            } else {
                mtwarn(WM_AWS_LOGTAG, "Interval overtaken.");
                time_sleep = aws_config->state.next_time = 0;
            }

            if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_WRITE, &aws_config->state, sizeof(aws_config->state)) < 0)
                mterror(WM_AWS_LOGTAG, "Couldn't save running state.");
        }

        // If time_sleep=0, yield CPU
        sleep(time_sleep);
    }

    return NULL;
}

// Destroy data

void wm_aws_destroy(wm_aws *aws_config) {
    free(aws_config);
}

// Setup module

void wm_aws_setup(wm_aws *_aws_config) {
    int i;

    aws_config = _aws_config;
    wm_aws_check();

    // Read running state

    if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_READ, &aws_config->state, sizeof(aws_config->state)) < 0)
        memset(&aws_config->state, 0, sizeof(aws_config->state));

    // Connect to socket

    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        sleep(WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_AWS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting

    atexit(wm_aws_cleanup);
}


// Check configuration

void wm_aws_check() {
    // Check if disabled

    if (!aws_config->enabled) {
        mtinfo(WM_AWS_LOGTAG, "Module AWS is disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if buckets defines

    if (!aws_config->buckets) {
        mtwarn(WM_AWS_LOGTAG, "No AWS buckets defined. Exiting...");
        pthread_exit(NULL);
    }

    // Check if interval defined; otherwise set default

    if (!aws_config->interval)
        aws_config->interval = WM_AWS_DEFAULT_INTERVAL;

}

// Cleanup function, doesn't overwrite wm_cleanup

void wm_aws_cleanup() {
    close(queue_fd);
    mtinfo(WM_AWS_LOGTAG, "Module AWS finished.");
}

// Run a bucket parsing

void wm_aws_run_s3(wm_aws_bucket *exec_bucket) {
    int status;
    char *output = NULL;
    char *command = NULL;

    // Define time to sleep between messages sent
    int usec = 1000000 / wm_max_eps;

    // Create arguments
    mtdebug2(WM_AWS_LOGTAG, "Create argument list");

    wm_strcat(&command, WM_AWS_SCRIPT_PATH, '\0');
    wm_strcat(&command, "--bucket", ' ');
    wm_strcat(&command, exec_bucket->bucket, ' ');

    if (exec_bucket->remove_from_bucket) {
        wm_strcat(&command, "--remove", ' ');
    }
    if (exec_bucket->access_key) {
        wm_strcat(&command, "--access_key", ' ');
        wm_strcat(&command, exec_bucket->access_key, ' ');
    }
    if (exec_bucket->secret_key) {
        wm_strcat(&command, "--secret_key", ' ');
        wm_strcat(&command, exec_bucket->secret_key, ' ');
    }
    if (exec_bucket->aws_profile) {
        wm_strcat(&command, "--aws_profile", ' ');
        wm_strcat(&command, exec_bucket->aws_profile, ' ');
    }
    if (exec_bucket->iam_role_arn) {
        wm_strcat(&command, "--iam_role_arn", ' ');
        wm_strcat(&command, exec_bucket->iam_role_arn, ' ');
    }
    if (exec_bucket->aws_account_id) {
        wm_strcat(&command, "--aws_account_id", ' ');
        wm_strcat(&command, exec_bucket->aws_account_id, ' ');
    }
    if (exec_bucket->aws_account_alias) {
        wm_strcat(&command, "--aws_account_alias", ' ');
        wm_strcat(&command, exec_bucket->aws_account_alias, ' ');
    }
    if (exec_bucket->trail_prefix) {
        wm_strcat(&command, "--trail_prefix", ' ');
        wm_strcat(&command, exec_bucket->trail_prefix, ' ');
    }
    if (exec_bucket->only_logs_after) {
        wm_strcat(&command, "--only_logs_after", ' ');
        wm_strcat(&command, exec_bucket->only_logs_after, ' ');
    }
    if (exec_bucket->regions) {
        wm_strcat(&command, "--regions", ' ');
        wm_strcat(&command, exec_bucket->regions, ' ');
    }
    if (exec_bucket->type) {
        wm_strcat(&command, "--type", ' ');
        wm_strcat(&command, exec_bucket->type, ' ');
    }
    if (isDebug()) {
        wm_strcat(&command, "--debug", ' ');
        if (isDebug() > 2) {
            wm_strcat(&command, "3", ' ');
        } else if (isDebug() > 1) {
            wm_strcat(&command, "2", ' ');
        } else {
            wm_strcat(&command, "1", ' ');
        }
    }
    if (aws_config->skip_on_error) {
        wm_strcat(&command, "--skip_on_error", ' ');
    }
    if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_READ, &aws_config->state, sizeof(aws_config->state)) < 0) {
        memset(&aws_config->state, 0, sizeof(aws_config->state));
    }

    // Execute

    char *trail_title = NULL;
    wm_strcat(&trail_title, "Bucket:", ' ');
    wm_strcat(&trail_title, exec_bucket->aws_account_id, ' ');
    if(exec_bucket->aws_account_alias){
        wm_strcat(&trail_title, "(", '\0');
        wm_strcat(&trail_title, exec_bucket->aws_account_alias, '\0');
        wm_strcat(&trail_title, ")", '\0');
    }
    wm_strcat(&trail_title, " - ", ' ');

    mtdebug1(WM_AWS_LOGTAG, "Launching S3 Command: %s", command);
    switch (wm_exec(command, &output, &status, 0)) {
    case 0:
        if (status > 0) {
            mtwarn(WM_AWS_LOGTAG, "%s Returned exit code %d", trail_title, status);
            if(status == 1) {
                char * unknown_error_msg = strstr(output,"Unknown error");
                if (unknown_error_msg == NULL)
                    mtwarn(WM_AWS_LOGTAG, "%s Unknown error.", trail_title);
                else
                    mtwarn(WM_AWS_LOGTAG, "%s %s", trail_title, unknown_error_msg);
            }
            else if(status == 2)
                mtwarn(WM_AWS_LOGTAG, "%s Error parsing arguments: %s", trail_title, strstr(output, "aws.py: error:")+14);
            else
                mtwarn(WM_AWS_LOGTAG, "%s %s", trail_title, strstr(output, "ERROR: ")+7);

            mtdebug1(WM_AWS_LOGTAG, "%s OUTPUT: %s", trail_title, output);
        } else {
            mtdebug2(WM_AWS_LOGTAG, "%s OUTPUT: %s", trail_title, output);
        }
        break;

    default:
        mterror(WM_AWS_LOGTAG, "Internal calling. Exiting...");
        pthread_exit(NULL);
    }
    char * line;

    for (line = strtok(output, "\n"); line; line = strtok(NULL, "\n")){
        wm_sendmsg(usec, queue_fd, line, WM_AWS_CONTEXT.name, LOCALFILE_MQ);
    }
    free(line);
    free(trail_title);
    free(output);
    free(command);
}
