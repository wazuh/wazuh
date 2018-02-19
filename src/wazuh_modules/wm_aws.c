/*
 * Wazuh Module for AWS CloudTrail integration
 * Copyright (C) 2017 Wazuh Inc.
 * January 08, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static void * wm_aws_main(wm_aws_t * config);    // Module main function. It won't return
static void wm_aws_destroy(wm_aws_t * config);   // Destroy data

// Command module context definition

const wm_context WM_AWS_CONTEXT = {
    "aws-cloudtrail",
    (wm_routine)wm_aws_main,
    (wm_routine)wm_aws_destroy
};

// Module module main function. It won't return.

void * wm_aws_main(wm_aws_t * config) {
    time_t time_start;
    time_t time_sleep = 0;
    int usec = 1000000 / wm_max_eps;
    struct timeval timeout = { 0, usec };

    if (!config->enabled) {
        mtwarn(WM_AWS_LOGTAG, "Module AWS-CloudTrail is disabled. Exiting.");
        pthread_exit(0);
    }

    mtinfo(WM_AWS_LOGTAG, "Module AWS-CloudTrail started");

    // Connect to socket
    
    int i;

    for (i = 0; config->queue_fd = StartMQ(DEFAULTQPATH, WRITE), config->queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++) {
        sleep(WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_AWS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // First sleeping

    if (!config->run_on_start) {
        time_start = time(NULL);

        if (config->state.next_time > time_start) {
            mtinfo(WM_AWS_LOGTAG, "Waiting interval to start fetching.");
            sleep(config->state.next_time - time_start);
        }
    }

    while (1) {
        int status;
        char * output = NULL;
        char *command = NULL;  
  
        // Create arguments

        wm_strcat(&command, WM_AWS_SCRIPT_PATH, '\0');
        wm_strcat(&command, "--bucket", ' ');
        wm_strcat(&command, config->bucket, ' ');

        if (config->remove_from_bucket) {
            wm_strcat(&command, "--remove", ' ');
        }
        if (config->access_key) {
            wm_strcat(&command, "--access_key", ' ');
            wm_strcat(&command, config->access_key, ' ');
        }
        if (config->secret_key) {
            wm_strcat(&command, "--secret_key", ' ');
            wm_strcat(&command, config->secret_key, ' ');
        }
        if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_READ, &config->state, sizeof(config->state)) < 0) {
            memset(&config->state, 0, sizeof(config->state));
        }

        mtinfo(WM_AWS_LOGTAG, "Fetching logs started");

        // Get time and execute
        time_start = time(NULL);

        switch (wm_exec(command, &output, &status, 0)) {
        case 0:
            if (status > 0) {
                mtwarn(WM_AWS_LOGTAG, "Returned exit code %d.", status);
                if(status == 3)
                    mtwarn(WM_AWS_LOGTAG, "Invalid credentials to access S3 Bucket");
                if(status == 4)
                    mtwarn(WM_AWS_LOGTAG, "boto3 module is required.");
                mtdebug2(WM_AWS_LOGTAG, "OUTPUT: %s", output);
            }

            break;

        default:
            mterror(WM_AWS_LOGTAG, "Internal calling. Exiting...");
            pthread_exit(NULL);
        }

        char * line;

        for (line = strtok(output, "\n"); line; line = strtok(NULL, "\n")){
            timeout.tv_usec = usec;
            select(0 , NULL, NULL, NULL, &timeout);
            SendMSG(config->queue_fd, line, WM_AWS_CONTEXT.name, LOCALFILE_MQ);
        }

        free(output);
        free(command);

        mtinfo(WM_AWS_LOGTAG, "Fetching logs finished.");

        if (config->interval) {
            time_sleep = time(NULL) - time_start;

            if ((time_t)config->interval >= time_sleep) {
                time_sleep = config->interval - time_sleep;
                config->state.next_time = config->interval + time_start;
            } else {
                mtwarn(WM_AWS_LOGTAG, "Interval overtaken.");
                time_sleep = config->state.next_time = 0;
            }

            if (wm_state_io(WM_AWS_CONTEXT.name, WM_IO_WRITE, &config->state, sizeof(config->state)) < 0)
                mterror(WM_AWS_LOGTAG, "Couldn't save running state.");
        }

        // If time_sleep=0, yield CPU
        sleep(time_sleep);
    }

    return NULL;
}

// Destroy data

void wm_aws_destroy(wm_aws_t * config) {
    free(config);
}
