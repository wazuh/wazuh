/*
 * Wazuh Module for custom command execution
 * Copyright (C) 2017 Wazuh Inc.
 * October 26, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static void * wm_command_main(wm_command_t * command);    // Module main function. It won't return
static void wm_command_destroy(wm_command_t * command);   // Destroy data

// Command module context definition

const wm_context WM_COMMAND_CONTEXT = {
    "command",
    (wm_routine)wm_command_main,
    (wm_routine)wm_command_destroy
};

// Module module main function. It won't return.

void * wm_command_main(wm_command_t * command) {
    time_t time_start;
    time_t time_sleep = 0;
    size_t extag_len;
    char * extag;
    int usec = 1000000 / wm_max_eps;
    int validation;

    // Verify command
    if (command->md5_hash && command->md5_hash[0]) {
        validation = wm_validate_command(command->command, command->md5_hash, MD5SUM);

        switch (validation) {
            case 1:
                mdebug1("MD5 hash matched: %s\n", command->command);
                break;

            case 0:
                merror("MD5 hash does not match: '%s' \n", command->command);
                if (!command->skip_verification)
                    pthread_exit(NULL);
                break;

            case -1:
                merror("Cannot check binary: '%s' \n", command->command);
                pthread_exit(NULL);
                break;
        }
    }

    if (command->sha1_hash && command->sha1_hash[0]) {
        validation = wm_validate_command(command->command, command->sha1_hash, SHA1SUM);

        switch (validation) {
            case 1:
                mdebug1("SHA1 hash matched: %s\n", command->command);
                break;

            case 0:
                merror("SHA1 hash does not match: '%s' \n", command->command);
                if (!command->skip_verification)
                    pthread_exit(NULL);
                break;

            case -1:
                merror("Cannot check binary: '%s' \n", command->command);
                pthread_exit(NULL);
                break;
        }
    }

    if (command->sha256_hash && command->sha256_hash[0]) {
        validation = wm_validate_command(command->command, command->sha256_hash, SHA256SUM);

        switch (validation) {
            case 1:
                mdebug1("SHA256 hash matched: %s\n", command->command);
                break;

            case 0:
                merror("SHA256 hash does not match: '%s' \n", command->command);
                if (!command->skip_verification)
                    pthread_exit(NULL);
                break;

            case -1:
                merror("Cannot check binary: '%s' \n", command->command);
                pthread_exit(NULL);
                break;
        }
    }

    if (!command->enabled) {
        mtwarn(WM_COMMAND_LOGTAG, "Module command:%s is disabled. Exiting.", command->tag);
        pthread_exit(0);
    }

#ifdef CLIENT
    if (!getDefine_Int("wazuh_command", "remote_commands", 0, 1) && command->agent_cfg) {
        mtwarn(WM_COMMAND_LOGTAG, "Remote commands are disabled. Ignoring '%s'.", command->tag);
        pthread_exit(0);
    }
#endif

    mtinfo(WM_COMMAND_LOGTAG, "Module command:%s started", command->tag);

    // Set extended tag

    extag_len = strlen(WM_COMMAND_CONTEXT.name) + strlen(command->tag) + 2;
    os_malloc(extag_len * sizeof(char), extag);
    snprintf(extag, extag_len, "%s_%s", WM_COMMAND_CONTEXT.name, command->tag);

    if (wm_state_io(extag, WM_IO_READ, &command->state, sizeof(command->state)) < 0) {
        memset(&command->state, 0, sizeof(command->state));
    }

    // Connect to socket

#ifndef WIN32
    if (!command->ignore_output) {
        int i;

        for (i = 0; command->queue_fd = StartMQ(DEFAULTQPATH, WRITE), command->queue_fd < 0 && i < WM_MAX_ATTEMPTS; i++) {
            sleep(WM_MAX_WAIT);
        }

        if (i == WM_MAX_ATTEMPTS) {
            mterror(WM_COMMAND_LOGTAG, "Can't connect to queue.");
            pthread_exit(NULL);
        }
    }
#endif

    // First sleeping

    if (!command->run_on_start) {
        time_start = time(NULL);

        if (command->state.next_time > time_start) {
            mtinfo(WM_COMMAND_LOGTAG, "%s: Waiting for turn to evaluate.", command->tag);
            sleep(command->state.next_time - time_start);
        }
    }

    while (1) {
        int status;
        char * output = NULL;

        mtdebug1(WM_COMMAND_LOGTAG, "Starting command '%s'.", command->tag);

        // Get time and execute
        time_start = time(NULL);

        switch (wm_exec(command->command, command->ignore_output ? NULL : &output, &status, command->timeout)) {
        case 0:
            if (status > 0) {
                mtwarn(WM_COMMAND_LOGTAG, "Command '%s' returned exit code %d.", command->tag, status);

                if (!command->ignore_output) {
                    mtdebug2(WM_COMMAND_LOGTAG, "OUTPUT: %s", output);
                }
            }

            break;

        default:
            mterror(WM_COMMAND_LOGTAG, "%s: Internal calling. Exiting...", command->tag);
            pthread_exit(NULL);
        }

        if (!command->ignore_output) {
            char * line;

            for (line = strtok(output, "\n"); line; line = strtok(NULL, "\n")){
            #ifdef WIN32
                wm_sendmsg(usec, 0, line, extag, LOCALFILE_MQ);
            #else
                wm_sendmsg(usec, command->queue_fd, line, extag, LOCALFILE_MQ);
            #endif
            }

            free(output);
        }


        mtdebug1(WM_COMMAND_LOGTAG, "Command '%s' finished.", command->tag);

        if (command->interval) {
            time_sleep = time(NULL) - time_start;

            if ((time_t)command->interval >= time_sleep) {
                time_sleep = command->interval - time_sleep;
                command->state.next_time = command->interval + time_start;
            } else {
                mtwarn(WM_COMMAND_LOGTAG, "%s: Interval overtaken.", command->tag);
                time_sleep = command->state.next_time = 0;
            }

            if (wm_state_io(extag, WM_IO_WRITE, &command->state, sizeof(command->state)) < 0)
                mterror(WM_COMMAND_LOGTAG, "%s: Couldn't save running state.", command->tag);
        }

        // If time_sleep=0, yield CPU
        sleep(time_sleep);
    }

    return NULL;
}

// Destroy data

void wm_command_destroy(wm_command_t * command) {
    free(command->tag);
    free(command->command);
    free(command);
}
