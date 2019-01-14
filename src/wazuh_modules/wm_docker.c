/*
 * Wazuh Module for Docker integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WIN32

#include "wmodules.h"

static wm_docker_t *docker_conf;                               // Pointer to docker config struct

static void* wm_docker_main(wm_docker_t *docker_conf);         // Module main function. It won't return
static void wm_docker_setup(wm_docker_t *_docker_conf);        // Setup module
static void wm_docker_cleanup();                               // Cleanup function, doesn't overwrite wm_cleanup
static void wm_docker_check();                                 // Check configuration, disable flag
static void wm_docker_destroy(wm_docker_t *docker_conf);       // Destroy data
cJSON *wm_docker_dump(const wm_docker_t *docker_conf);         // Dump docker config to JSON

// Docker module context definition

const wm_context WM_DOCKER_CONTEXT = {
    "docker-listener",
    (wm_routine)wm_docker_main,
    (wm_routine)wm_docker_destroy,
    (cJSON * (*)(const void *))wm_docker_dump
};

// Module module main function. It won't return.

void* wm_docker_main(wm_docker_t *docker_conf) {

    int status = 0;
    char * command = NULL;
    char * output = NULL;
    int attempts = 0;

    wm_docker_setup(docker_conf);
    mtinfo(WM_DOCKER_LOGTAG, "Module docker-listener started");

    // First sleeping

    if (!docker_conf->flags.run_on_start) {
        mtinfo(WM_DOCKER_LOGTAG, "Waiting the interval (%u seconds) to run the listener.", docker_conf->interval);
        sleep(docker_conf->interval);
    }

    // Main loop

    while (1) {

        mtinfo(WM_DOCKER_LOGTAG, "Starting to listening Docker events.");

        // Running the docker listener script

        command = strdup(WM_DOCKER_SCRIPT_PATH);

        mtdebug1(WM_DOCKER_LOGTAG, "Launching command '%s'.", command);

        switch (wm_exec(command, &output, &status, 0, NULL)) {
            case 0:
                if (status > 0) {
                    mtwarn(WM_DOCKER_LOGTAG, "Returned exit code %d", status);
                    mterror(WM_DOCKER_LOGTAG, "OUTPUT: %s", output);
                } else {
                    if (output) {
                        mtdebug2(WM_DOCKER_LOGTAG, "OUTPUT: %s", output);
                    }
                }
                attempts++;
                break;
            default:
                mterror(WM_DOCKER_LOGTAG, "Internal calling. Exiting...");
                pthread_exit(NULL);
        }

        if (attempts > docker_conf->attempts) {
            mtinfo(WM_DOCKER_LOGTAG, "Maximum attempts reached to run the listener. Exiting...");
            pthread_exit(NULL);
        }

        mtinfo(WM_DOCKER_LOGTAG, "Docker-listener finished unexpected. Retrying to run it in %u seconds...", docker_conf->interval);
        sleep(docker_conf->interval);

    }

    return NULL;
}


// Get readed data

cJSON *wm_docker_dump(const wm_docker_t *docker_conf) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_docker = cJSON_CreateObject();

    if (docker_conf->flags.enabled) cJSON_AddStringToObject(wm_docker,"disabled","no"); else cJSON_AddStringToObject(wm_docker,"disabled","yes");
    if (docker_conf->flags.run_on_start) cJSON_AddStringToObject(wm_docker,"run_on_start","yes"); else cJSON_AddStringToObject(wm_docker,"run_on_start","no");
    cJSON_AddNumberToObject(wm_docker,"interval",docker_conf->interval);

    cJSON_AddItemToObject(root,"docker-listener",wm_docker);

    return root;
}


// Destroy data

void wm_docker_destroy(wm_docker_t *docker_conf) {
    free(docker_conf);
}

// Setup module

void wm_docker_setup(wm_docker_t *_docker_conf) {

    docker_conf = _docker_conf;
    wm_docker_check();

    // Cleanup exiting

    atexit(wm_docker_cleanup);
}


// Check configuration

void wm_docker_check() {
    // Check if disabled

    if (!docker_conf->flags.enabled) {
        mtinfo(WM_DOCKER_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if interval defined; otherwise set default

    if (!docker_conf->interval)
        docker_conf->interval = WM_DOCKER_DEF_INTERVAL;

}

// Cleanup function, doesn't overwrite wm_cleanup

void wm_docker_cleanup() {
    mtinfo(WM_DOCKER_LOGTAG, "Module finished.");
}

#endif
