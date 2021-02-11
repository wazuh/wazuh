/*
 * Wazuh Module for Docker integration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October, 2018.
 *
 * This program is free software; you can redistribute it
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
    (wm_routine)(void *)wm_docker_destroy,
    (cJSON * (*)(const void *))wm_docker_dump
};

// Module module main function. It won't return.

void* wm_docker_main(wm_docker_t *docker_conf) {
    int status = 0;
    char * command = WM_DOCKER_SCRIPT_PATH;
    char * timestamp = NULL;
    int attempts = 0;

    wm_docker_setup(docker_conf);
    mtinfo(WM_DOCKER_LOGTAG, "Module docker-listener started.");

    // Main
    do {
        const time_t time_sleep = sched_scan_get_time_until_next_scan(&(docker_conf->scan_config), WM_DOCKER_LOGTAG, docker_conf->flags.run_on_start);

        if (time_sleep) {
            const int next_scan_time = sched_get_next_scan_time(docker_conf->scan_config);
            timestamp = w_get_timestamp(next_scan_time);
            mtdebug2(WM_DOCKER_LOGTAG, "Sleeping until: %s", timestamp);
            os_free(timestamp);
            w_sleep_until(next_scan_time);
        }
        mtinfo(WM_DOCKER_LOGTAG, "Starting to listening Docker events.");

        // Running the docker listener script

        mtdebug1(WM_DOCKER_LOGTAG, "Launching command '%s'", command);

        wfd_t * wfd = wpopenl(command, W_BIND_STDERR | W_APPEND_POOL, command, NULL);

        if (wfd == NULL) {
            mterror(WM_DOCKER_LOGTAG, "Cannot launch Docker integration due to an internal error.");
            pthread_exit(NULL);
        }

        char buffer[4096];

        while (fgets(buffer, sizeof(buffer), wfd->file)) {
            char * end = strchr(buffer, '\n');
            if (end) {
                *end = '\0';
            }

            mterror(WM_DOCKER_LOGTAG, "%s", buffer);
        }

        // At this point, DockerListener terminated

        status = wpclose(wfd);
        int exitcode = WEXITSTATUS(status);

        switch (exitcode) {
        case 127:
            mterror(WM_DOCKER_LOGTAG, "Cannot launch Docker integration. Please check the file '%s'", command);
            pthread_exit(NULL);

        default:
            if (++attempts >= docker_conf->attempts) {
                mterror(WM_DOCKER_LOGTAG, "Maximum attempts reached to run the listener. Exiting...");
                pthread_exit(NULL);
            }
            mtwarn(WM_DOCKER_LOGTAG, "Docker-listener finished unexpectedly (code %d). Retrying to run in next scheduled time...", exitcode);
        }
    } while (FOREVER());

    return NULL;
}


// Get read data

cJSON *wm_docker_dump(const wm_docker_t *docker_conf) {

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_docker = cJSON_CreateObject();

    sched_scan_dump(&(docker_conf->scan_config), wm_docker);

    if (docker_conf->flags.enabled) cJSON_AddStringToObject(wm_docker,"disabled","no"); else cJSON_AddStringToObject(wm_docker,"disabled","yes");
    if (docker_conf->flags.run_on_start) cJSON_AddStringToObject(wm_docker,"run_on_start","yes"); else cJSON_AddStringToObject(wm_docker,"run_on_start","no");
    cJSON_AddNumberToObject(wm_docker, "attempts", docker_conf->attempts);
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
