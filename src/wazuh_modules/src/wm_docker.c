/*
 * Wazuh Module for Docker integration
 * Copyright (C) 2015, Wazuh Inc.
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

// PID of the listener currently running, or 0 if none. Read by wm_docker_stop()
// from the signal handling path, so it must stay a plain atomic value: taking a
// lock the module thread may be holding is not an option there.
static volatile sig_atomic_t docker_child_pid = 0;

static void* wm_docker_main(wm_docker_t *docker_conf);         // Module main function. It won't return
static void wm_docker_setup(wm_docker_t *_docker_conf);        // Setup module
static void wm_docker_cleanup();                               // Cleanup function, doesn't overwrite wm_cleanup
static void wm_docker_check();                                 // Check configuration, disable flag
static void wm_docker_destroy(wm_docker_t *docker_conf);       // Destroy data
static void wm_docker_stop(wm_docker_t *docker_conf);          // Stop module
static void wm_docker_terminate_child(pid_t child);            // Terminate a running listener
cJSON *wm_docker_dump(const wm_docker_t *docker_conf);         // Dump docker config to JSON

// Docker module context definition

const wm_context WM_DOCKER_CONTEXT = {
    .name = "docker-listener",
    .start = (wm_routine)wm_docker_main,
    .destroy = (void(*)(void *))wm_docker_destroy,
    .dump = (cJSON * (*)(const void *))wm_docker_dump,
    .sync = NULL,
    .stop = (void(*)(void *))wm_docker_stop,
    .query = NULL,
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
            wm_sleep_until_interruptible(next_scan_time);
            if (wm_shutdown_requested) break;
        }
        if (wm_shutdown_requested) break;
        mtinfo(WM_DOCKER_LOGTAG, "Starting to listening Docker events.");

        // Running the docker listener script

        mtdebug1(WM_DOCKER_LOGTAG, "Launching command '%s'", command);

        wfd_t * wfd = wpopenl(command, W_BIND_STDERR, command, NULL);

        if (wfd == NULL) {
            mterror(WM_DOCKER_LOGTAG, "Cannot launch Docker integration due to an internal error.");
            pthread_exit(NULL);
        }

#ifdef WIN32
        wm_append_handle(wfd->pinfo.hProcess);
#else
        if (0 <= wfd->pid) {
            // Arm the signal target before anything else, so a shutdown that
            // arrives right now still reaches the listener.
            docker_child_pid = wfd->pid;
            wm_append_sid(wfd->pid);

            // A shutdown that started while the listener was being launched
            // read docker_child_pid before this thread wrote it, so its
            // stop() found nothing to signal. Cover that window here.
            if (wm_shutdown_requested) {
                wm_docker_terminate_child(wfd->pid);
            }
        }
#endif

        char buffer[4096];

        while (fgets(buffer, sizeof(buffer), wfd->file_out)) {
            char * end = strchr(buffer, '\n');
            if (end) {
                *end = '\0';
            }

            if (strncmp(buffer, "INFO ", 5) == 0) {
                mtinfo(WM_DOCKER_LOGTAG, "%s", buffer + 5);
            } else if (strncmp(buffer, "WARN ", 5) == 0) {
                mtwarn(WM_DOCKER_LOGTAG, "%s", buffer + 5);
            } else {
                mterror(WM_DOCKER_LOGTAG, "%s", buffer);
            }
        }

        // At this point, DockerListener terminated
#ifdef WIN32
        wm_remove_handle(wfd->pinfo.hProcess);
#else
        // Stop treating the child as a signal target before wpclose() reaps it,
        // so its PID can never be recycled while it is still one.
        docker_child_pid = 0;

        if (0 <= wfd->pid) {
            wm_remove_sid(wfd->pid);
        }
#endif
        status = wpclose(wfd);
        int exitcode = WEXITSTATUS(status);

        if (wm_shutdown_requested) {
            // The listener was terminated on purpose by wm_docker_stop().
            break;
        }

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
    } while (FOREVER() && !wm_shutdown_requested);

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

// Terminate a running listener

void wm_docker_terminate_child(pid_t child) {
    if (child <= 0) {
        return;
    }

    // wpopenv() calls setsid() in the child, so its PGID ends up equal to its
    // PID and the group signal also reaches anything the listener spawned.
    // setsid() runs after fork() returns here, though, so the group may not
    // exist yet: signal the process itself too, which always works.
    kill(-child, SIGTERM);
    kill(child, SIGTERM);
}

// Stop module

void wm_docker_stop(__attribute__((unused)) wm_docker_t *docker_conf) {
    // Signal only: terminating the listener makes the module thread's fgets()
    // return, which is what lets its thread be joined. Without this the thread
    // stays blocked until wm_kill_children() runs on exit, which is too late:
    // the service control script has already escalated to SIGKILL by then and
    // the listener survives as an orphan.

    wm_docker_terminate_child((pid_t)docker_child_pid);
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
