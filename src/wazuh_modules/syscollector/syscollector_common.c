/*
 * Wazuh Module for System inventory
 * Copyright (C) 2017 Wazuh Inc.
 * March 9, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "syscollector.h"
#include <errno.h>

static wm_sys_t *sys;                           // Pointer to configuration

static void* wm_sys_main(wm_sys_t *sys);        // Module main function. It won't return
const char *WM_SYS_LOCATION = "syscollector";   // Location field for event sending

// Syscollector module context definition

const wm_context WM_SYS_CONTEXT = {
    "syscollector",
    (wm_routine)wm_sys_main,
    NULL
};

#ifndef WIN32
int queue_fd;                                   // Output queue file descriptor
#endif

static void delay(unsigned int ms);
static void wm_sys_setup(wm_sys_t *_sys);       // Setup module
static void wm_sys_check();                     // Check configuration, disable flag
#ifndef WIN32
static void wm_sys_cleanup();                   // Cleanup function, doesn't overwrite wm_cleanup
#endif

// Module main function. It won't return

void* wm_sys_main(wm_sys_t *sys) {

    time_t time_start = 0;
    time_t time_sleep = 0;

    // Check configuration and show debug information

    wm_sys_setup(sys);
    mtinfo(WM_SYS_LOGTAG, "Module started.");

    // First sleeping

    if (!sys->flags.scan_on_start) {
        time_start = time(NULL);

        if (sys->state.next_time > time_start) {
            mtinfo(WM_SYS_LOGTAG, "Waiting for turn to evaluate.");
            delay(1000 * (sys->state.next_time - time_start));
        }
    }

    #ifdef WIN32
        if (!checkVista()){
            mtwarn(WM_SYS_LOGTAG, "Network and OS scan is incompatible with versions older than Vista.");
            sys->flags.netinfo = 0;
            sys->flags.osinfo = 0;
        }
    #endif

    // Main loop

    while (1) {

        mtinfo(WM_SYS_LOGTAG, "Starting evaluation.");

        // Get time and execute
        time_start = time(NULL);

        /* Network inventory */
        if (sys->flags.netinfo){
            #ifdef WIN32
                sys_network_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_network_linux(queue_fd, WM_SYS_LOCATION);
            #elif defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
                sys_network_bsd(queue_fd, WM_SYS_LOCATION);
            #endif
        }

        /* Operating System inventory */
        if (sys->flags.osinfo){
            #ifdef WIN32
                sys_os_windows(WM_SYS_LOCATION);
            #else
                sys_os_unix(queue_fd, WM_SYS_LOCATION);
            #endif
        }

        /* Hardware inventory */
        if (sys->flags.hwinfo){
            #if defined(WIN32)
                sys_hw_windows(WM_SYS_LOCATION);
            #elif defined(__linux__)
                sys_hw_linux(queue_fd, WM_SYS_LOCATION);
            #else
                sys->flags.hwinfo = 0;
                mtwarn(WM_SYS_LOGTAG, "Hardware inventory is not available for this OS version.");
            #endif
        }

        time_sleep = time(NULL) - time_start;

        mtinfo(WM_SYS_LOGTAG, "Evaluation finished.");

        if ((time_t)sys->interval >= time_sleep) {
            time_sleep = sys->interval - time_sleep;
            sys->state.next_time = sys->interval + time_start;
        } else {
            mterror(WM_SYS_LOGTAG, "Interval overtaken.");
            time_sleep = sys->state.next_time = 0;
        }

        if (wm_state_io(&WM_SYS_CONTEXT, WM_IO_WRITE, &sys->state, sizeof(sys->state)) < 0)
            mterror(WM_SYS_LOGTAG, "Couldn't save running state.");

        // If time_sleep=0, yield CPU
        delay(1000 * time_sleep);
    }

    return NULL;
}

// Setup module

static void wm_sys_setup(wm_sys_t *_sys) {

    sys = _sys;
    wm_sys_check();

    // Read running state

    if (wm_state_io(&WM_SYS_CONTEXT, WM_IO_READ, &sys->state, sizeof(sys->state)) < 0)
        memset(&sys->state, 0, sizeof(sys->state));

    #ifndef WIN32

    int i;
    // Connect to socket
    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++)
        delay(1000 * WM_MAX_WAIT);

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_SYS_LOGTAG, "Can't connect to queue.");
        pthread_exit(NULL);
    }

    // Cleanup exiting
    atexit(wm_sys_cleanup);

    #endif
}

#ifndef WIN32
void wm_sys_cleanup() {
    close(queue_fd);
    mtinfo(WM_SYS_LOGTAG, "Module finished.");
}
#endif

// Check configuration

void wm_sys_check() {

    // Check if disabled

    if (!sys->flags.enabled) {
        mterror(WM_SYS_LOGTAG, "Module disabled. Exiting...");
        pthread_exit(NULL);
    }

    // Check if evals

    if (!sys->flags.netinfo) {
        mtwarn(WM_SYS_LOGTAG, "Network scan disabled.");
    }

    if (!sys->flags.osinfo) {
        mtwarn(WM_SYS_LOGTAG, "OS scan disabled.");
    }

    if (!sys->flags.hwinfo) {
        mtwarn(WM_SYS_LOGTAG, "Hardware scan disabled.");
    }

    // Check if interval

    if (!sys->interval)
        sys->interval = WM_SYS_DEF_INTERVAL;
}

void delay(unsigned int ms) {
#ifdef WIN32
    Sleep(ms);
#else
    struct timeval timeout = { ms / 1000, (ms % 1000) * 1000};
    select(0, NULL, NULL, NULL, &timeout);
#endif

}
