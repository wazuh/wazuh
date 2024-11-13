/*
 * Wazuh Module Manager
 * Copyright (C) 2015, Wazuh Inc.
 * April 22, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <sys/types.h>

static void wm_help();                  // Print help.
static void wm_setup();                 // Setup function. Exits on error.
static void wm_cleanup();               // Cleanup function, called on exiting.
static void wm_handler(int signum);     // Action on signal.

static int flag_foreground = 0;         // Running in foreground.

// Main function

int main(int argc, char **argv)
{
    int c;
    int wm_debug = 0;
    int test_config = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    wmodule *cur_module;
    wm_debug_level = getDefine_Int("wazuh_modules", "debug", 0, 2);

    // Get command line options

    while ((c = getopt(argc, argv, "dfht")) != -1) {
        switch (c) {
        case 'd':
            nowDebug();
            wm_debug = 1;
            break;
        case 'f':
            flag_foreground = 1;
            break;
        case 'h':
            wm_help();
            break;
        case 't':
            test_config = 1;
            flag_foreground = 1;
            break;
        default:
            print_out(" ");
            wm_help();
        }
    }

    // Get default debug level

    if (wm_debug == 0) {
        wm_debug = wm_debug_level;

        while (wm_debug != 0) {
            nowDebug();
            wm_debug--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);

    // Setup daemon

    wm_setup();

    if (test_config)
        exit(EXIT_SUCCESS);

    minfo(STARTUP_MSG, (int)getpid());

    // Run modules

    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        if (CreateThreadJoinable(&cur_module->thread, cur_module->context->start, cur_module->data) < 0) {
            merror_exit("CreateThreadJoinable() for '%s': %s", cur_module->tag, strerror(errno));
        }
        mdebug2("Created new thread for the '%s' module.", cur_module->tag);
    }

    // Start com request thread
    w_create_thread(wmcom_main, NULL);

    // Wait for threads

    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        pthread_join(cur_module->thread, NULL);
    }

    return EXIT_SUCCESS;
}

// Print help

void wm_help()
{
    print_out("Wazuh Module Manager - %s\nWazuh Inc.", __ossec_version);
    print_out(" ");
    print_out("Usage: %s -[d|f|h|t]", ARGV0);
    print_out(" ");
    print_out("    -d    Increase debug mode.");
    print_out("    -f    Run in foreground.");
    print_out("    -h    Print this help.");
    print_out("    -t    Test configuration.");

    exit(EXIT_FAILURE);
}

// Setup function. Exits on error.

void wm_setup()
{
    struct sigaction action = { .sa_handler = wm_handler };

    // Read XML settings and internal options

    if (wm_config() < 0) {
        exit(EXIT_FAILURE);
    }

    // Go daemon

    if (!flag_foreground) {
        goDaemon();
        nowDaemon();
    }

    const gid_t gid = Privsep_GetGroup(GROUPGLOBAL);
    if (gid == (gid_t) OS_INVALID) {
        merror_exit(USER_ERROR, "", GROUPGLOBAL, strerror(errno), errno);
    }

    wm_setGroupID(gid);

    if (wm_check() < 0) {
        minfo("No configuration defined. Exiting...");
        exit(EXIT_SUCCESS);
    }

    // Signal management

    atexit(wm_cleanup);
    sigaction(SIGTERM, &action, NULL);

    if (flag_foreground) {
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
    }

    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    // Create PID file

    if (CreatePID(ARGV0, getpid()) < 0)
        merror_exit("Couldn't create PID file: (%s)", strerror(errno));

    // Initialize children pool
    wm_children_pool_init();
}

// Cleanup function, called on exiting.

void wm_cleanup()
{
    // Kill active child processes
    wm_kill_children();

    // Delete PID file

    if (DeletePID(ARGV0) < 0) {
        mdebug1("Couldn't delete PID file.");
    }
}

// Action on signal

void wm_handler(int signum)
{
    wmodule * cur_module;
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        // For the moment only gracefull shutdown will be for syscollector, in the future
        // it will be modified for all wmodules, modifying the mainloop of each thread.
        for (cur_module = wmodules; cur_module && cur_module->context && cur_module->context->name; cur_module = cur_module->next) {
            if (cur_module->context->stop) {
                cur_module->context->stop(cur_module->data);
            }
        }
        exit(EXIT_SUCCESS);
    default:
        merror("unknown signal (%d)", signum);
    }
}
