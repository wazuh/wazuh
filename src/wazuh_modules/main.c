/*
 * Wazuh Module Manager
 * Wazuh Inc.
 * April 22, 2016
 */

#include "wmodules.h"

static void wm_help();                  // Print help.
static void wm_setup();                 // Setup function. Exits on error.
static void wm_cleanup();               // Cleanup function, called on exiting.
static void wm_handler(int signum);     // Action on signal.

static int flag_foreground = 0;         // Running in foreground.

// Main function

int main(int argc, char **argv)
{
    int c;
    int debug = 0;
    int test_config = 0;
    wmodule *cur_module;
    pthread_attr_t attr;

    // Get command line options

    while ((c = getopt(argc, argv, "dfht")) != -1) {
        switch (c) {
        case 'd':
            nowDebug();
            debug = 1;
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

    if (debug == 0) {
        debug = getDefine_Int("wazuh_modules", "debug", 0, 2);

        while (debug != 0) {
            nowDebug();
            debug--;
        }
    }

    // Setup daemon

    wm_setup();

    if (test_config)
        exit(EXIT_SUCCESS);

    verbose("%s: INFO: Process started.", ARGV0);

    // Run modules

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        int error = pthread_create(&cur_module->thread, &attr, cur_module->context->start, cur_module->data);

        if (error)
            ErrorExit("%s: ERROR: fork(): %s", ARGV0, strerror(error));
    }

    pthread_attr_destroy(&attr);
    pthread_exit(NULL);
    return EXIT_SUCCESS;
}

// Print help

void wm_help()
{
    print_out("Wazuh Module Manager - %s\nWazuh Inc.", __wazuh_version);
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
    int modules = CWMODULE;

    // Read configuration: ossec.conf
    if (ReadConfig(CWMODULE, DEFAULTCPATH, &wmodules, NULL) < 0)
        exit(EXIT_FAILURE);

#ifdef CLIENT
    /* Read shared config */
    modules |= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, &wmodules, NULL);
#endif

    wm_check();

    // Go daemon

    if (!flag_foreground) {
        goDaemon();
        nowDaemon();
    }

    // Create PID file

    if (CreatePID(ARGV0, getpid()) < 0)
        merror("%s: ERROR: Couldn't create PID file: (%s)", ARGV0, strerror(errno));

    // Signal management

    atexit(wm_cleanup);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);

    if (flag_foreground) {
        sigaction(SIGHUP, &action, NULL);
        sigaction(SIGINT, &action, NULL);
    }
}

// Cleanup function, called on exiting.

void wm_cleanup()
{
    // Delete PID file

    if (DeletePID(ARGV0) < 0)
        merror("%s: ERROR: Couldn't delete PID file.", ARGV0);
}

// Action on signal

void wm_handler(int signum)
{
    switch (signum) {
    case SIGHUP:
    case SIGINT:
    case SIGTERM:
        exit(EXIT_SUCCESS);
    case SIGUSR1:
        wm_flag_reload = 1;
        break;
    default:
        merror("%s: ERROR: unknown signal (%d)", ARGV0, signum);
    }
}
