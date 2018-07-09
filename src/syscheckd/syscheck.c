/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Syscheck
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 */

#include "shared.h"
#include "syscheck.h"
#include "rootcheck/rootcheck.h"

// Global variables
syscheck_config syscheck;
pthread_cond_t audit_thread_started;

#ifdef USE_MAGIC
#include <magic.h>
magic_t magic_cookie = 0;


void init_magic(magic_t *cookie_ptr)
{
    if (!cookie_ptr || *cookie_ptr) {
        return;
    }

    *cookie_ptr = magic_open(MAGIC_MIME_TYPE);

    if (!*cookie_ptr) {
        const char *err = magic_error(*cookie_ptr);
        merror("Can't init libmagic: %s", err ? err : "unknown");
    } else if (magic_load(*cookie_ptr, NULL) < 0) {
        const char *err = magic_error(*cookie_ptr);
        merror("Can't load magic file: %s", err ? err : "unknown");
        magic_close(*cookie_ptr);
        *cookie_ptr = 0;
    }
}
#endif /* USE_MAGIC */

/* Read syscheck internal options */
static void read_internal(int debug_level)
{
    syscheck.tsleep = (unsigned int) getDefine_Int("syscheck", "sleep", 0, 64);
    syscheck.sleep_after = getDefine_Int("syscheck", "sleep_after", 1, 9999);
    syscheck.rt_delay = getDefine_Int("syscheck", "rt_delay", 1, 1000);
#ifndef WIN32
    syscheck.max_audit_entries = getDefine_Int("syscheck", "max_audit_entries", 256, 4096);
#endif

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0) {
        debug_level = getDefine_Int("syscheck", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    return;
}

/* Initialize syscheck variables */
int fim_initilize() {

    /* Create store data */
    syscheck.fp = OSHash_Create();
    syscheck.local_hash = OSHash_Create();

    /* Duplicate hash table to check for deleted files */
    syscheck.last_check = OSHash_Duplicate(syscheck.fp);

    return 0;
}


#ifdef WIN32
/* syscheck main for Windows */
int Start_win32_Syscheck()
{
    int debug_level = 0;
    int r = 0;
    char *cfg = DEFAULTCPATH;
    /* Read internal options */
    read_internal(debug_level);

    mdebug1(STARTED_MSG);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit(NO_CONFIG, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        /* Disabled */
        if (!syscheck.dir) {
            minfo(SK_NO_DIR);
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL);
        } else if (!syscheck.dir[0]) {
            minfo(SK_NO_DIR);
        }

        syscheck.dir[0] = NULL;

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            syscheck.ignore[0] = NULL;
        }

        if (!syscheck.registry) {
            dump_syscheck_entry(&syscheck, "", 0, 1, NULL);
        }
        syscheck.registry[0].entry = NULL;

        minfo("Syscheck disabled.");
    }

    /* Rootcheck config */
    if (rootcheck_init(0) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
    }

    if (!syscheck.disabled) {

        /* Print options */
        r = 0;
        while (syscheck.registry[r].entry != NULL) {
            minfo("Monitoring registry entry: '%s%s'.", syscheck.registry[r].entry, syscheck.registry[r].arch == ARCH_64BIT ? " [x64]" : "");
            r++;
        }

        /* Print directories to be monitored */
        r = 0;
        while (syscheck.dir[r] != NULL) {
            char optstr[ 1024 ];
            minfo("Monitoring directory: '%s', with options %s.", syscheck.dir[r], syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));
            r++;
        }

        /* Print ignores. */
        if(syscheck.ignore)
            for (r = 0; syscheck.ignore[r] != NULL; r++)
                minfo("Ignoring: '%s'", syscheck.ignore[r]);

        /* Print files with no diff. */
        if (syscheck.nodiff){
            r = 0;
            while (syscheck.nodiff[r] != NULL) {
                minfo("No diff for file: '%s'", syscheck.nodiff[r]);
                r++;
            }
        }

        /* Start up message */
        minfo(STARTUP_MSG, getpid());
    }

    /* Some sync time */
    sleep(syscheck.tsleep * 5);

    /* Wait if agent started properly */
    os_wait();

    start_daemon();

    exit(0);
}
#endif /* WIN32 */

#ifndef WIN32

/* Print help statement */
__attribute__((noreturn)) static void help_syscheckd()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out(" ");
    exit(1);
}

/* Syscheck unix main */
int main(int argc, char **argv)
{
    int c, r;
    int debug_level = 0;
    int test_config = 0, run_foreground = 0;
    const char *cfg = DEFAULTCPATH;
    audit_thread_active = 0;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vtdhfc:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_syscheckd();
                break;
            case 'd':
                nowDebug();
                debug_level ++;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_syscheckd();
                break;
        }
    }

    /* Read internal options */
    read_internal(debug_level);

    mdebug1(STARTED_MSG);

    /* Check if the configuration is present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit(NO_CONFIG, cfg);
    }

    /* Read syscheck config */
    if ((r = Read_Syscheck_Config(cfg)) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    } else if ((r == 1) || (syscheck.disabled == 1)) {
        if (!syscheck.dir) {
            if (!test_config) {
                minfo(SK_NO_DIR);
            }
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL);
        } else if (!syscheck.dir[0]) {
            if (!test_config) {
                minfo(SK_NO_DIR);
            }
        }

        syscheck.dir[0] = NULL;

        if (!syscheck.ignore) {
            os_calloc(1, sizeof(char *), syscheck.ignore);
        } else {
            syscheck.ignore[0] = NULL;
        }

        if (!test_config) {
            minfo("Syscheck disabled.");
        }
    }

    /* Rootcheck config */
    if (rootcheck_init(test_config) == 0) {
        syscheck.rootcheck = 1;
    } else {
        syscheck.rootcheck = 0;
    }

    /* Exit if testing config */
    if (test_config) {
        exit(0);
    }

    /* Setup libmagic */
#ifdef USE_MAGIC
    init_magic(&magic_cookie);
#endif

    if (!run_foreground) {
        nowDaemon();
        goDaemon();
    }

    /* Start signal handling */
    StartSIG(ARGV0);

    /* Create pid */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    if (syscheck.rootcheck) {
        rootcheck_connect();
    }

    /* Initial time to settle */
    sleep(syscheck.tsleep + 2);

    /* Connect to the queue */
    if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
        merror(QUEUE_ERROR, DEFAULTQPATH, strerror(errno));

        sleep(5);
        if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
            /* more 10 seconds of wait */
            merror(QUEUE_ERROR, DEFAULTQPATH, strerror(errno));
            sleep(10);
            if ((syscheck.queue = StartMQ(DEFAULTQPATH, WRITE)) < 0) {
                merror_exit(QUEUE_FATAL, DEFAULTQPATH);
            }
        }
    }

    if (!syscheck.disabled) {

        /* Start up message */
        minfo(STARTUP_MSG, (int)getpid());

        /* Print directories to be monitored */
        r = 0;
        while (syscheck.dir[r] != NULL) {
            char optstr[ 1024 ];
            minfo("Monitoring directory: '%s', with options %s.", syscheck.dir[r], syscheck_opts2str(optstr, sizeof( optstr ), syscheck.opts[r]));
            r++;
        }

        /* Print ignores. */
        if(syscheck.ignore)
            for (r = 0; syscheck.ignore[r] != NULL; r++)
                minfo("Ignoring: '%s'", syscheck.ignore[r]);

        /* Print files with no diff. */
        if (syscheck.nodiff){
            r = 0;
            while (syscheck.nodiff[r] != NULL) {
                minfo("No diff for file: '%s'", syscheck.nodiff[r]);
                r++;
            }
        }

        /* Check directories set for real time */
        r = 0;
        while (syscheck.dir[r] != NULL) {
            if (syscheck.opts[r] & CHECK_REALTIME) {
  #ifdef INOTIFY_ENABLED
                minfo("Directory set for real time monitoring: '%s'.", syscheck.dir[r]);
  #elif defined(WIN32)
                minfo("Directory set for real time monitoring: '%s'.", syscheck.dir[r]);
  #else
                mwarn("Ignoring flag for real time monitoring on directory: '%s'.", syscheck.dir[r]);
  #endif
            }
            r++;
        }
    }

    if (syscheck.rootcheck) {
        mtinfo("rootcheck", STARTUP_MSG, (int)getpid());
    }

    /* Some sync time */
    sleep(syscheck.tsleep * 5);
    fim_initilize();

    // Audit events thread
    if (syscheck.enable_whodata) {
        int out = audit_init();
        if (out < 0)
            mwarn("Audit events reader thread not started.");
    }

    /* Start the daemon */
    start_daemon();
}

#endif /* !WIN32 */
