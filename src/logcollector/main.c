/* @(#) $Id: ./src/logcollector/main.c, 2012/03/28 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.4 (2005/11/11): Some cleanup and bug fixes
 * v0.3 (2005/08/26): Reading all files in just one process
 * v0.2 (2005/04/04):
 */


/* Logcollector daemon.
 * Monitor some files and forward the output to our analysis system.
 */


#include <sys/types.h>
#include <sys/time.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "os_regex/os_regex.h"

#include "logcollector.h"



/* main: v0.3: 2005/04/04 */
int main(int argc, char **argv)
{
    int c;
    int debug_level = 0;
    int test_config = 0,run_foreground = 0;
    int accept_manager_commands = 0;
    char *cfg = DEFAULTCPATH;
    // TODO: delete or implement
    char *dir __attribute__((unused)) = DEFAULTDIR;


    /* Setuping up random */
    #ifndef WIN32
        #ifdef __OpenBSD__
        srandomdev();
        #else
        srandom(time(0));
        #endif
    #else
    srandom(time(0))
    #endif

    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "VtdhfD:c:")) != -1)
    {
        switch(c)
        {
            case 'V':
                print_version();
                break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                debug_level = 1;
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help(ARGV0);
                break;
        }

    }

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0)
    {
        /* Getting debug level */
        debug_level = getDefine_Int("logcollector", "debug", 0, 2);
        while(debug_level != 0)
        {
            nowDebug();
            debug_level--;
        }
    }


    debug1(STARTED_MSG,ARGV0);


    accept_manager_commands = getDefine_Int("logcollector", "remote_commands",
                                       0, 1);


    /* Reading config file */
    if(LogCollectorConfig(cfg, accept_manager_commands) < 0)
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);


    /* Getting loop timeout */
    loop_timeout = getDefine_Int("logcollector",
                                 "loop_timeout",
                                 1, 120);

    open_file_attempts = getDefine_Int("logcollector", "open_attempts",
                                       2, 998);

    accept_manager_commands = getDefine_Int("logcollector", "remote_commands",
                                       0, 1);


    /* Exit if test config */
    if(test_config)
        exit(0);


    /* No file available to monitor -- continue */
    if(logff == NULL)
    {
        os_calloc(2, sizeof(logreader), logff);
        logff[0].file = NULL;
        logff[0].ffile = NULL;
        logff[0].logformat = NULL;
        logff[0].fp = NULL;
        logff[1].file = NULL;
        logff[1].logformat = NULL;

        merror(NO_FILE, ARGV0);
    }


    /* Starting signal handler */
    StartSIG(ARGV0);


    if (!run_foreground)
    {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }


    /* Creating PID file */
    if(CreatePID(ARGV0, getpid()) < 0)
        merror(PID_ERROR, ARGV0);



    /* Waiting 6 seconds for the analysisd/agentd to settle */
    debug1("%s: DEBUG: Waiting main daemons to settle.", ARGV0);
    sleep(6);


    /* Starting the queue. */
    if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);


    /* Main loop */
    LogCollectorStart();


    return(0);
}



/* EOF */
