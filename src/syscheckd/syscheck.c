/* @(#) $Id: ./src/syscheckd/syscheck.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


/*
 * Syscheck v 0.3
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 * http://www.ossec.net
 *
 * syscheck.c, 2004/03/17, Daniel B. Cid
 */

/* Inclusion of syscheck into OSSEC */


#include "shared.h"
#include "syscheck.h"

#include "rootcheck/rootcheck.h"

int dump_syscheck_entry(syscheck_config *syscheck, const char *entry, int vals, int reg, const char *restrictfile);

#ifdef USE_MAGIC
#include <magic.h>
magic_t magic_cookie = 0;

void init_magic(magic_t* cookie_ptr)
{
    if(!cookie_ptr || *cookie_ptr) return;

    *cookie_ptr = magic_open(MAGIC_MIME_TYPE);

    if(!*cookie_ptr)
    {
        const char* err = magic_error(*cookie_ptr);
        merror("%s: ERROR: Can't init libmagic: %s", ARGV0, err ? err : "unknown");
    }
    else if(magic_load(*cookie_ptr, NULL) < 0)
    {
        const char* err = magic_error(*cookie_ptr);
        merror("%s: ERROR: Can't load magic file: %s", ARGV0, err ? err : "unknown");
        magic_close(*cookie_ptr);
        *cookie_ptr = 0;
    }
}
#endif


/* void read_internal()
 * Reads syscheck internal options.
 */
void read_internal(int debug_level)
{
    syscheck.tsleep = getDefine_Int("syscheck","sleep",0,64);
    syscheck.sleep_after = getDefine_Int("syscheck","sleep_after",1,9999);

    /* Check current debug_level
     * Command line setting takes precedence
     */
    if (debug_level == 0)
    {
        /* Getting debug level */
        debug_level = getDefine_Int("syscheck", "debug", 0, 2);
        while(debug_level != 0)
        {
            nowDebug();
            debug_level--;
        }
    }

    return;
}


#ifdef WIN32
/* int Start_win32_Syscheck()
 * syscheck main for windows
 */
int Start_win32_Syscheck()
{
    int debug_level = 0;
    int r = 0;
    char *cfg = DEFAULTCPATH;


    /* Reading internal options */
    read_internal(debug_level);


    debug1(STARTED_MSG, ARGV0);


    /* Zeroing the structure */
    syscheck.workdir = DEFAULTDIR;


    /* Checking if the configuration is present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit(NO_CONFIG, ARGV0, cfg);


    /* Read syscheck config */
    if((r = Read_Syscheck_Config(cfg)) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }
    /* Disabled */
    else if((r == 1) || (syscheck.disabled == 1))
    {
        if(!syscheck.dir)
        {
            merror(SK_NO_DIR, ARGV0);
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL);
        }
        else if(!syscheck.dir[0])
        {
            merror(SK_NO_DIR, ARGV0);
        }
        syscheck.dir[0] = NULL;

        if(!syscheck.registry)
        {
            dump_syscheck_entry(&syscheck, "", 0, 1, NULL);
        }
        syscheck.registry[0] = NULL;

        merror("%s: WARN: Syscheck disabled.", ARGV0);
    }


    /* Rootcheck config */
    if(rootcheck_init(0) == 0)
    {
        syscheck.rootcheck = 1;
    }
    else
    {
        syscheck.rootcheck = 0;
        merror("%s: WARN: Rootcheck module disabled.", ARGV0);
    }



    /* Printing options */
    r = 0;
    while(syscheck.registry[r] != NULL)
    {
        verbose("%s: INFO: Monitoring registry entry: '%s'.",
                ARGV0, syscheck.registry[r]);
        r++;
    }

    r = 0;
    while(syscheck.dir[r] != NULL)
    {
        verbose("%s: INFO: Monitoring directory: '%s'.",
                ARGV0, syscheck.dir[r]);
        r++;
    }


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());



    /* Some sync time */
    sleep(syscheck.tsleep + 10);


    /* Waiting if agent started properly. */
    os_wait();


    start_daemon();


    exit(0);
}
#endif



/* Syscheck unix main.
 */
#ifndef WIN32
int main(int argc, char **argv)
{
    int c,r;
    int debug_level = 0;
    int test_config = 0,run_foreground = 0;

    char *cfg = DEFAULTCPATH;


    /* Zeroing the structure */
    syscheck.workdir = NULL;


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
                syscheck.workdir = optarg;
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


    /* Reading internal options */
    read_internal(debug_level);


    debug1(STARTED_MSG, ARGV0);


    /* Checking if the configuration is present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit(NO_CONFIG, ARGV0, cfg);


    /* Read syscheck config */
    if((r = Read_Syscheck_Config(cfg)) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }
    else if((r == 1) || (syscheck.disabled == 1))
    {
        if(!syscheck.dir)
        {
            if(!test_config)
                merror(SK_NO_DIR, ARGV0);
            dump_syscheck_entry(&syscheck, "", 0, 0, NULL);
        }
        else if(!syscheck.dir[0])
        {
            if(!test_config)
                merror(SK_NO_DIR, ARGV0);
        }
        syscheck.dir[0] = NULL;
        if(!test_config)
        {
            merror("%s: WARN: Syscheck disabled.", ARGV0);
        }
    }


    /* Rootcheck config */
    if(rootcheck_init(test_config) == 0)
    {
        syscheck.rootcheck = 1;
    }
    else
    {
        syscheck.rootcheck = 0;
        merror("%s: WARN: Rootcheck module disabled.", ARGV0);
    }


    /* Exit if testing config */
    if(test_config)
        exit(0);


    /* Setting default values */
    if(syscheck.workdir == NULL)
        syscheck.workdir = DEFAULTDIR;


    /* Setup libmagic */
    #ifdef USE_MAGIC
    init_magic(&magic_cookie);
    #endif


    if(!run_foreground)
    {
        nowDaemon();
        goDaemon();
    }

    /* Initial time to settle */
    sleep(syscheck.tsleep + 2);


    /* Connect to the queue  */
    if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
    {
        merror(QUEUE_ERROR, ARGV0, DEFAULTQPATH, strerror(errno));

        sleep(5);
        if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            /* more 10 seconds of wait.. */
            merror(QUEUE_ERROR, ARGV0, DEFAULTQPATH, strerror(errno));
            sleep(10);
            if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQPATH);
        }
    }


    /* Start the signal handling */
    StartSIG(ARGV0);


    /* Creating pid */
    if(CreatePID(ARGV0, getpid()) < 0)
        merror(PID_ERROR,ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

    if(syscheck.rootcheck)
    {
        verbose(STARTUP_MSG, "ossec-rootcheck", (int)getpid());
    }


    /* Printing directories to be monitored. */
    r = 0;
    while(syscheck.dir[r] != NULL)
    {
        verbose("%s: INFO: Monitoring directory: '%s'.",
                ARGV0, syscheck.dir[r]);
        r++;
    }

    /* Checking directories set for real time. */
    r = 0;
    while(syscheck.dir[r] != NULL)
    {
        if(syscheck.opts[r] & CHECK_REALTIME)
        {
            #ifdef USEINOTIFY
            verbose("%s: INFO: Directory set for real time monitoring: "
                    "'%s'.", ARGV0, syscheck.dir[r]);
            #elif WIN32
            verbose("%s: INFO: Directory set for real time monitoring: "
                    "'%s'.", ARGV0, syscheck.dir[r]);
            #else
            verbose("%s: WARN: Ignoring flag for real time monitoring on "
                    "directory: '%s'.", ARGV0, syscheck.dir[r]);
            #endif
        }
        r++;
    }


    /* Some sync time */
    sleep(syscheck.tsleep + 10);


    /* Start the daemon */
    start_daemon();

    return(0);
}
#endif /* ifndef WIN32 */


/* EOF */
