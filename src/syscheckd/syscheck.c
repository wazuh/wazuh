/* @(#) $Id$ */

/* Copyright (C) 2003-2008 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
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

/* Definitions only used in here. */
#define SYSCHECK_DB     SYSCHECK_DIR "/syschecklocal.db"
#define SYS_WIN_DB      "syscheck/syschecklocal.db"



/* void read_internal()
 * Reads syscheck internal options.
 */
void read_internal()
{
    syscheck.tsleep = getDefine_Int("syscheck","sleep",1,64);
    syscheck.sleep_after = getDefine_Int("syscheck","sleep_after",1,128);

    return;
}


#ifdef WIN32
/* int Start_win32_Syscheck()
 * syscheck main for windows
 */
int Start_win32_Syscheck()
{
    int r = 0;
    char *cfg = DEFAULTCPATH;


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
        syscheck.dir[0] = NULL;
        syscheck.registry[0] = NULL;
        merror("%s: WARN: Syscheck disabled.", ARGV0);
    }


    /* Reading internal options */
    read_internal();


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
                                                            


    /* Opening syscheck db file */
    os_calloc(1024,sizeof(char), syscheck.db);
    snprintf(syscheck.db,1023,"%s",SYS_WIN_DB);


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
            
        
        
    /* Will create the db to store syscheck data */
    sleep(syscheck.tsleep +2);
    create_db();
    fflush(syscheck.fp);


    /* Some sync time */
    sleep(syscheck.tsleep +2);


    /* Waiting if agent started properly. */
    os_wait();

    
    /* Start the daemon checking against the syscheck.db */
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
    int test_config = 0;
    
    char *cfg = DEFAULTCPATH;
    
    
    /* Zeroing the structure */
    syscheck.workdir = NULL;


    /* Setting the name */
    OS_SetName(ARGV0);
        
    
    while((c = getopt(argc, argv, "VtdhD:c:")) != -1)
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
        syscheck.dir[0] = NULL;
        if(!test_config)
        {
            merror("%s: WARN: Syscheck disabled.", ARGV0);
        }
    }


    /* Reading internal options */
    read_internal();
        
    

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


    /* Creating a temporary fp */
    syscheck.db = (char *)calloc(1024,sizeof(char));
    if(syscheck.db == NULL)
        ErrorExit(MEM_ERROR,ARGV0);
        
    snprintf(syscheck.db,1023,"%s%s-%d%d.tmp",
                              syscheck.workdir,
                              SYSCHECK_DB,
                              (int)time(NULL),
                              (int)getpid());    



    /* Setting daemon flag */
    nowDaemon();


    /* Entering in daemon mode now */
    goDaemon();

   
    /* Initial time to settle */
    sleep(syscheck.tsleep); 
    
    
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
    verbose(STARTUP_MSG, ARGV0, getpid());

    if(syscheck.rootcheck)
    {
        verbose(STARTUP_MSG, "ossec-rootcheck", getpid());
    }
        
    
    /* Create local database */
    create_db();    
    

    fflush(syscheck.fp);

    /* Some sync time */
    sleep(syscheck.tsleep);


    /* Start the daemon */
    start_daemon();

    return(0);        
}
#endif /* ifndef WIN32 */


/* EOF */
