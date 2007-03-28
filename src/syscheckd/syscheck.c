/* @(#) $Id$ */

/* Copyright (C) 2003-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
/*
 * Syscheck v 0.3
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 * http://www.ossec.net/syscheck/
 *
 * syscheck.c, 2004/03/17, Daniel B. Cid
 */

/* Inclusion of syscheck into OSSEC */


#include "shared.h"
#include "syscheck.h"

#include "rootcheck/rootcheck.h"


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
    else if(r == 1)
    {
        merror("%s: Syscheck disabled.", ARGV0);
        return(0);
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
        merror("%s: Rootcheck module disabled.", ARGV0);
    }
                                                            


    /* Opening syscheck db file */
    syscheck.db = (char *)calloc(1024,sizeof(char));
    if(syscheck.db == NULL)
        ErrorExit(MEM_ERROR,ARGV0);

    snprintf(syscheck.db,1023,"%s",SYS_WIN_DB);


    /* Printing options */
    r = 0;
    while(syscheck.registry[r] != NULL)
    {
        verbose("%s: Monitoring registry entry: '%s'.", 
                ARGV0, syscheck.registry[r]);
        r++;
    }
    
    r = 0;
    while(syscheck.dir[r] != NULL)
    {
        verbose("%s: Monitoring directory: '%s'.",
                ARGV0, syscheck.dir[r]);
        r++;
    }
        
        
    /* Will create the db to store syscheck data */
    create_db();
    fflush(syscheck.fp);


    /* Some sync time */
    sleep(syscheck.tsleep);


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
                help();
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
                help();
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
    else if(r == 1)
    {
        if(!test_config)
        {
            merror("%s: Syscheck disabled. Exiting.", ARGV0);
        }
        exit(0);
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
        merror("%s: Rootcheck module disabled.", ARGV0);
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
