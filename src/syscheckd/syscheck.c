/*   $OSSEC, syscheck.c, v0.5, 2005/05/30, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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

/* Inclusion of the syscheck into the OSSEC HIDS system */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>
#include <time.h>

#include "headers/sig_op.h"
#include "headers/file_op.h"
#include "headers/mq_op.h"
#include "headers/defs.h"
#include "headers/help.h"
#include "headers/debug_op.h"
#include "syscheck.h"

#ifdef OSSECHIDS
#include "rootcheck/rootcheck.h"
#endif

#include "error_messages/error_messages.h"

/** Prototypes **/

/* Read the new XML config */
int Read_Syscheck_Config(char * cfgfile, config *cfg);
/* create the database */
int create_db();


/* main v0.3
 *
 */
int main(int argc, char **argv)
{
    int init = 0, c;
    
    char *cfg = DEFAULTCPATH;
    
    /* Zeroing the structure */
    syscheck.workdir = NULL;
    syscheck.dir = NULL;
    syscheck.daemon = 1;
    syscheck.notify = SYSLOG;
    
    while((c = getopt(argc, argv, "sdhD:c:")) != -1)
    {
        switch(c)
        {
            case 's':
                init = 1;
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
            default:
                help();
                break;   
        }

    }

    /* Staring message */
    debug1(STARTED_MSG,ARGV0);

    /* Checking if the configuration is present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit("%s: Configuration file: %s not found",ARGV0,cfg);


    if(Read_Syscheck_Config(cfg, &syscheck) < 0)
    {
        ErrorExit("%s: Error on the configuration file '%s'",ARGV0,cfg);
    }

    /* Setting default values */
    if(syscheck.workdir == NULL)
        syscheck.workdir = DEFAULTDIR;


    /* Creating a temporary fp */
    if((init == 0)&&(syscheck.notify == QUEUE))
    {
        time_t tmp_time;
        pid_t tmp_pid;

        tmp_time = time(NULL);
        tmp_pid = getpid();
        
        syscheck.db = (char *)calloc(1024,sizeof(char));
        if(syscheck.db == NULL)
            ErrorExit(MEM_ERROR,ARGV0);
        
        snprintf(syscheck.db,1023,"%s%s/%s-%d%d.tmp",
                                  syscheck.workdir,
                                  CHECKSUM_DIR,
                                  "syscheck-db",
                                  (int)tmp_time,
                                  (int)tmp_pid);    
    }

    else
    {
        /* setting db directory */
        syscheck.db = (char *)calloc(1024, sizeof(char));

        if(syscheck.db == NULL)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        snprintf(syscheck.db, 1024, "%s%s",syscheck.workdir,SYSCHECK_DB);
    }

    
    /* Going on daemon mode */
    if(syscheck.daemon)
    {

        /* Setting daemon flag */
        nowDaemon();

        /* Entering in daemon mode now */
        goDaemon();
    }
    
    
    /* Connect to the queue if configured to do so */
    if(syscheck.notify == QUEUE)
    {
        sleep(3);

        /* Starting the queue. */
        if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {   
            merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH);
            
            /* 5 seconds to see if the agent starts */
            sleep(5);
            if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
            {
                /* more 10 seconds of wait.. */
                merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH);
                sleep(10);
                if((syscheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                    ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQPATH);
            }
        }
    }

    /* Start the signal handling */
    StartSIG(ARGV0);

    /* Lets create the database */
    if(init == 1)
    {
        verbose("%s: Creating new database for integrity check",ARGV0);
        create_db();
        exit(0);
    }
   
    /* When using the queue, we always create the database */
    if(syscheck.notify == QUEUE)
    {
        /* Starting rootcheck */
        #ifdef OSSECHIDS
        if(rootcheck_init() == 0)
            syscheck.rootcheck = 1;
        #endif
            
    }
  
    /* If syslog is set, just read the database */ 
    else if(syscheck.notify == SYSLOG)
    {
        syscheck.fp = fopen(syscheck.db,"r");
        if(!syscheck.fp)
        {
            merror("%s: Did you create the syscheck database ?",ARGV0);
            ErrorExit("%s: Unable to create syscheck database "
                  "at '%s/%s'. Exiting..",ARGV0,syscheck.workdir,SYSCHECK_DB);
            return(0);    
        }
    }

    else
    {
        ErrorExit("%s: Invalid notification type.",ARGV0);
    }
    


    /* Going on daemon mode */
    if(syscheck.daemon)
    {

        /* Creating pid */
        if(CreatePID(ARGV0, getpid()) < 0)
            merror(PID_ERROR,ARGV0);


        /* When on QUEUE, we need to create the database every time */
        if(syscheck.notify == QUEUE)
        {
            /* Will create the temp db to store in a file pointer */
            create_db();

            fflush(syscheck.fp);

            /* Some sync time */
            sleep(1);
        }

        /* Start the daemon checking against the syscheck.db */
        start_daemon();

    }
    
    /* Will only check the integrity once and exit */
    else
    {
        run_check(); 
    }
    

    debug1("%s: Leaving main process.", ARGV0);
    return(0);        
}

/* EOF */
