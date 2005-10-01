/*   $OSSEC, root.c, v0.1, 2005/09/30, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
       
/*
 * Rootcheck v 0.3
 * Copyright (C) 2003 Daniel B. Cid <daniel@underlinux.com.br>
 * http://www.ossec.net/rootcheck/
 *
 */

/* Included from the Rootcheck project */


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
#include "rootcheck.h"

#ifndef ARGV0
#define ARGV0 "rootcheck"
#endif

#include "error_messages/error_messages.h"


int dbg_flag = 0;
int chroot_flag = 0;

/** Prototypes **/

/* Read the new XML config */
int Read_Rootcheck_Config(char * cfgfile, config *cfg);


/* main v0.1
 *
 */
int main(int argc, char **argv)
{
    int c;
    
    char *cfg = DEFAULTCPATH;
    
    /* Zeroing the structure */
    rootcheck.workdir = NULL;
    rootcheck.daemon = 1;
    rootcheck.notify = SYSLOG;
    
    while((c = getopt(argc, argv, "sdhD:c:")) != -1)
    {
        switch(c)
        {
            case 'h':
                help();
                break;
            case 'd':
                dbg_flag++;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                rootcheck.workdir = optarg;
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


    if(Read_Rootcheck_Config(cfg, &rootcheck) < 0)
        ErrorExit("%s: Error on the configuration file '%s'",ARGV0,cfg);


    /* Setting default values */
    if(rootcheck.workdir == NULL)
        rootcheck.workdir = DEFAULTDIR;


    
    /* Connect to the queue if configured to do so */
    if(rootcheck.notify == QUEUE)
    {
        debug1("%s: Starting queue ...",ARGV0);
        
        /* Starting the queue. */
        if((rootcheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {   
            merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH);
            
            /* 10 seconds to see if the agent starts */
            sleep(10);
            if((rootcheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
            {
                /* more 1 minute of wait.. */
                merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH);
                sleep(60);
                if((rootcheck.queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                    ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQPATH);
            }
        }
    }


    /* Start the signal handling */
    StartSIG(ARGV0);


    /* Forking */
    if(rootcheck.daemon)
    {
        pid_t pid;

        pid = fork();
        if(pid < 0)
            ErrorExit(FORK_ERROR,ARGV0);
        
        else if(pid == 0)
        {
            /* Create pid */
            if(CreatePID(ARGV0, getpid()) < 0)
                ErrorExit(PID_ERROR,ARGV0);
                
            /* Start the daemon */
            debug1("%s: DEBUG: Starting daemon", ARGV0);
            start_daemon();
        }
        
        else
        {
            /* Child is running now */
        }
    }
    
    /* Will only check the integrity once and exit */
    else
    {
        debug1("%s: DEBUG: Running run_check",ARGV0);
        run_check(); 
    }

   
    debug1("%s: DEBUG:  Leaving...",ARGV0); 

    return(0);        
}

/* EOF */
