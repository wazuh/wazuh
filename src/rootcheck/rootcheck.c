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

#ifdef OSSECHIDS
#include "headers/mq_op.h"
#endif

#include "headers/defs.h"
#include "headers/help.h"
#include "headers/debug_op.h"
#include "rootcheck.h"

#ifndef ARGV0
#define ARGV0 "rootcheck"
#endif

#include "error_messages/error_messages.h"


/** Prototypes **/
/* Read the new XML config */
int Read_Rootcheck_Config(char * cfgfile, rkconfig *cfg);


#ifndef OSSECHIDS

int dbg_flag = 0;
int chroot_flag = 0;


/* main v0.1
 *
 */
int main(int argc, char **argv)
{
    int c;

#else

int rootcheck_init()
{
    
#endif    
   
    #ifdef OSSECHIDS 
    char *cfg = DEFAULTCPATH;
    #else
    char *cfg = "./rootcheck.conf";
    #endif
    
    /* Zeroing the structure */
    rootcheck.workdir = NULL;
    rootcheck.daemon = 1;
    rootcheck.notify = SYSLOG;
    rootcheck.scanall = 0;


#ifndef OSSECHIDS
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
            case 's':
                rootcheck.scanall = 1;
                break;    
            default:
                help();
                break;   
        }

    }

#endif

    /* Staring message */
    debug1(STARTED_MSG,ARGV0);

    /* Checking if the configuration is present */
    if(File_DateofChange(cfg) < 0)
    {
        merror("%s: Configuration file '%s' not found",ARGV0,cfg);
        return(-1);
    }


    if(Read_Rootcheck_Config(cfg, &rootcheck) < 0)
    {
        return(-1);
    }


    /* Setting default values */
    if(rootcheck.workdir == NULL)
        rootcheck.workdir = DEFAULTDIR;


    #ifdef OSSECHIDS
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
    #endif

    #ifndef OSSECHIDS
    /* Start the signal handling */
    StartSIG(ARGV0);

    #else
    return(0);
        
    #endif

    
    debug1("%s: DEBUG: Running run_rk_check",ARGV0);
    run_rk_check(); 

   
    debug1("%s: DEBUG:  Leaving...",ARGV0); 

    return(0);        
}

/* EOF */
