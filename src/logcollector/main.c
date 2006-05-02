/*   $OSSEC, main.c, v0.4, 2005/11/11, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
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


/* Logcolletor daemon.
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
    int test_config = 0;
    char *cfg = DEFAULTCPATH;
    char *dir = DEFAULTDIR;


    /* Setting the name */
    OS_SetName(ARGV0);
        

    while((c = getopt(argc, argv, "tdhD:c:")) != -1)
    {
        switch(c)
        {
            case 'h':
                help();
                break;
            case 'd':
                nowDebug();
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
                help();
                break;   
        }

    }

    debug1(STARTED_MSG,ARGV0);


    /* Reading config file */
    if(LogCollectorConfig(cfg) < 0)
        ErrorExit(CONFIG_ERROR,ARGV0,cfg);
    

    if(logff[0].file == NULL)
        ErrorExit(NO_FILE, ARGV0);
            

    /* Exit if test config */
    if(test_config)
        exit(0);
        

    /* Starting signal handler */
    StartSIG(ARGV0);	


    /* Going on daemon mode */
    nowDaemon();
    goDaemon();


    /* Creating PID file */
    if(CreatePID(ARGV0, getpid()) < 0)
        merror(PID_ERROR, ARGV0);

   
   
    /* Waiting 6 seconds for the analysisd/agentd to settle */
    sleep(6);
    
     
    /* Starting the queue. */
    if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        ErrorExit(QUEUE_FATAL, ARGV0, DEFAULTQPATH);


    /* Main loop */        
    LogCollectorStart();
    

    return(0);
}



/* EOF */
