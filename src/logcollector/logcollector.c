/*   $OSSEC, logcollector.c, v0.3, 2005/08/26, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* v0.3 (2005/08/26): Reading all files in just one process 
 * v0.2 (2005/04/04):
 */  

/* Logcolletor daemon.
 * Monitor some files and forward the output to our analysis system.
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#ifndef ARGV0
   #define ARGV0="ossec-logcollector"
#endif
      
#include "headers/defs.h"
#include "headers/mq_op.h"
#include "headers/sig_op.h"
#include "headers/file_op.h"
#include "headers/debug_op.h"
#include "headers/help.h"
#include "headers/privsep_op.h"
#include "headers/os_err.h"
#include "os_regex/os_regex.h"

#include "error_messages/error_messages.h"

#include "logcollector.h"


/* External use dbg ahd chroot flags */
short int dbg_flag=0;
short int chroot_flag=0;



/* Internal functions */
int FilesConf(char * cfgfile);
void run();
int handle_file(int i);
int read_snortfull(int pos);
int read_syslog(int pos);


/* main: v0.3: 2005/04/04 */
int main(int argc, char **argv)
{
    int c;
    char *cfg=DEFAULTCPATH;
    char *dir=DEFAULTDIR;

    while((c = getopt(argc, argv, "dhD:c:")) != -1)
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
                dir = optarg;
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

    debug1(STARTED_MSG,ARGV0);

    /* Configuration file not present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit("%s: Configuration file '%s' not found",ARGV0,cfg);

    /* Reading config file */
    if((c = FilesConf(cfg)) == OS_NOTFOUND)
    {
        verbose("%s: No file configured to monitor. Exiting...",ARGV0);
        exit(0);
    }
    else if(c < 0)
        ErrorExit(CONFIG_ERROR,ARGV0,cfg);

    #ifdef DEBUG
        verbose("%s: Going to read files and fork..",ARGV0);
    #endif

    
    /* Starting the queue. */
    if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
    {   
        merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH);
        sleep(10);
        if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
        {
            merror(QUEUE_ERROR,ARGV0,DEFAULTQPATH);
            sleep(60);
            if((logr_queue = StartMQ(DEFAULTQPATH,WRITE)) < 0)
                ErrorExit(QUEUE_FATAL,ARGV0,DEFAULTQPATH);
        }
    }

    /* Starting signal handler */
    StartSIG(ARGV0);	

    /* Forking .. */
    {
        int pid = 0;
        pid = fork();

        if(pid < 0)
            ErrorExit(FORK_ERROR,ARGV0);

        else if(pid == 0)
        {
            #ifdef DEBUG
            verbose("%s: New process %d ..",ARGV0,getpid());
            #endif

            /* Creating Pid file */
            if(CreatePID(ARGV0, getpid()) < 0)
                ErrorExit(PID_ERROR,ARGV0);
            
            run();
            
            return(0);    
        }
        else
        {
            exit(0);
        }
    }

    /* Exiting from the main process  -- shouldn't reach here any way*/
    exit(0);
}


/* run: Process the file and forward their content to analysd/agentd */
void run()
{
    int i = 0, r = 0;
    int max_file = 0;
    int f_check = 0;
    int tmtmp = 0;
    
    struct timeval fp_timeout;

    /* Initializing each file and structure */
    for(i = 0;;i++)
    {
        if(logr[i].file == NULL)
            break;
        
        max_file++;
        
        /* Initiating the files */    
        handle_file(i);
        
        
        /* Getting the log type */
        logr[i].type = LOCALFILE_MQ; 
        if(OS_Match("snort-full", logr[i].group))
        {
            logr[i].type = SNORT_MQ_FULL;
        }
        else if(OS_Match("snort-fast", logr[i].group))
        {
            logr[i].type = SNORT_MQ_FAST;
        }
        else if(OS_Match("apache-err", logr[i].group))
        {
            logr[i].type = APACHERR_MQ;
        }
    }

    
    /* Daemon loop */
    while(1)
    {
        fp_timeout.tv_sec = FP_TIMEOUT;
        fp_timeout.tv_usec = 0;

        /* Waiting for the select timeout */ 
        if ((r = select(0, NULL, NULL, NULL, &fp_timeout)) < 0)
        {
            merror("%s: Internal error (select).",ARGV0);
            continue;
        }

        f_check++;

        /* Checking which file is available */
        for(i = 0; i <= max_file; i++)
        {
            if(!logr[i].file)
                break;
            if(!logr[i].fp)
                continue;

            tmtmp = File_DateofChange(logr[i].file);
            if(tmtmp != logr[i].mtime)
            {
                /* Reading file */
                if(logr[i].type == SNORT_MQ_FULL)
                {
                    r = read_snortfull(i);
                }
                else
                {
                    r = read_syslog(i);
                }

                /* Checking read ret code */
                if(r == 0 && feof(logr[i].fp))
                {
                    /* Clearing EOF */
                    clearerr(logr[i].fp);

                    /* Updating mtime */
                    logr[i].mtime = File_DateofChange(logr[i].file);

                    logr[i].ign = 0;
                }
                
                else
                {
                    merror("%s: File error: '%s'",ARGV0,logr[i].file);
                    
                    if(fseek(logr[i].fp,0,SEEK_END) < 0)
                    {
                        merror("%s: File error (fseek): '%s'",ARGV0,logr[i].file);
                        fclose(logr[i].fp);
                        handle_file(i);
                    }
                    
                    logr[i].ign--;
                    clearerr(logr[i].fp);
                }
            }
        }

        /* Only check bellow if check> 50 */
        if(f_check <= 50)
            continue;

        /* Zeroing f_check */    
        f_check = 0;

        /* Checking if any file has been renamed/removed */
        for(i = 0; i <= max_file; i++)
        {
            if(!logr[i].file)
                break;
            else if(!logr[i].fp)
            {
                if(logr[i].ign == -10)
                    continue;
                else
                {
                    handle_file(i);
                    continue;
                }
            }
            else if(logr[i].ign < -1)
            {
                if(logr[i].ign < -5)
                {
                    merror("%s: Ignoring file '%s'. Too many problems "
                            " reading it.",ARGV0,logr[i].file);
                    fclose(logr[i].fp);
                    logr[i].fp = NULL;
                    logr[i].ign = -10;
                }
                continue;
            }
        }

    }
}


/* handke_file: Open, get the ileno, seek to the end and update mtime */
int handle_file(int i)
{
    logr[i].fp = fopen(logr[i].file, "r");
    if(!logr[i].fp)
    {
        return(-1);
    }

    if(fseek(logr[i].fp, 0, SEEK_END) < 0)
    {
        merror("%s: Error handling file '%s' (fseek)",ARGV0,logr[i].file);
        fclose(logr[i].fp);
        logr[i].fp = NULL;
        return(-1);
    }
    if((logr[i].mtime = File_DateofChange(logr[i].file)) < 0)
    {
        merror("%s: Error handling file '%s' (date_of_change)",ARGV0,logr[i].file);
        fclose(logr[i].fp);
        logr[i].fp = NULL;
        return(-1);
    }
    
    logr[i].ign = 0;
    return(0);
}


/* EOF */
