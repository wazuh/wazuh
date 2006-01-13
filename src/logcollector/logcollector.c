/*   $OSSEC, logcollector.c, v0.4, 2005/11/11, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
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


/** void LogCollectorStart() v0.4
 * Handle file management.
 */
void LogCollectorStart()
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
        
        
        /* Initiating the files */    
        handle_file(i);
        
        
        /* Getting the log type */
        if(logr[i].logformat && OS_Match("snort-full", logr[i].logformat))
        {
            logr[i].read = (void *)read_snortfull;
        }
        else
        {
            logr[i].read = (void *)read_syslog;
        }
    }

    max_file = i;
    
    
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
            if(!logr[i].fp)
                continue;

            tmtmp = File_DateofChange(logr[i].file);
            if(tmtmp != logr[i].mtime)
            {
                /* Reading file */
                logr[i].read(i, &r);

                /* Checking read ret code */
                if(r == 0 && feof(logr[i].fp))
                {
                    /* Clearing EOF */
                    clearerr(logr[i].fp);

                    /* Updating mtime */
                    logr[i].mtime = tmtmp;

                    logr[i].ign = 0;
                }
                
                else
                {
                    merror("%s: File error: '%s'", ARGV0, logr[i].file);
                    
                    if(fseek(logr[i].fp,0,SEEK_END) < 0)
                    {
                        merror("%s: File error (fseek): '%s'",
                                                ARGV0, 
                                                logr[i].file);
                        fclose(logr[i].fp);
                        logr[i].fp = NULL;
                        
                        if(handle_file(i) != 0)
                        {
                            logr[i].ign--;
                            continue;
                        }
                    }
                    
                    logr[i].ign--;
                    clearerr(logr[i].fp);
                }
            }
        }

        /* Only check bellow if check > 50 */
        if(f_check <= 50)
            continue;

        /* Zeroing f_check */    
        f_check = 0;

        /* Checking if any file has been renamed/removed */
        for(i = 0; i <= max_file; i++)
        {
            if(!logr[i].fp)
            {
                if(logr[i].ign == -10)
                    continue;
                else
                {
                    handle_file(i);
                    continue;
                }
            }
            else if(logr[i].ign < -5)
            {
                merror("%s: Ignoring file '%s'. Too many problems "
                        "reading it.",ARGV0, logr[i].file);
                fclose(logr[i].fp);
                logr[i].fp = NULL;
                logr[i].ign = -10;
            }
        }

    }
}



/* handle_file: Open, get the fileno, seek to the end and update mtime */
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
