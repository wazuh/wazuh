/*   $OSSEC, logcollector.c, v0.4, 2005/11/11, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */




#include "shared.h"

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
    int int_error = 0;
    
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

    max_file = i -1;
    
    
    /* Daemon loop */
    while(1)
    {
        fp_timeout.tv_sec = FP_TIMEOUT;
        fp_timeout.tv_usec = 0;

        /* Waiting for the select timeout */ 
        if ((r = select(0, NULL, NULL, NULL, &fp_timeout)) < 0)
        {
            merror(SELECT_ERROR, ARGV0);
            int_error++;

            if(int_error >= 5)
            {
                ErrorExit(SYSTEM_ERROR, ARGV0);
            }
            continue;
        }

        f_check++;


        /* Checking which file is available */
        for(i = 0; i <= max_file; i++)
        {
            if(!logr[i].fp)
                continue;

            /* We check if the date of the file has changed.
             * If it did, we go and read the file. If for some
             * reason, there is nothing available to be read,
             * the file returns 1. On error, ferror is returned.
             * If nothing is available to be read and the
             * time of change keep changing, it's probably
             * because the file has been moved or something
             * like that. We need to open and close the file
             * again.
             */
            tmtmp = File_DateofChange(logr[i].file);
            if(tmtmp != logr[i].mtime)
            {
                /* Reading file */
                logr[i].read(i, &r);

                /* Checking read ret code */
                if(!ferror(logr[i].fp))
                {
                    /* Clearing EOF */
                    clearerr(logr[i].fp);

                    /* Updating mtime */
                    logr[i].mtime = tmtmp;

                    /* Nothing was available to be read */
                    if(r == 0)
                    {
                        logr[i].ign = 0;
                    }
                    else if(r == 1)
                    {
                        logr[i].ign++;
                    }
                    /* File formatting error */
                    else
                    {
                        logr[i].ign--;
                    }
                }
                /* ferror is set */
                else
                {
                    merror(FREAD_ERROR, ARGV0, logr[i].file);
                    
                    if(fseek(logr[i].fp,0,SEEK_END) < 0)
                    {
                        merror(FSEEK_ERROR, ARGV0, logr[i].file);

                        /* Closing the file */
                        fclose(logr[i].fp);
                        logr[i].fp = NULL;
                        
                        /* Trying to open it again */
                        if(handle_file(i) != 0)
                        {
                            logr[i].ign--;
                            continue;
                        }
                    }
                    
                    /* Increase the error count  */
                    logr[i].ign--;
                    clearerr(logr[i].fp);
                }
            }
        }

        /* Only check bellow if check > 20 */
        if(f_check <= 20)
            continue;

        /* Zeroing f_check */    
        f_check = 0;


        /* Checking if any file has been renamed/removed */
        for(i = 0; i <= max_file; i++)
        {
            /* File has been changing, but not able to read */
            if(logr[i].ign > 0)
            {
                fclose(logr[i].fp);
                logr[i].fp = NULL;
                if(handle_file(i) < 0)
                {
                    logr[i].ign = -1;
                }
                else
                {
                    logr[i].ign = -1;
                    continue;
                }
            }
            
            
            /* Too many errors for the file */ 
            if(logr[i].ign < -8)
            {
                merror(LOGC_FILE_ERROR, ARGV0, logr[i].file);
                fclose(logr[i].fp);
                logr[i].fp = NULL;
                logr[i].ign = -10;
                continue;
            }
            
            if(!logr[i].fp)
            {
                if(logr[i].ign <= -10)
                    continue;
                else
                {
                    /* Try for a few times to open the file */
                    if(handle_file(i) < 0)
                    {
                        logr[i].ign--;
                    }
                    continue;
                }
            }
           
        }

    }
}



/* handle_file: Open, get the fileno, seek to the end and update mtime */
int handle_file(int i)
{
    /* We must be able to open the file, fseek and get the
     * time of change from it.
     */
    logr[i].fp = fopen(logr[i].file, "r");
    if(!logr[i].fp)
    {
        merror(FOPEN_ERROR, ARGV0, logr[i].file);
        return(-1);
    }

    if(fseek(logr[i].fp, 0, SEEK_END) < 0)
    {
        merror(FSEEK_ERROR, ARGV0,logr[i].file);
        fclose(logr[i].fp);
        logr[i].fp = NULL;
        return(-1);
    }
    
    if((logr[i].mtime = File_DateofChange(logr[i].file)) < 0)
    {
        merror(FILE_ERROR,ARGV0,logr[i].file);
        fclose(logr[i].fp);
        logr[i].fp = NULL;
        return(-1);
    }
    
    logr[i].ign = 0;
    return(0);
}


/* EOF */
