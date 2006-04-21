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
    
    #ifndef WIN32
    int int_error = 0;
    struct timeval fp_timeout;
    #endif

    /* Initializing each file and structure */
    for(i = 0;;i++)
    {
        if(logf[i].file == NULL)
            break;
       
        if(strcmp(logf[i].logformat,"eventlog") == 0)
        {
            #ifdef WIN32
            verbose(READING_EVTLOG, ARGV0, logf[i].file);
            win_startel(logf[i].file);
            #endif
            logf[i].file = NULL;
            logf[i].fp = NULL;
        }
        
        else
        {
            verbose(READING_FILE, ARGV0, logf[i].file);

            /* Initiating the files */    
            handle_file(i);

            /* Getting the log type */
            if(strcmp("snort-full", logf[i].logformat) == 0)
            {
                logf[i].read = (void *)read_snortfull;
            }
            else
            {
                logf[i].read = (void *)read_syslog;
            }
        }
    }


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());
        
    max_file = i -1;
    
    
    /* Daemon loop */
    while(1)
    {
        #ifndef WIN32
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
        #else
        /* Windows don't like select that way */
        Sleep((FP_TIMEOUT + 2) * 1000);
        #endif

        f_check++;
        
        #ifdef WIN32
        /* Check for messages in the event viewer */
        win_readel();
        #endif
        
        /* Checking which file is available */
        for(i = 0; i <= max_file; i++)
        {
            if(!logf[i].fp)
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
            tmtmp = File_DateofChange(logf[i].file);
            if(tmtmp != logf[i].mtime)
            {
                /* Reading file */
                logf[i].read(i, &r);

                /* Checking read ret code */
                if(!ferror(logf[i].fp))
                {
                    /* Clearing EOF */
                    clearerr(logf[i].fp);

                    /* Updating mtime */
                    logf[i].mtime = tmtmp;

                    /* Nothing was available to be read */
                    if(r == 0)
                    {
                        logf[i].ign = 0;
                    }
                    else if(r == 1)
                    {
                        logf[i].ign++;
                    }
                    /* File formatting error */
                    else
                    {
                        logf[i].ign--;
                    }
                }
                /* ferror is set */
                else
                {
                    merror(FREAD_ERROR, ARGV0, logf[i].file);
                    
                    if(fseek(logf[i].fp,0,SEEK_END) < 0)
                    {
                        merror(FSEEK_ERROR, ARGV0, logf[i].file);

                        /* Closing the file */
                        fclose(logf[i].fp);
                        logf[i].fp = NULL;
                        
                        /* Trying to open it again */
                        if(handle_file(i) != 0)
                        {
                            logf[i].ign--;
                            continue;
                        }
                    }
                    
                    /* Increase the error count  */
                    logf[i].ign--;
                    clearerr(logf[i].fp);
                }
            }
        }

        /* Only check bellow if check > 40 */
        if(f_check <= 40)
            continue;

        /* Zeroing f_check */    
        f_check = 0;


        /* Checking if any file has been renamed/removed */
        for(i = 0; i <= max_file; i++)
        {
            /* These are the windows logs */
            if(!logf[i].file)
                continue;
                
            /* File has been changing, but not able to read */
            if(logf[i].ign > 0)
            {
                if(logf[i].fp)
                    fclose(logf[i].fp);
                logf[i].fp = NULL;
                if(handle_file(i) < 0)
                {
                    logf[i].ign = -1;
                }
                else
                {
                    logf[i].ign = -1;
                    continue;
                }
            }
            
            
            /* Too many errors for the file */ 
            if(logf[i].ign < -8)
            {
                merror(LOGC_FILE_ERROR, ARGV0, logf[i].file);
                fclose(logf[i].fp);
                logf[i].fp = NULL;
                logf[i].ign = -10;
                continue;
            }
            
            if(!logf[i].fp)
            {
                if(logf[i].ign <= -10)
                    continue;
                else
                {
                    /* Try for a few times to open the file */
                    if(handle_file(i) < 0)
                    {
                        logf[i].ign--;
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
    logf[i].fp = fopen(logf[i].file, "r");
    if(!logf[i].fp)
    {
        merror(FOPEN_ERROR, ARGV0, logf[i].file);
        return(-1);
    }

    if(fseek(logf[i].fp, 0, SEEK_END) < 0)
    {
        merror(FSEEK_ERROR, ARGV0,logf[i].file);
        fclose(logf[i].fp);
        logf[i].fp = NULL;
        return(-1);
    }
    
    if((logf[i].mtime = File_DateofChange(logf[i].file)) < 0)
    {
        merror(FILE_ERROR,ARGV0,logf[i].file);
        fclose(logf[i].fp);
        logf[i].fp = NULL;
        return(-1);
    }
    
    logf[i].ign = 0;
    return(0);
}


/* EOF */
