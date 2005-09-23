/*   $OSSEC, log.c, v0.4, 2005/09/10, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* v0.4 (2005/09/10): Added logging for multiple events
 * v0.3 (2005/02/10)
 */
 
/* Basic logging operations */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>


#include "log.h"
#include "alerts.h"
#include "getloglocation.h"

#include "error_messages/error_messages.h"

#include "headers/defs.h"
#include "headers/os_err.h"
#include "headers/debug_op.h"
#include "headers/file_op.h"

/* analysisd headers */
#include "rules.h"
#include "eventinfo.h"
#include "config.h"


/* Will store the events in a file 
 * The string must be null terminated and contain
 * any necessary new lines, tabs, etc.
 *
 */
void _storetofile(Eventinfo *lf)
{
    if(_eflog) 
    {
        if(fprintf(_eflog,
            "%d %s %02d %s %s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->log) < 0)
        {
            merror("%s: Error writting to archive log file",ARGV0);
            fclose(_eflog);
            _eflog = NULL;
        }
   
        fflush(_eflog); 
    }
    else
    {
        merror("%s: File descriptor closed.",ARGV0);
    }
    
    return;	
}


/* _writefile: v0.2, 2005/02/09 */
void _writefile(Eventinfo *lf)
{

    /* Writting to the alert log file */
    if(_aflog) 
    {
        fprintf(_aflog,
                "%d %s %02d %s %s\nRule: %d (level %d) -> '%s'\n%s\n",
                lf->year,
                lf->mon,
                lf->day,
                lf->hour,
                lf->location,
                lf->sigid,
                lf->level,
                lf->comment,
                lf->sigid == STATS_PLUGIN?
                "No Log Available (HOURLY_STATS)":lf->log);

        /* Printing the last events if present */
        if(lf->last_events[0])
        {
            char **lasts = lf->last_events;
            while(*lasts)
            {
                fprintf(_aflog,"%s\n",*lasts);
                lasts++;
            }
            fprintf(_aflog,"\n");
        }
        else
        {
            fprintf(_aflog,"\n");
        }
        
        fflush(_aflog);
    }
    else
    {
        merror("%s: File descriptor (aflog) closed. Error.",ARGV0);
    }
    
    return;	
}


/* OS_Store: v0.2, 2005/02/10 */
void OS_Store(Eventinfo *lf)
{
    if(OS_GetLogLocation(lf) < 0)
    {
    /* Return null for permission errors. 
     * We can't log.
     */
        merror(PERM_ERROR,ARGV0);
        return;
    }


    /* Write to file */
    _storetofile(lf);

    return;
}


/* OS_Log: v0.2, 2005/02/10 */
void OS_Log(Eventinfo *lf)
{
    if(OS_GetLogLocation(lf) < 0)
    {
    /* Return null for permission errors. 
     * We can't log.
     */
        merror(PERM_ERROR,ARGV0);
        return;
    }


    /* Write to file */
    _writefile(lf);

    return;
}

/* EOF */
