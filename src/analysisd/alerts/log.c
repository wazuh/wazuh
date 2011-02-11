/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */


#include "shared.h"
#include "log.h"
#include "alerts.h"
#include "getloglocation.h"
#include "rules.h"
#include "eventinfo.h"
#include "config.h"


/* Drop/allow patterns */
OSMatch FWDROPpm;
OSMatch FWALLOWpm;


/* OS_Store: v0.2, 2005/02/10 */
/* Will store the events in a file 
 * The string must be null terminated and contain
 * any necessary new lines, tabs, etc.
 *
 */
void OS_Store(Eventinfo *lf)
{
    fprintf(_eflog,
            "%d %s %02d %s %s%s%s %s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->full_log);

    fflush(_eflog); 
    return;	
}



void OS_LogOutput(Eventinfo *lf)
{
    printf(
           "** Alert %d.%ld:%s - %s\n"
            "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
            "%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
            lf->time,
            __crt_ftell,
            lf->generated_rule->alert_opts & DO_MAILALERT?" mail ":"",
            lf->generated_rule->group,
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->generated_rule->sigid,
            lf->generated_rule->level,
            lf->generated_rule->comment,

            lf->srcip == NULL?"":"\nSrc IP: ",
            lf->srcip == NULL?"":lf->srcip,

            lf->srcport == NULL?"":"\nSrc Port: ",
            lf->srcport == NULL?"":lf->srcport,

            lf->dstip == NULL?"":"\nDst IP: ",
            lf->dstip == NULL?"":lf->dstip,

            lf->dstport == NULL?"":"\nDst Port: ",
            lf->dstport == NULL?"":lf->dstport,

            lf->dstuser == NULL?"":"\nUser: ",
            lf->dstuser == NULL?"":lf->dstuser,

            lf->full_log);


    /* Printing the last events if present */
    if(lf->generated_rule->last_events)
    {
        char **lasts = lf->generated_rule->last_events;
        while(*lasts)
        {
            printf("%.1256s\n",*lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    printf("\n");

    fflush(stdout);
    return;	
}



/* OS_Log: v0.3, 2006/03/04 */
/* _writefile: v0.2, 2005/02/09 */
void OS_Log(Eventinfo *lf)
{
    /* Writting to the alert log file */
    fprintf(_aflog,
            "** Alert %d.%ld:%s - %s\n"
            "%d %s %02d %s %s%s%s\nRule: %d (level %d) -> '%s'"
            "%s%s%s%s%s%s%s%s%s%s\n%.1256s\n",
            lf->time,
            __crt_ftell,
            lf->generated_rule->alert_opts & DO_MAILALERT?" mail ":"",
            lf->generated_rule->group,
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->generated_rule->sigid,
            lf->generated_rule->level,
            lf->generated_rule->comment,

            lf->srcip == NULL?"":"\nSrc IP: ",
            lf->srcip == NULL?"":lf->srcip,

            lf->srcport == NULL?"":"\nSrc Port: ",
            lf->srcport == NULL?"":lf->srcport,

            lf->dstip == NULL?"":"\nDst IP: ",
            lf->dstip == NULL?"":lf->dstip,

            lf->dstport == NULL?"":"\nDst Port: ",
            lf->dstport == NULL?"":lf->dstport,

            lf->dstuser == NULL?"":"\nUser: ",
            lf->dstuser == NULL?"":lf->dstuser,

            lf->full_log);


    /* Printing the last events if present */
    if(lf->generated_rule->last_events)
    {
        char **lasts = lf->generated_rule->last_events;
        while(*lasts)
        {
            fprintf(_aflog,"%.1256s\n",*lasts);
            lasts++;
        }
        lf->generated_rule->last_events[0] = NULL;
    }

    fprintf(_aflog,"\n");

    fflush(_aflog);
    return;	
}



void OS_InitFwLog()
{
    /* Initializing fw log regexes */
    if(!OSMatch_Compile(FWDROP, &FWDROPpm, 0))
    {
        ErrorExit(REGEX_COMPILE, ARGV0, FWDROP,
                FWDROPpm.error);
    }

    if(!OSMatch_Compile(FWALLOW, &FWALLOWpm, 0))
    {
        ErrorExit(REGEX_COMPILE, ARGV0, FWALLOW,
                FWALLOWpm.error);
    }
                    
}


/* FW_Log: v0.1, 2005/12/30 */
int FW_Log(Eventinfo *lf)
{
    /* If we don't have the srcip or the
     * action, there is no point in going
     * forward over here
     */
    if(!lf->action || !lf->srcip)
    {
        return(0);
    }


    /* Setting the actions */
    switch(*lf->action)
    {
        /* discard, drop, deny, */
        case 'd':
        case 'D':
        /* reject, */
        case 'r':
        case 'R':
        /* block */
        case 'b':
        case 'B':
            os_free(lf->action);
            os_strdup("DROP", lf->action);
            break;
        /* Closed */
        case 'c':
        case 'C':
        /* Teardown */
        case 't':
        case 'T':
            os_free(lf->action);
            os_strdup("CLOSED", lf->action);
            break;
        /* allow, accept, */    
        case 'a':
        case 'A':
        /* pass/permitted */
        case 'p':
        case 'P':
        /* open */
        case 'o':
        case 'O':    
            os_free(lf->action);
            os_strdup("ALLOW", lf->action);        
            break;
        default:
            if(OSMatch_Execute(lf->action,strlen(lf->action),&FWDROPpm))
            {
                os_free(lf->action);
                os_strdup("DROP", lf->action);
            }
            if(OSMatch_Execute(lf->action,strlen(lf->action),&FWALLOWpm))
            {
                os_free(lf->action);
                os_strdup("ALLOW", lf->action);
            }
            else
            {
                os_free(lf->action);
                os_strdup("UNKNOWN", lf->action);
            }
            break;    
    }


    /* log to file */
    fprintf(_fflog,
            "%d %s %02d %s %s%s%s %s %s %s:%s->%s:%s\n",
            lf->year,
            lf->mon,
            lf->day,
            lf->hour,
            lf->hostname != lf->location?lf->hostname:"",
            lf->hostname != lf->location?"->":"",
            lf->location,
            lf->action,
            lf->protocol,
            lf->srcip,
            lf->srcport,
            lf->dstip,
            lf->dstport);
    
    fflush(_fflog);

    return(1);
}

/* EOF */
