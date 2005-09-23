/*   $OSSEC, eventinfo.c, v0.2, 2005/09/08, Daniel B. Cid$   */

/* Copyright (C) 2004, 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* v0.2(2005/09/08): Multiple additions.
 * v0.1:
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "headers/defs.h"

#include "rules.h"
#include "config.h"
#include "analysisd.h"
#include "eventinfo.h"

#include "headers/debug_op.h"

#include "os_regex/os_regex.h"

/* Search LastEvents.  
 * Will look if any of the last events (inside the timeframe)
 * match the specified rule. 
 */
Eventinfo *Search_LastEvents(Eventinfo *my_lf)
{
    EventNode *eventnode_pt;

    eventnode_pt = OS_GetLastEvent();

    if(!eventnode_pt)
    {
        /* Nothing found */
        return(NULL);
    }
    
    /* Searching all previous events */
    do
    {
        Eventinfo *lf = eventnode_pt->event;
        
        /* If time is outside the timeframe, return */
        if((c_time - lf->time) > currently_rule->timeframe)
            return(NULL);
        
        /* Don't search for events that were already matched 
         * on the same rule.
         */
        if(my_lf->matched == lf->level)
            break;
            
        /* If regex does not match, go to next */
        if(currently_rule->if_matched_regex)
        {
            if(!OS_Regex(currently_rule->if_matched_regex,
                    lf->log))
            {
                /* Didn't match */
                continue;
            }
        }

        /* Group match */
        if(currently_rule->if_matched_group)
        {
            if(!OS_Match(currently_rule->if_matched_group,
                lf->log))
            {
                continue; /* Didn't match */
            }
        }
      
        /* Sid match */
        if(currently_rule->if_matched_sid)
        {
            if(currently_rule->if_matched_sid !=
               lf->sigid)
            {
                continue; /* Didn't match */ 
            }
        }
         
        /* checking for repetitions on user error */
        if(currently_rule->same_user)
        {
            if((!lf->user)||(!currently_lf->user))
                continue;
                
            if(strcmp(lf->user,currently_lf->user) != 0)
                continue;
            
            if(currently_lf->frequency < currently_rule->frequency)
            {
                if(my_lf->frequency <= 30)
                    my_lf->last_events[my_lf->frequency] = lf->log;
                currently_lf->frequency++;
                continue;
            }
        }
        
        /* checking for repetitions from same src_ip */
        else if(currently_rule->same_source_ip)
        {
            if((!lf->srcip)||(!currently_lf->srcip))
                continue;
                
            if(strcmp(lf->srcip,currently_lf->srcip) != 0)
                continue;
            
            if(currently_lf->frequency < currently_rule->frequency)
            {
                if(my_lf->frequency <= 30)
                    my_lf->last_events[my_lf->frequency] = lf->log;
                currently_lf->frequency++;
                continue;
            }
        }
        
        /* frequency check */
        else if(currently_rule->frequency)
        {
            if(my_lf->frequency < currently_rule->frequency)
            {
                if(my_lf->frequency <= 30)
                    my_lf->last_events[my_lf->frequency] = lf->log;
                my_lf->frequency++;
                continue;
            }
        }
        
        /* If reached here, we matched */
        if(my_lf->frequency <= 31)
            my_lf->last_events[my_lf->frequency] = NULL;
        
        lf->matched = my_lf->level;
            
        return(lf);    
        
    }while((eventnode_pt=eventnode_pt->next) != NULL);

    /* Setting last events to null, if we don't match them */
    my_lf->last_events[0] = NULL;
    return(NULL);
}


/* Zero the loginfo structure */
void Zero_Eventinfo(Eventinfo *lf)
{
    lf->log_tag = NULL;
    lf->log = NULL;
    lf->location = NULL;
    lf->group = NULL;
    lf->hostname = NULL;
    lf->comment = NULL;
    lf->info = NULL;
    lf->last_events[0] = NULL; /* Setting the first event as null */
    lf->last_events[31] = NULL; /* Setting the last event as null */

    lf->srcip = NULL;
    lf->dstip = NULL;
    lf->user = NULL;
    lf->dstuser = NULL;
    lf->id = NULL;
    lf->command = NULL;
    lf->fts = NULL;

    lf->type = 0;        
    lf->level = -1; /* level 0 is valid */
    lf->sigid = -1; /* signature id 0 is valid */
    lf->time = 0;
    lf->frequency = 0;
    lf->matched = 0;
    
    lf->year = 0;
    lf->mon = NULL;
    lf->day = 0;
    lf->hour = NULL;

    return;
}

/* Free the loginfo structure */
void Free_Eventinfo(Eventinfo *lf)
{
    if(!lf)
    {
        merror("%s: Trying to free NULL event. Inconsistent..",ARGV0);
        return;
    }
    
    if(lf->log)
        free(lf->log);
    if(lf->group)
        free(lf->group);
    if(lf->location)
        free(lf->location);
    if(lf->hostname)
        free(lf->hostname);    
    if(lf->info)
        free(lf->info);    

    if(lf->srcip)
        free(lf->srcip);
    if(lf->dstip)
        free(lf->dstip);
    if(lf->user)
        free(lf->user);
    if(lf->dstuser)
        free(lf->dstuser);    
    if(lf->id)
        free(lf->id);
    if(lf->command)
        free(lf->command);
        
    if(lf->mon)
        free(lf->mon);
    if(lf->hour)
        free(lf->hour);            

    /* We dont need to free:
     * log_tag
     * fts
     * comment
     */
    
    free(lf);
    lf = NULL; 
    
    return;
}	

/* EOF */
