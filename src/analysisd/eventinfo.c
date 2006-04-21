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



#include "config.h"
#include "analysisd.h"
#include "eventinfo.h"
#include "os_regex/os_regex.h"

/* Search LastEvents.  
 * Will look if any of the last events (inside the timeframe)
 * match the specified rule. 
 */
Eventinfo *Search_LastEvents(Eventinfo *my_lf, RuleInfo *currently_rule)
{
    EventNode *eventnode_pt;
    Eventinfo *lf;

    eventnode_pt = OS_GetLastEvent();

    if(!eventnode_pt)
    {
        /* Nothing found */
        return(NULL);
    }
    
    /* Setting frequency to 0 */
    currently_rule->__frequency = 0;

    
    /* Searching all previous events */
    do
    {
        lf = eventnode_pt->event;
        
        /* If time is outside the timeframe, return */
        if((c_time - lf->time) > currently_rule->timeframe)
        {
            return(NULL);
        }

        /* The category must be the same */
        else if(lf->type != my_lf->type)
        {
            continue;    
        }
        
        /* We avoid multiple triggers for the same rule 
         * or rules with a lower level.
         */
        else if(lf->matched >= currently_rule->level)
        {
            break;
        }
        
        /* If regex does not match, go to next */
        if(currently_rule->if_matched_regex)
        {
            if(!OSRegex_Execute(lf->log, currently_rule->if_matched_regex))
            {
                /* Didn't match */
                continue;
            }
        }

        /* Group match */
        if(currently_rule->if_matched_group)
        {
            if(!OSMatch_Execute(lf->log, lf->size,
                                         currently_rule->if_matched_group))
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
         
        /* Checking for repetitions on user error */
        if(currently_rule->same_user)
        {
            if((!lf->user)||(!my_lf->user))
                continue;
                
            if(strcmp(lf->user,my_lf->user) != 0)
                continue;
        }
        
        /* Checking for repetitions from same src_ip */
        else if(currently_rule->same_source_ip)
        {
            if((!lf->srcip)||(!my_lf->srcip))
                continue;
                
            if(strcmp(lf->srcip,my_lf->srcip) != 0)
                continue;
        }
       
        
        /* Checking if the number of matches worked */ 
        if(currently_rule->__frequency < currently_rule->frequency)
        {
            if(currently_rule->__frequency <= 10)
            {
                currently_rule->last_events[currently_rule->__frequency] 
                            = lf->log;
                currently_rule->last_events[currently_rule->__frequency+1] 
                            = NULL;
            }
            
            currently_rule->__frequency++;
            continue;
        }
        
        
        /* If reached here, we matched */
        lf->matched = currently_rule->level;
            
        return(lf);    
        
    }while((eventnode_pt = eventnode_pt->next) != NULL);

    
    return(NULL);
}


/* Zero the loginfo structure */
void Zero_Eventinfo(Eventinfo *lf)
{
    lf->log_tag = NULL;
    lf->log = NULL;
    lf->group = NULL;
    lf->hostname = NULL;
    lf->comment = NULL;
    lf->info = NULL;

    lf->srcip = NULL;
    lf->dstip = NULL;
    lf->srcport = NULL;
    lf->dstport = NULL;
    lf->protocol = NULL;
    lf->action = NULL;
    lf->user = NULL;
    lf->dstuser = NULL;
    lf->id = NULL;
    lf->command = NULL;
    lf->url = NULL;
    lf->fts = 0;

    lf->mail_flag = 0;
    lf->type = SYSLOG; /* default type is syslog */        
    lf->level = 0;     /* level 0 is valid */
    lf->sigid = -1;    /* signature id 0 is valid */
    lf->time = 0;
    lf->lasts_lf = NULL;
    lf->matched = 0;
    
    lf->year = 0;
    lf->mon[0] = '\0'; lf->mon[3] = '\0';
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
    if(lf->hostname)
        free(lf->hostname);    
    if(lf->info)
        free(lf->info);    

    if(lf->srcip)
        free(lf->srcip);
    if(lf->dstip)
        free(lf->dstip);
    if(lf->srcport)
        free(lf->srcport);
    if(lf->dstport)
        free(lf->dstport);
    if(lf->protocol)
        free(lf->protocol);
    if(lf->action)
        free(lf->action);            
    if(lf->user)
        free(lf->user);
    if(lf->dstuser)
        free(lf->dstuser);    
    if(lf->id)
        free(lf->id);
    if(lf->command)
        free(lf->command);
    if(lf->url)
        free(lf->url);
        
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
