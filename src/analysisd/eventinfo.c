/* @(#) $Id$ */

/* Copyright (C) 2004-2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC.
 * Available at http://www.ossec.net
 */
  


#include "config.h"
#include "analysisd.h"
#include "eventinfo.h"
#include "os_regex/os_regex.h"

/* Search last times a signature fired
 * Will look for only that specific signature.
 */
Eventinfo *Search_LastSids(Eventinfo *my_lf, RuleInfo *currently_rule)
{
    Eventinfo *lf;
    Eventinfo *first_lf;
    OSListNode *lf_node;
    
    
    /* Setting frequency to 0 */
    currently_rule->__frequency = 0;


    /* checking sid search is valid */
    if(!currently_rule->sid_search)
    {
        merror("%s: No sid search!! XXX", ARGV0);
    }

    /* Getting last node */
    lf_node = OSList_GetLastNode(currently_rule->sid_search);
    if(!lf_node)
    {
        return(NULL);
    }
    first_lf = (Eventinfo *)lf_node->data;
    

    do
    {
        lf = (Eventinfo *)lf_node->data;
        
        /* If time is outside the timeframe, return */
        if((c_time - lf->time) > currently_rule->timeframe)
        {
            return(NULL);
        }

        /* We avoid multiple triggers for the same rule
         * or rules with a lower level.
         */
        else if(lf->matched >= currently_rule->level)
        {
            return(NULL);
        }


        /* Checking for repetitions on user error */
        if(currently_rule->context_opts & SAME_USER)
        {
            if((!lf->user)||(!my_lf->user))
                continue;

            if(strcmp(lf->user,my_lf->user) != 0)
                continue;
        }

        /* Checking for same id */
        if(currently_rule->context_opts & SAME_ID)
        {
            if((!lf->id) || (!my_lf->id))
                continue;

            if(strcmp(lf->id,my_lf->id) != 0)
                continue;
        }

        /* Checking for repetitions from same src_ip */
        if(currently_rule->context_opts & SAME_SRCIP)
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
                    = lf->full_log;
                currently_rule->last_events[currently_rule->__frequency+1]
                    = NULL;
            }

            currently_rule->__frequency++;
            continue;
        }


        /* If reached here, we matched */
        my_lf->matched = currently_rule->level;
        lf->matched = currently_rule->level;
        first_lf->matched = currently_rule->level;

        return(lf);


    }while((lf_node = lf_node->prev) != NULL);

    return(NULL);
}


/* Search LastEvents.  
 * Will look if any of the last events (inside the timeframe)
 * match the specified rule. 
 */
Eventinfo *Search_LastEvents(Eventinfo *my_lf, RuleInfo *currently_rule)
{
    EventNode *eventnode_pt;
    Eventinfo *lf;

    /* Last sids search */
    if(currently_rule->if_matched_sid)
    {
        return(Search_LastSids(my_lf, currently_rule));
    }
    
    /* Last events */
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


        /* We avoid multiple triggers for the same rule 
         * or rules with a lower level.
         */
        else if(lf->matched >= currently_rule->level)
        {
            return(NULL);
        }
        
        
        /* The category must be the same */
        else if(lf->type != my_lf->type)
        {
            continue;    
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
            if(!OSMatch_Execute(lf->generated_rule->group, 
                                lf->size,
                                currently_rule->if_matched_group))
            {
                continue; /* Didn't match */
            }
        }
      
        /* Checking for repetitions on user error */
        if(currently_rule->context_opts & SAME_USER)
        {
            if((!lf->user)||(!my_lf->user))
                continue;
                
            if(strcmp(lf->user,my_lf->user) != 0)
                continue;
        }
       
        /* Checking for same id */
        if(currently_rule->context_opts & SAME_ID)
        {
            if((!lf->id) || (!my_lf->id))
                continue;
            
            if(strcmp(lf->id,my_lf->id) != 0)
                continue;    
        }
         
        /* Checking for repetitions from same src_ip */
        if(currently_rule->context_opts & SAME_SRCIP)
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
                            = lf->full_log;
                currently_rule->last_events[currently_rule->__frequency+1] 
                            = NULL;
            }
            
            currently_rule->__frequency++;
            continue;
        }
        
        
        /* If reached here, we matched */
        my_lf->matched = currently_rule->level;
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
    lf->full_log = NULL;
    lf->hostname = NULL;
    lf->program_name = NULL;

    lf->srcip = NULL;
    lf->dstip = NULL;
    lf->srcport = NULL;
    lf->dstport = NULL;
    lf->protocol = NULL;
    lf->action = NULL;
    lf->user = NULL;
    lf->dstuser = NULL;
    lf->id = NULL;
    lf->status = NULL;
    lf->command = NULL;
    lf->url = NULL;
    lf->data = NULL;
    lf->systemname = NULL;
    lf->fts = 0;

    lf->type = SYSLOG; /* default type is syslog */        
    lf->time = 0;
    lf->matched = 0;
    
    lf->year = 0;
    lf->mon[3] = '\0';
    lf->hour[9] = '\0';
    lf->day = 0;

    lf->generated_rule = NULL;
    lf->node_to_delete = NULL;
    
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
    
    if(lf->full_log)
        free(lf->full_log);    

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
    if(lf->status)
        free(lf->status);
    if(lf->dstuser)
        free(lf->dstuser);    
    if(lf->id)
        free(lf->id);
    if(lf->command)
        free(lf->command);
    if(lf->url)
        free(lf->url);

    if(lf->data)
        free(lf->data);    
    if(lf->systemname)
        free(lf->systemname);    


    /* Freeing node to delete */
    if(lf->node_to_delete)
    {
        OSList_DeleteThisNode(lf->generated_rule->prev_matched, 
                              lf->node_to_delete);
    }
    
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
