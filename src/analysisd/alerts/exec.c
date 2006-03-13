/*   $OSSEC, exec.c, v0.2, 2005/02/10, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software 
 * Foundation
 */

/* Basic e-mailing operations */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "alerts.h"

#include "shared.h"
#include "rules.h"
#include "config.h"
#include "active-response.h"

#include "os_net/os_net.h"
#include "os_regex/os_regex.h"
#include "os_execd/execd.h"

#include "eventinfo.h"


/* OS_Exec v0.1 
 */
void OS_Exec(int *execq, int *arq, Eventinfo *lf, active_response *ar)
{
    char exec_msg[OS_MAXSTR +1];
    char *ip;
    char *location;

    /* Cleaning the IP */
    if(lf->srcip)
    {
        ip = rindex(lf->srcip, ':');
        if(ip)
        {
            ip++;
        }
        else
        {
            ip = lf->srcip;
        }


        /* Checking if IP is to ignored */
        if(Config.white_list)
        {
            if(OS_IPFoundList(lf->srcip, Config.white_list))
            {
                return;
            }
        }
    }
    else
    {
        ip = "";
    }
   

    /* Setting null user */
    if(!lf->user)
    {
        lf->user = "null";
    }
    
    
    /* active response on the server. 
     * The response must be here, if the ar->location is set to AS
     * or the ar->location is set to local (REMOTE_AGENT) and the
     * event location is from here.
     */         
    if((ar->location & AS_ONLY) ||
      ((ar->location & REMOTE_AGENT) && (index(lf->location, '>') == NULL)) )
    {
        if(!(Config.ar & LOCAL_AR))
            return;
            
        snprintf(exec_msg, OS_MAXSTR,
                "%s %s %s",
                ar->name,
                lf->user,
                ip);

        if(OS_SendUnix(*execq, exec_msg, 0) < 0)
        {
            merror("%s: Error communicating with execd", ARGV0);
        }
    }
   
    /* Removing (agent_name) if present */
    if((location = strchr(lf->location, ')')) != NULL)
    {
        /* Going after the ) */
        location+=2;
    }
    else
    {
        location = lf->location;
    }
    
    /* Active response to the forwarder */ 
    if(Config.ar & REMOTE_AR)
    {
        snprintf(exec_msg, OS_MAXSTR,
                "%s %c%c%c %s %s %s %s",
                location,
                (ar->location & ALL_AGENTS)?ALL_AGENTS_C:NONE_C,
                (ar->location & REMOTE_AGENT)?REMOTE_AGENT_C:NONE_C,
                (ar->location & SPECIFIC_AGENT)?SPECIFIC_AGENT_C:NONE_C,
                ar->agent_id,
                ar->name,
                lf->user,
                ip);
       
        if(OS_SendUnix(*arq, exec_msg, 0) < 0)
        {
            merror("%s: Error communicating with ar queue", ARGV0);
        }
    }
    
    return;
}

/* EOF */
