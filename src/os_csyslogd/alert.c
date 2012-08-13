/* @(#) $Id: ./src/os_csyslogd/alert.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "csyslogd.h"
#include "config/config.h"
#include "os_net/os_net.h"





/** int OS_Alert_SendSyslog
 * Sends an alert via syslog.
 * Returns 1 on success or 0 on error.
 */
int OS_Alert_SendSyslog(alert_data *al_data, SyslogConfig *syslog_config)
{
    char *tstamp;
    char user_msg[256];
    char srcip_msg[256];
    
    char syslog_msg[OS_SIZE_2048 +1];


    /* Invalid socket. */
    if(syslog_config->socket < 0)
    {
        return(0);
    }
    

    /* Clearing the memory before insert */
    memset(syslog_msg, '\0', OS_SIZE_2048 +1);


    /* Looking if location is set */
    if(syslog_config->location)
    {
        if(!OSMatch_Execute(al_data->location,
                            strlen(al_data->location),
                            syslog_config->location))
        {
            return(0);
        }
    }


    /* Looking for the level */
    if(syslog_config->level)
    {
        if(al_data->level < syslog_config->level)
        {
            return(0);
        }
    }


    /* Looking for rule id */
    if(syslog_config->rule_id)
    {
        int id_i = 0;
        while(syslog_config->rule_id[id_i] != 0)
        {
            if(syslog_config->rule_id[id_i] == al_data->rule)
            {
                break;
            }
            id_i++;
        }


        /* If we found, id is going to be a valid rule */
        if(!syslog_config->rule_id[id_i])
        {
            return(0);
        }
    }


    /* Looking for the group */
    if(syslog_config->group)
    {
        if(!OSMatch_Execute(al_data->group,
                            strlen(al_data->group),
                            syslog_config->group))
        {
            return(0);
        }
    }


    /* Fixing the timestamp to be syslog compatible. 
     * We have 2008 Jul 10 10:11:23
     * Should be: Jul 10 10:11:23
     */
    tstamp = al_data->date;
    if(strlen(al_data->date) > 14)
    {
        tstamp+=5;

        /* Fixing first digit if the day is < 10 */ 
        if(tstamp[4] == '0')
            tstamp[4] = ' ';
    }
    

    /* Adding source ip. */
    if(!al_data->srcip || 
       ((al_data->srcip[0] == '(') &&
        (al_data->srcip[1] == 'n') &&
        (al_data->srcip[2] == 'o')))
    {
        srcip_msg[0] = '\0';
    }
    else
    {
        snprintf(srcip_msg, 255, " srcip: %s;", al_data->srcip);
    }


    /* Adding username. */
    if(!al_data->user || 
       ((al_data->user[0] == '(') &&
        (al_data->user[1] == 'n') &&
        (al_data->user[2] == 'o')))
    {
        user_msg[0] = '\0';
    }
    else
    {
        snprintf(user_msg, 255, " user: %s;", al_data->user);
    }


    /* Inserting data */
    if(syslog_config->format == DEFAULT_CSYSLOG)
    {
       	/* Building syslog message. */
       	snprintf(syslog_msg, OS_SIZE_2048,
               	"<%d>%s %s ossec: Alert Level: %d; Rule: %d - %s; "
               	"Location: %s;%s%s  %s",
               	syslog_config->priority, tstamp, __shost,
               	al_data->level, al_data->rule, al_data->comment,
               	al_data->location, 

               	/* Source ip. */
               	srcip_msg,
               	user_msg,
               	al_data->log[0]);
    }
    else if(syslog_config->format == CEF_CSYSLOG)
    {
    	/* Adding source ip. */
    	if(!al_data->srcip ||
	       ((al_data->srcip[0] == '(') &&
        	(al_data->srcip[1] == 'n') &&
        	(al_data->srcip[2] == 'o')))
    	{
    	    srcip_msg[0] = '\0';
    	}
    	else
    	{
    	    snprintf(srcip_msg, 255, "%s", al_data->srcip);
    	}

	/* Adding username. */
	if(!al_data->user ||
	       ((al_data->user[0] == '(') &&
	        (al_data->user[1] == 'n') &&
        	(al_data->user[2] == 'o')))
   	 {
  	      user_msg[0] = '\0';
  	  }
  	  else
  	  {
  	      snprintf(user_msg, 255, "%s", al_data->user);
 	   }

       	snprintf(syslog_msg, OS_SIZE_2048,

               	"<%d>%s CEF:0|%s|%s|%s|%d|%s|%d|dvc=%s cs2=%s cs2Label=Location src=%s suser=%s msg=%s",
               	syslog_config->priority,
		tstamp,
		__author,
		__name,
		__version,
		al_data->rule,
		al_data->comment,
		(al_data->level > 10) ? 10 : al_data->level,
		 __shost, al_data->location, 

               	/* Source ip. */
               	srcip_msg,
               	user_msg,

		/* Message */
               	al_data->log[0]);

    }

    OS_SendUDPbySize(syslog_config->socket, strlen(syslog_msg), syslog_msg);
    
    return(1);
}


/* EOF */
