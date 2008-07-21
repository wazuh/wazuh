/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "csyslogd.h"
#include "config/config.h"





/** int OS_Alert_SendSyslog
 * Sends an alert via syslog.
 * Returns 1 on success or 0 on error.
 */
int OS_Alert_SendSyslog(alert_data *al_data, SyslogConfig *syslog_config)
{
    char *tstamp;
    char syslog_msg[OS_SIZE_2048 +1];


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
    


    /* Inserting data */
    if(syslog_config->format == DEFAULT_CSYSLOG)
    {
        /* Building syslog message. */
        snprintf(syslog_msg, OS_SIZE_2048,
                "<%d>%s %s ossec: Alert Level: %d; Rule: %d - %s; "
                "Location: %s; %s%s%s %s",
                syslog_config->priority, tstamp, __shost,
                al_data->level, al_data->rule, al_data->comment,
                al_data->location, 

                /* Source ip. */
                al_data->srcip?"srcip: ":"",
                al_data->srcip?al_data->srcip:"",
                al_data->srcip?";":"",
                al_data->log[0]);
    }


    merror("XXXXX ARG '%s'", syslog_msg);
    return(1);
}


/* EOF */
