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
#include "cJSON.h"
#include "config/config.h"
#include "os_net/os_net.h"

/** int OS_Alert_SendSyslog
 * Sends an alert via syslog.
 * Returns 1 on success or 0 on error.
 */
int OS_Alert_SendSyslog(alert_data *al_data, const SyslogConfig *syslog_config)
{
    char *tstamp;
    char syslog_msg[OS_SIZE_2048];

    /* Invalid socket. */
    if(syslog_config->socket < 0)
    {
        return(0);
    }


    /* Clearing the memory before insert */
    memset(syslog_msg, '\0', OS_SIZE_2048);


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
                "<%u>%s %s ossec: Alert Level: %u; Rule: %u - %s; Location: %s;",
               	syslog_config->priority, tstamp, __shost,
                al_data->level,
                al_data->rule, al_data->comment,
                al_data->location
        );
        field_add_string(syslog_msg, OS_SIZE_2048, " srcip: %s;", al_data->srcip );
#ifdef GEOIP
        field_add_string(syslog_msg, OS_SIZE_2048, " srccity: %s;", al_data->geoipdatasrc );
        field_add_string(syslog_msg, OS_SIZE_2048, " dstcity: %s;", al_data->geoipdatadst );
#endif
        field_add_string(syslog_msg, OS_SIZE_2048, " dstip: %s;", al_data->dstip );
        field_add_string(syslog_msg, OS_SIZE_2048, " user: %s;", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " Previous MD5: %s;", al_data->old_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " Current MD5: %s;", al_data->new_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " Previous SHA1: %s;", al_data->old_sha1 );
        field_add_string(syslog_msg, OS_SIZE_2048, " Current SHA1: %s;", al_data->new_sha1 );
        field_add_truncated(syslog_msg, OS_SIZE_2048, " %s", al_data->log[0], 2 );
    }
    else if(syslog_config->format == CEF_CSYSLOG)
    {
       	snprintf(syslog_msg, OS_SIZE_2048,

                "<%u>%s CEF:0|%s|%s|%s|%u|%s|%u|dvc=%s cs2=%s cs2Label=Location",
               	syslog_config->priority,
		tstamp,
		__author,
		__ossec_name,
		__version,
		al_data->rule,
		al_data->comment,
		(al_data->level > 10) ? 10 : al_data->level,
                __shost, al_data->location);
        field_add_string(syslog_msg, OS_SIZE_2048, " src=%s", al_data->srcip );
        field_add_int(syslog_msg, OS_SIZE_2048, " dpt=%d", al_data->dstport );
        field_add_int(syslog_msg, OS_SIZE_2048, " spt=%d", al_data->srcport );
        field_add_string(syslog_msg, OS_SIZE_2048, " fname=%s", al_data->filename );
        field_add_string(syslog_msg, OS_SIZE_2048, " dhost=%s", al_data->dstip );
        field_add_string(syslog_msg, OS_SIZE_2048, " shost=%s", al_data->srcip );
        field_add_string(syslog_msg, OS_SIZE_2048, " suser=%s", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " dst=%s", al_data->dstip );
#ifdef GEOIP
        field_add_string(syslog_msg, OS_SIZE_2048, " cs3Label=SrcCity cs3=%s", al_data->geoipdatasrc );
        field_add_string(syslog_msg, OS_SIZE_2048, " cs4Label=DstCity cs4=%s", al_data->geoipdatadst );
#endif
        field_add_string(syslog_msg, OS_SIZE_2048, " suser=%s", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " dst=%s", al_data->dstip );
        field_add_truncated(syslog_msg, OS_SIZE_2048, " msg=%s", al_data->log[0], 2 );
        if (al_data->new_md5 && al_data->new_sha1) {
            field_add_string(syslog_msg, OS_SIZE_2048, " cs1Label=OldMD5 cs1=%s", al_data->old_md5);
            field_add_string(syslog_msg, OS_SIZE_2048, " cs2Label=NewMDG cs2=%s", al_data->new_md5);
            field_add_string(syslog_msg, OS_SIZE_2048, " oldFileHash=%s", al_data->old_sha1 );
            field_add_string(syslog_msg, OS_SIZE_2048, " fhash=%s", al_data->new_sha1 );
            field_add_string(syslog_msg, OS_SIZE_2048, " fileHash=%s", al_data->new_sha1 );
        }
    }
    else if(syslog_config->format == JSON_CSYSLOG)
    {
        /* Build a JSON Object for logging */
        cJSON *root;
        char *json_string;
        root = cJSON_CreateObject();

        // Data guaranteed to be there
        cJSON_AddNumberToObject(root, "crit",      al_data->level);
        cJSON_AddNumberToObject(root, "id",        al_data->rule);
        cJSON_AddStringToObject(root, "component", al_data->location);

        // Rule Meta Data
        if (al_data->group)   cJSON_AddStringToObject(root, "classification", al_data->group);
        if (al_data->comment) cJSON_AddStringToObject(root, "description",    al_data->comment);

        // Raw log message generating event
        if (al_data->log && al_data->log[0])
                cJSON_AddStringToObject(root, "message",        al_data->log[0]);

        // Add data if it exists
        if (al_data->user)       cJSON_AddStringToObject(root,   "acct",       al_data->user);
        if (al_data->srcip)      cJSON_AddStringToObject(root,   "src_ip",     al_data->srcip);
        if (al_data->srcport)    cJSON_AddNumberToObject(root,   "src_port",   al_data->srcport);
        if (al_data->dstip)      cJSON_AddStringToObject(root,   "dst_ip",     al_data->dstip);
        if (al_data->dstport)    cJSON_AddNumberToObject(root,   "dst_port",   al_data->dstport);
        if (al_data->filename)   cJSON_AddStringToObject(root,   "file",       al_data->filename);
        if (al_data->old_md5)    cJSON_AddStringToObject(root,   "md5_old",    al_data->old_md5);
        if (al_data->new_md5)    cJSON_AddStringToObject(root,   "md5_new",    al_data->new_md5);
        if (al_data->old_sha1)   cJSON_AddStringToObject(root,   "sha1_old",   al_data->old_sha1);
        if (al_data->new_sha1)   cJSON_AddStringToObject(root,   "sha1_new",   al_data->new_sha1);
#ifdef GEOIP
        if (al_data->geoipdatasrc) cJSON_AddStringToObject(root, "src_city", al_data->geoipdatasrc);
        if (al_data->geoipdatadst) cJSON_AddStringToObject(root, "dst_city", al_data->geoipdatadst);
#endif

        // Create the JSON String
        json_string = cJSON_PrintUnformatted(root);

        // Create the syslog message
        snprintf(syslog_msg, OS_SIZE_2048,
                "<%u>%s %s ossec: %s",

                /* syslog header */
                syslog_config->priority, tstamp, __shost,

                /* JSON Encoded Data */
                json_string
        );
        // Cleanup the memory for the JSON Structure
        free(json_string);
        cJSON_Delete(root);
    }
    else if(syslog_config->format == SPLUNK_CSYSLOG)
    {
        /* Build a Splunk Style Key/Value string for logging */
        snprintf(syslog_msg, OS_SIZE_2048,
                "<%u>%s %s ossec: crit=%u id=%u description=\"%s\" component=\"%s\",",

                /* syslog header */
                syslog_config->priority, tstamp, __shost,

                /* OSSEC metadata */
                al_data->level, al_data->rule, al_data->comment,
                al_data->location
        );
        /* Event specifics */
        field_add_string(syslog_msg, OS_SIZE_2048, " classification=\"%s\",", al_data->group );

        if( field_add_string(syslog_msg, OS_SIZE_2048, " src_ip=\"%s\",", al_data->srcip ) > 0 )
            field_add_int(syslog_msg, OS_SIZE_2048, " src_port=%d,", al_data->srcport );

#ifdef GEOIP
        field_add_string(syslog_msg, OS_SIZE_2048, " src_city=\"%s\",", al_data->geoipdatasrc );
        field_add_string(syslog_msg, OS_SIZE_2048, " dst_city=\"%s\",", al_data->geoipdatadst );
#endif

        if( field_add_string(syslog_msg, OS_SIZE_2048, " dst_ip=\"%s\",", al_data->dstip ) > 0 )
            field_add_int(syslog_msg, OS_SIZE_2048, " dst_port=%d,", al_data->dstport );

        field_add_string(syslog_msg, OS_SIZE_2048, " file=\"%s\",", al_data->filename );
        field_add_string(syslog_msg, OS_SIZE_2048, " acct=\"%s\",", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " md5_old=\"%s\",", al_data->old_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " md5_new=\"%s\",", al_data->new_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " sha1_old=\"%s\",", al_data->old_sha1 );
        field_add_string(syslog_msg, OS_SIZE_2048, " sha1_new=\"%s\",", al_data->new_sha1 );
        /* Message */
        field_add_truncated(syslog_msg, OS_SIZE_2048, " message=\"%s\"", al_data->log[0], 2 );
    }


    OS_SendUDPbySize(syslog_config->socket, strlen(syslog_msg), syslog_msg);
    return(1);
}


/* EOF */
