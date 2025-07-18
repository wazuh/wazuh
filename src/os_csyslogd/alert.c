/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "csyslogd.h"
#include "shared.h"
#include "cJSON.h"
#include "config/config.h"
#include "os_net/os_net.h"


/* Send an alert via syslog
 * Returns 1 on success or 0 on error
 */

int OS_Alert_SendSyslog(alert_data *al_data, SyslogConfig *syslog_config) {
    char *tstamp;
    char *hostname;
    char syslog_msg[OS_MAXSTR];


    /* Invalid socket, reconnect */
    if (syslog_config->socket < 0) {
        resolve_hostname(&syslog_config->server, 5);

        syslog_config->socket = OS_ConnectUDP(syslog_config->port, get_ip_from_resolved_hostname(syslog_config->server), 0, 0);
        if (syslog_config->socket < 0) {
            return (0);
        }
        mdebug2(SUCCESSFULLY_RECONNECTED_SOCKET, syslog_config->server);
    }

    /* Clear the memory before insert */
    memset(syslog_msg, '\0', OS_MAXSTR);

    /* Look if location is set */

    if (syslog_config->location) {
        //Check if location is headless
        char * location_headless = strstr(al_data->location,"->");

        if (location_headless){        //If location has head, cut it off
            location_headless = location_headless + 2;
        }

        if (!OSMatch_Execute(location_headless ? location_headless : al_data->location,
                             strlen(al_data->location),
                             syslog_config->location)) {
            return (0);
        }

    }


    /* Look for the level */
    if (syslog_config->level) {
        if (al_data->level < syslog_config->level) {
            return (0);
        }
    }

    /* Look for rule id */
    if (syslog_config->rule_id) {
        int id_i = 0;
        while (syslog_config->rule_id[id_i] != 0) {
            if (syslog_config->rule_id[id_i] == al_data->rule) {
                break;
            }
            id_i++;
        }

        /* If we found, id is going to be a valid rule */
        if (!syslog_config->rule_id[id_i]) {
            return (0);
        }
    }

    /* Look for the group */
    if (syslog_config->group) {
        if (!OSMatch_Execute(al_data->group,
                             strlen(al_data->group),
                             syslog_config->group)) {
            return (0);
        }
    }

    /* Fix the timestamp to be syslog compatible
     * We have 2008 Jul 10 10:11:23
     * Should be: Jul 10 10:11:23
     */
    tstamp = al_data->date;
    if (strlen(al_data->date) > 14) {
        tstamp += 5;

        /* Fix first digit if the day is < 10 */
        if (tstamp[4] == '0') {
            tstamp[4] = ' ';
        }
    }

    if (syslog_config->use_fqdn) {
        hostname = __shost_long;
    } else {
        hostname = __shost;
    }

    /* Insert data */
    if (syslog_config->format == DEFAULT_CSYSLOG) {
        /* Build syslog message */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s %s ossec: Alert Level: %u; Rule: %u - %s; Location: %s;",
                 syslog_config->priority, tstamp, hostname,
                 al_data->level,
                 al_data->rule, al_data->comment,
                 al_data->location
                );
        field_add_string(syslog_msg, OS_SIZE_2048, " classification: %s;", al_data->group );
        field_add_string(syslog_msg, OS_SIZE_2048, " srcip: %s;", al_data->srcip );
        field_add_string(syslog_msg, OS_SIZE_2048, " dstip: %s;", al_data->dstip );
        field_add_string(syslog_msg, OS_SIZE_2048, " user: %s;", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " Previous MD5: %s;", al_data->old_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " Current MD5: %s;", al_data->new_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " Previous SHA1: %s;", al_data->old_sha1 );
        field_add_string(syslog_msg, OS_SIZE_2048, " Current SHA1: %s;", al_data->new_sha1 );
        if(al_data->old_sha256){
            field_add_string(syslog_msg, OS_SIZE_2048, " Previous SHA256: %s;", al_data->old_sha256 );
        }
        if(al_data->new_sha256){
            field_add_string(syslog_msg, OS_SIZE_2048, " Current SHA256: %s;", al_data->new_sha256 );
        }
     /* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
        field_add_string(syslog_msg, OS_SIZE_2048, " Size changed: from %s;", al_data->file_size );
        field_add_string(syslog_msg, OS_SIZE_2048, " User ownership: was %s;", al_data->owner_chg );
        field_add_string(syslog_msg, OS_SIZE_2048, " Group ownership: was %s;", al_data->group_chg );
        field_add_string(syslog_msg, OS_SIZE_2048, " Permissions changed: from %s;", al_data->perm_chg );
     /* "9/19/2016 - Sivakumar Nellurandi - parsing additions" */
        field_add_truncated(syslog_msg, OS_SIZE_61440, " %s", al_data->log[0], 2 );
    } else if (syslog_config->format == CEF_CSYSLOG) {
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s CEF:0|%s|%s|%s|%u|%s|%u|dvc=%s cs1=%s cs1Label=Location",
                 syslog_config->priority,
                 tstamp,
                 __author,
                 __ossec_name,
                 __ossec_version,
                 al_data->rule,
                 al_data->comment,
                 (al_data->level > 10) ? 10 : al_data->level,
                 hostname, al_data->location);
        field_add_string(syslog_msg, OS_SIZE_2048, " cat=%s", al_data->group );
        field_add_string(syslog_msg, OS_SIZE_2048, " src=%s", al_data->srcip );
        field_add_int(syslog_msg, OS_SIZE_2048, " dpt=%d", al_data->dstport );
        field_add_int(syslog_msg, OS_SIZE_2048, " spt=%d", al_data->srcport );
        field_add_string(syslog_msg, OS_SIZE_2048, " fname=%s", al_data->filename );
        field_add_string(syslog_msg, OS_SIZE_2048, " dhost=%s", al_data->dstip );
        field_add_string(syslog_msg, OS_SIZE_2048, " shost=%s", al_data->srcip );
        field_add_string(syslog_msg, OS_SIZE_2048, " suser=%s", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " dst=%s", al_data->dstip );
        field_add_string(syslog_msg, OS_SIZE_2048, " suser=%s", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " dst=%s", al_data->dstip );
        field_add_truncated(syslog_msg, OS_SIZE_61440, " msg=%s", al_data->log[0], 2 );
        if (al_data->new_md5 && al_data->new_sha1) {
            field_add_string(syslog_msg, OS_SIZE_2048, " cs2Label=OldMD5 cs2=%s", al_data->old_md5);
            field_add_string(syslog_msg, OS_SIZE_2048, " cs3Label=NewMD5 cs3=%s", al_data->new_md5);
            field_add_string(syslog_msg, OS_SIZE_2048, " oldFileHash=%s", al_data->old_sha1 );
            field_add_string(syslog_msg, OS_SIZE_2048, " fhash=%s", al_data->new_sha1 );
            field_add_string(syslog_msg, OS_SIZE_2048, " fileHash=%s", al_data->new_sha1 );
        }
    } else if (syslog_config->format == JSON_CSYSLOG) {
        /* Build a JSON Object for logging */
        cJSON *root;
        char *json_string;
        root = cJSON_CreateObject();

        /* Data guaranteed to be there */
        cJSON_AddNumberToObject(root, "crit",      al_data->level);
        cJSON_AddNumberToObject(root, "id",        al_data->rule);
        cJSON_AddStringToObject(root, "component", al_data->location);

        /* Rule Meta Data */
        if (al_data->group) {
            cJSON_AddStringToObject(root, "classification", al_data->group);
        }
        if (al_data->comment) {
            cJSON_AddStringToObject(root, "description",    al_data->comment);
        }

        /* Raw log message generating event */
        if (al_data->log && al_data->log[0]) {
            cJSON_AddStringToObject(root, "message",        al_data->log[0]);
        }

        /* Add data if it exists */
        if (al_data->user) {
            cJSON_AddStringToObject(root,   "acct",       al_data->user);
        }
        if (al_data->srcip) {
            cJSON_AddStringToObject(root,   "src_ip",     al_data->srcip);
        }
        if (al_data->srcport) {
            cJSON_AddNumberToObject(root,   "src_port",   al_data->srcport);
        }
        if (al_data->dstip) {
            cJSON_AddStringToObject(root,   "dst_ip",     al_data->dstip);
        }
        if (al_data->dstport) {
            cJSON_AddNumberToObject(root,   "dst_port",   al_data->dstport);
        }
        if (al_data->filename) {
            cJSON_AddStringToObject(root,   "file",       al_data->filename);
        }
        if (al_data->old_md5) {
            cJSON_AddStringToObject(root,   "md5_old",    al_data->old_md5);
        }
        if (al_data->new_md5) {
            cJSON_AddStringToObject(root,   "md5_new",    al_data->new_md5);
        }
        if (al_data->old_sha1) {
            cJSON_AddStringToObject(root,   "sha1_old",   al_data->old_sha1);
        }
        if (al_data->new_sha1) {
            cJSON_AddStringToObject(root,   "sha1_new",   al_data->new_sha1);
        }
        if (al_data->old_sha256) {
            cJSON_AddStringToObject(root,   "sha256_old",   al_data->old_sha256);
        }
        if (al_data->new_sha256) {
            cJSON_AddStringToObject(root,   "sha256_new",   al_data->new_sha256);
        }

        /* Create the JSON string */
        json_string = cJSON_PrintUnformatted(root);

        /* Create the syslog message */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s %s ossec: %s",

                 /* syslog header */
                 syslog_config->priority, tstamp, hostname,

                 /* JSON Encoded Data */
                 json_string
                );
        /* Clean up the memory for the JSON structure */
        free(json_string);
        cJSON_Delete(root);
    } else if (syslog_config->format == SPLUNK_CSYSLOG) {
        /* Build a Splunk Style Key/Value string for logging */
        snprintf(syslog_msg, OS_SIZE_2048,
                 "<%u>%s %s ossec: crit=%u id=%u description=\"%s\" component=\"%s\",",

                 /* syslog header */
                 syslog_config->priority, tstamp, hostname,

                 /* OSSEC metadata */
                 al_data->level, al_data->rule, al_data->comment,
                 al_data->location
                );
        /* Event specifics */
        field_add_string(syslog_msg, OS_SIZE_2048, " classification=\"%s\",", al_data->group );

        if ( field_add_string(syslog_msg, OS_SIZE_2048, " src_ip=\"%s\",", al_data->srcip ) > 0 ) {
            field_add_int(syslog_msg, OS_SIZE_2048, " src_port=%d,", al_data->srcport );
        }


        if ( field_add_string(syslog_msg, OS_SIZE_2048, " dst_ip=\"%s\",", al_data->dstip ) > 0 ) {
            field_add_int(syslog_msg, OS_SIZE_2048, " dst_port=%d,", al_data->dstport );
        }

        field_add_string(syslog_msg, OS_SIZE_2048, " file=\"%s\",", al_data->filename );
        field_add_string(syslog_msg, OS_SIZE_2048, " acct=\"%s\",", al_data->user );
        field_add_string(syslog_msg, OS_SIZE_2048, " md5_old=\"%s\",", al_data->old_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " md5_new=\"%s\",", al_data->new_md5 );
        field_add_string(syslog_msg, OS_SIZE_2048, " sha1_old=\"%s\",", al_data->old_sha1 );
        field_add_string(syslog_msg, OS_SIZE_2048, " sha1_new=\"%s\",", al_data->new_sha1 );
        if(al_data->old_sha256){
            field_add_string(syslog_msg, OS_SIZE_2048, " sha256_old=\"%s\",", al_data->old_sha256 );
        }
        if(al_data->new_sha256){
            field_add_string(syslog_msg, OS_SIZE_2048, " sha256_new=\"%s\",", al_data->new_sha256 );
        }
        /* Message */
        field_add_truncated(syslog_msg, OS_SIZE_61440, " message=\"%s\"", al_data->log[0], 2 );
    }

    if (OS_SendUDPbySize(syslog_config->socket, strlen(syslog_msg), syslog_msg) != 0) {
        OS_CloseSocket(syslog_config->socket);
        syslog_config->socket = -1;
        merror(ERROR_SENDING_MSG, syslog_config->server);
    }

    return (1);
}

/* Send alerts via syslog from JSON alert
 * Returns 1 on success or 0 on error
 */
int OS_Alert_SendSyslog_JSON(cJSON *json_data, SyslogConfig *syslog_config) {
    cJSON * rule;
    cJSON * timestamp;
    cJSON * groups;
    cJSON * item;
    char * string;
    int i;
    char msg[OS_MAXSTR];
    struct tm tm = { .tm_sec = 0 };
    time_t now;
    char * end;
    char strtime[64];

    mdebug2("OS_Alert_SendSyslog_JSON()");

    if (rule = cJSON_GetObjectItem(json_data, "rule"), !rule) {
        mdebug2("Alert with no rule field.");
        return 0;
    }

    if (timestamp = cJSON_GetObjectItem(json_data, "timestamp"), !timestamp) {
        merror("Alert with no timestamp field.");
        return 0;
    }

    /* Look if location is set */

    if (syslog_config->location && !(item = cJSON_GetObjectItem(json_data, "location"), item && (string = item->valuestring, OSMatch_Execute(string, strlen(string), syslog_config->location)))) {
        return 0;
    }

    /* Look for the level */

    if (syslog_config->level && !(item = cJSON_GetObjectItem(rule, "level"), item && item->valueint >= (int)syslog_config->level)) {
        return 0;
    }

    /* Look for rule id */

    if (syslog_config->rule_id) {

        // If no such rule or level, give up

        if (!(rule && (item = cJSON_GetObjectItem(rule, "id"), item))) {
            return 0;
        }

        for (i = 0; syslog_config->rule_id[i] && (int)syslog_config->rule_id[i] != atoi(item->valuestring); i++);

        /* If we found, id is going to be a valid rule */

        if (!syslog_config->rule_id[i]) {
            return (0);
        }
    }

    /* Look for the group */

    if (syslog_config->group) {
        int found = 0;

        if (!(rule && (groups = cJSON_GetObjectItem(rule, "groups"), groups))) {
            return 0;
        }

        cJSON_ArrayForEach(item, groups) {
            string = item->valuestring;

            if (OSMatch_Execute(string, strlen(string), syslog_config->group)) {
                found++;
                break;
            }
        }

        if (!found) {
            return 0;
        }
    }

    string = cJSON_PrintUnformatted(json_data);

    now = time(NULL);
    localtime_r(&now, &tm);

    if (end = strchr(timestamp->valuestring, '.'), end)
        *end = '\0';

    if (end = strptime(timestamp->valuestring, "%FT%T", &tm), !end || *end) {
        merror("Could not parse timestamp '%s'.", timestamp->valuestring);
    }

    strftime(strtime, sizeof(strtime), "%b %d %T", &tm);

    // Space-padding instead of zero-padding
    if (strtime[4] == '0') {
        strtime[4] = ' ';
    }

    /* Create the syslog message */
    snprintf(msg, OS_MAXSTR,
             "<%u>%s %s ossec: %s",

             /* syslog header */
             syslog_config->priority, strtime, syslog_config->use_fqdn ? __shost_long : __shost,

             /* JSON Encoded Data */
             string
            );

    /* Invalid socket, reconnect */
    if (syslog_config->socket < 0) {
        resolve_hostname(&syslog_config->server, 5);

        syslog_config->socket = OS_ConnectUDP(syslog_config->port, get_ip_from_resolved_hostname(syslog_config->server), 0, 0);
        if (syslog_config->socket < 0) {
            return (0);
        }
        mdebug2(SUCCESSFULLY_RECONNECTED_SOCKET, syslog_config->server);
    }

    mdebug2("OS_Alert_SendSyslog_JSON(): sending '%s'", msg);
    if (OS_SendUDPbySize(syslog_config->socket, strlen(msg), msg) != 0) {
        OS_CloseSocket(syslog_config->socket);
        syslog_config->socket = -1;
        merror(ERROR_SENDING_MSG, syslog_config->server);
    }
    free(string);

    return 1;
}
