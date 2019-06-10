/*
* Copyright (C) 2015-2019, Wazuh Inc.
* June 05, 2019.
*
* This program is a free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* YARA decoder */

#include "config.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "external/cJSON/cJSON.h"
#include "plugin_decoders.h"
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"
#include "os_crypto/sha256/sha256_op.h"
#include "string_op.h"
#include "../../remoted/remoted.h"
#include <time.h>

/* Set handling */
static void HandleSetDataEvent(Eventinfo *lf, int *socket, cJSON *event);
static int CheckSetDataJSON(cJSON *event, cJSON **name, cJSON **description);
static int FindSetDataEvent(Eventinfo *lf, char *name, int *socket);

/* Set rules handling */
static void HandleSetDataRuleEvent(Eventinfo *lf, int *socket, cJSON *event);
static int CheckSetDataRuleJSON(cJSON *event, cJSON **rules);
static int FindSetDataRuleEvent(Eventinfo *lf, char *event, int *socket);

/* Save event to DB */
static int SaveEvent(Eventinfo *lf, int exists, int *socket, char *query, cJSON *event);

static int pm_send_db(char *msg, char *response, int *sock);
static OSDecoderInfo *yara_json_dec = NULL;


void YARAInit()
{
    os_calloc(1, sizeof(OSDecoderInfo), yara_json_dec);
    yara_json_dec->id = getDecoderfromlist(YARA_MOD);
    yara_json_dec->type = OSSEC_RL;
    yara_json_dec->name = YARA_MOD;
    yara_json_dec->fts = 0;

    mdebug1("YARAInit completed.");
}

int DecodeYARA(Eventinfo *lf, int *socket)
{
    int ret_val = 1;
    cJSON *json_event = NULL;
    cJSON *type = NULL;
    lf->decoder_info = yara_json_dec;

    if (json_event = cJSON_Parse(lf->log), !json_event)
    {
        merror("Malformed configuration assessment JSON event");
        return ret_val;
    }

    type = cJSON_GetObjectItem(json_event, "type");

    if(type) {

        if (strcmp(type->valuestring,"set-data") == 0){

            HandleSetDataEvent(lf, socket, json_event);
            HandleSetDataRuleEvent(lf, socket, json_event);
            lf->decoder_info = yara_json_dec;
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        }

    } else {
        ret_val = 0;
        goto end;
    }

    ret_val = 1;

end:
    cJSON_Delete(json_event);
    return (ret_val);
}

static void HandleSetDataEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);
    
    cJSON *name = NULL;
    cJSON *description = NULL;

    if (!CheckSetDataJSON(event, &name, &description)) {
       
        int result_event = 0;
        int result_db = FindSetDataEvent(lf, name->valuestring, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying yara database for agent %s", lf->agent_id);
                break;
            case 0: // It exists, update
                result_event = SaveEvent(lf, 1, socket, "update", event);
               
                if (result_event < 0) {
                    merror("Error updating yara database for agent %s", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveEvent(lf, 0, socket, "insert_set_data", event);

                if (result_event < 0) {
                    merror("Error storing yara information for agent %s", lf->agent_id);
                }
                break;
            default:
                break;
        }
    }
}

static int CheckSetDataJSON(cJSON *event, cJSON **name, cJSON **description) {
    assert(event);
    int retval = 1;
    cJSON *obj;

    if ( *name = cJSON_GetObjectItem(event, "name"), !*name) {
        merror("Malformed JSON: field 'name' not found");
        return retval;
    }

    obj = *name;
    if ( !obj->valuestring ) {
        merror("Malformed JSON: field 'name' must be a string");
        return retval;
    }

    if ( *description = cJSON_GetObjectItem(event, "description"), !*name) {
        merror("Malformed JSON: field 'description' not found");
        return retval;
    }

    obj = *description;
    if ( !obj->valuestring ) {
        merror("Malformed JSON: field 'description' must be a string");
        return retval;
    }

    retval = 0;
    return retval;
}

int FindSetDataEvent(Eventinfo *lf, char *name, int *socket)
{
    assert(lf);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s yara query %s", lf->agent_id, name);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok found", 8))
        {
            retval = 0;
        }
        else if (!strcmp(response, "ok not found"))
        {
            retval = 1;
        }
        else
        {
            retval = -1;
        }
    }

    free(response);
    return retval;
}

static int SaveEvent(Eventinfo *lf, int exists, int *socket, char *query, cJSON *event) {
    assert(lf);
    assert(event);

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    char *json_event = cJSON_PrintUnformatted(event);

    if (exists) {
        snprintf(msg, OS_MAXSTR - 1, "agent %s yara %s %s", lf->agent_id, query, json_event);
    } else {
        snprintf(msg, OS_MAXSTR - 1, "agent %s yara %s %s", lf->agent_id, query, json_event);
    }

    os_free(json_event);

    if (pm_send_db(msg, response, socket) == 0)
    {
        os_free(response);
        return 0;
    }
    else
    {   
        os_free(response);
        return -1;
    }
}

static void HandleSetDataRuleEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);
    
    cJSON *rules = NULL;
    cJSON *set_name = NULL;

    set_name = cJSON_GetObjectItem(event, "name");

    if (!CheckSetDataRuleJSON(event, &rules)) {
       
        cJSON *rule = NULL;
        cJSON_ArrayForEach(rule, rules){
            cJSON_AddStringToObject(rule,"set_name",set_name->valuestring);

            char *rule_event = cJSON_PrintUnformatted(rule);
            int result_event = 0;
            int result_db = FindSetDataRuleEvent(lf, rule_event, socket);

            switch (result_db)
            {
                case -1:
                    merror("Error querying yara database for agent %s", lf->agent_id);
                    break;
                case 0: // It exists, update
                    result_event = SaveEvent(lf, 1, socket, "update", rule);
                    
                    if (result_event < 0) {
                        merror("Error updating yara database for agent %s", lf->agent_id);
                    }
                    break;
                case 1: // It not exists, insert
                    result_event = SaveEvent(lf, 0, socket, "insert_set_data_rule", rule);

                    if (result_event < 0) {
                        merror("Error storing yara information for agent %s", lf->agent_id);
                    }
                    break;
                default:
                    break;
            }
        }
    }
}

static int CheckSetDataRuleJSON(cJSON *event, cJSON **rules) {
    assert(event);

    int retval = 1;
    cJSON *obj;

    if ( *rules = cJSON_GetObjectItem(event, "rules"), !*rules) {
        merror("Malformed JSON: rules 'name' not found");
        return retval;
    }

    cJSON *rule = NULL;
    cJSON_ArrayForEach(rule,*rules) {

        cJSON *path = NULL;
        if (path = cJSON_GetObjectItem(rule, "path"), !path) {
            merror("Malformed JSON: rule 'path' not found");
            return retval;
        }

        if (!path->valuestring) {
            merror("Malformed JSON: field 'path' must be a string");
            return retval;
        }
    }
    
    retval = 0;
    return retval;
}

static int FindSetDataRuleEvent(Eventinfo *lf, char *event, int *socket) {
    assert(lf);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s yara query_set_get_rule %s", lf->agent_id, event);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok found", 8))
        {
            retval = 0;
        }
        else if (!strcmp(response, "ok not found"))
        {
            retval = 1;
        }
        else
        {
            retval = -1;
        }
    }

    free(event);
    free(response);
    return retval;
}

int pm_send_db(char *msg, char *response, int *sock)
{
    ssize_t length;
    fd_set fdset;
    struct timeval timeout = {0, 1000};
    int size = strlen(msg);
    int retval = -1;
    int attempts;

    // Connect to socket if disconnected
    if (*sock < 0)
    {
        for (attempts = 1; attempts <= PM_MAX_WAZUH_DB_ATTEMPS && (*sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_128)) < 0; attempts++)
        {
            switch (errno)
            {
            case ENOENT:
                mtinfo(ARGV0, "Cannot find '%s'. Waiting %d seconds to reconnect.", WDB_LOCAL_SOCK, attempts);
                break;
            default:
                mtinfo(ARGV0, "Cannot connect to '%s': %s (%d). Waiting %d seconds to reconnect.", WDB_LOCAL_SOCK, strerror(errno), errno, attempts);
            }
            sleep(attempts);
        }

        if (*sock < 0)
        {
            mterror(ARGV0, "at pm_send_db(): Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            goto end;
        }
    }

    // Send msg to Wazuh DB
    if (OS_SendSecureTCP(*sock, size + 1, msg) != 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            merror("at pm_send_db(): database socket is full");
        }
        else if (errno == EPIPE)
        {
            // Retry to connect
            merror("at pm_send_db(): Connection with wazuh-db lost. Reconnecting.");
            close(*sock);

            if (*sock = OS_ConnectUnixDomain(WDB_LOCAL_SOCK, SOCK_STREAM, OS_SIZE_128), *sock < 0)
            {
                switch (errno)
                {
                case ENOENT:
                    mterror(ARGV0, "Cannot find '%s'.", WDB_LOCAL_SOCK);
                    break;
                default:
                    mterror(ARGV0, "Cannot connect to '%s': %s (%d).", WDB_LOCAL_SOCK, strerror(errno), errno);
                }
                goto end;
            }

            if (OS_SendSecureTCP(*sock, size + 1, msg))
            {
                merror("at OS_SendSecureTCP() (retry): %s (%d)", strerror(errno), errno);
                goto end;
            }
        }
        else
        {
            merror("at OS_SendSecureTCP(): %s (%d)", strerror(errno), errno);
            goto end;
        }
    }

    // Wait for socket
    FD_ZERO(&fdset);
    FD_SET(*sock, &fdset);

    if (select(*sock + 1, &fdset, NULL, NULL, &timeout) < 0)
    {
        merror("at select(): %s (%d)", strerror(errno), errno);
        goto end;
    }

    // Receive response from socket
    length = OS_RecvSecureTCP(*sock, response, OS_SIZE_6144);
    switch (length)
    {
    case OS_SOCKTERR:
        merror("OS_RecvSecureTCP(): response size is bigger than expected");
        break;
    case -1:
        merror("at OS_RecvSecureTCP(): %s (%d)", strerror(errno), errno);
        goto end;

    default:
        response[length] = '\0';

        if (strncmp(response, "ok", 2))
        {
            merror("received: '%s'", response);
            goto end;
        }
    }

    retval = 0;

end:
    free(msg);
    return retval;
}
