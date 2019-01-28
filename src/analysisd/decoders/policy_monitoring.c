/*
* Copyright (C) 2015-2019, Wazuh Inc.
* December 05, 2018.
*
* This program is a free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* Windows eventchannel decoder */

#include "config.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "external/cJSON/cJSON.h"
#include "plugin_decoders.h"
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"
#include "string_op.h"
#include <time.h>

/* Logging levels */
#define AUDIT 0
#define CRITICAL 1
#define ERROR 2
#define WARNING 3
#define INFORMATION 4
#define VERBOSE 5

static int FindEventcheck(Eventinfo *lf, char *pm_id, int *socket, char *check_result);
static int SaveEventcheck(Eventinfo *lf, int exists, int *socket, char * pm_id, char * description, char * file, char * reference,char * pci_dss,char * cis,char * result);
static int pm_send_db(char *msg, char *response, int *sock);

static OSDecoderInfo *rootcheck_json_dec = NULL;
static int first_time = 0;

void PolicyMonitoringInit()
{

    os_calloc(1, sizeof(OSDecoderInfo), rootcheck_json_dec);
    rootcheck_json_dec->id = getDecoderfromlist(POLICY_MONITORING_MOD);
    rootcheck_json_dec->type = OSSEC_RL;
    rootcheck_json_dec->name = POLICY_MONITORING_MOD;
    rootcheck_json_dec->fts = 0;

    mdebug1("RootcheckJSONInit completed.");
}

/* Special decoder for Windows eventchannel */
int DecodeRootcheckJSON(Eventinfo *lf, int *socket)
{
    int ret_val = 1;
    int result_db = 0;
    cJSON *json_event = NULL;
    cJSON *type = NULL;
    cJSON *id = NULL;
    cJSON *timestamp = NULL;
    cJSON *profile = NULL;
    cJSON *description = NULL;
    cJSON *check = NULL;
    cJSON *pm_id = NULL;
    cJSON *title = NULL;
    cJSON *files = NULL;
    cJSON *references = NULL;
    cJSON *cis = NULL;
    cJSON *pci_dss = NULL;
    cJSON *result = NULL;

    if (json_event = cJSON_Parse(lf->log), !json_event)
    {
        merror("Malformed rootcheck JSON event");
        return ret_val;
    }

    /* TODO - Check if the event is a final event */
    type = cJSON_GetObjectItem(json_event, "type");

    if(type) {

        if(strcmp(type->valuestring,"info") == 0){
            cJSON *message = cJSON_GetObjectItem(json_event, "message");

            if(message) {
                minfo("%s",cJSON_PrintUnformatted(json_event));
                cJSON_Delete(json_event);
                ret_val = 1;
                return ret_val;
            }
        }
        else if (strcmp(type->valuestring,"alert") == 0){
            minfo("%s",cJSON_PrintUnformatted(json_event));
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } 
        else if (strcmp(type->valuestring,"summary") == 0){
            minfo("%s",cJSON_PrintUnformatted(json_event));
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        }
    } else {
        ret_val = 0;
        goto end;
    }

  

    /* Check if the event is a check */
    id = cJSON_GetObjectItem(json_event, "id");
    timestamp = cJSON_GetObjectItem(json_event, "timestamp");
    profile = cJSON_GetObjectItem(json_event, "profile");
    check = cJSON_GetObjectItem(json_event, "check");
    pm_id = cJSON_GetObjectItem(check, "pm_id");
    title = cJSON_GetObjectItem(check, "title");
    files = cJSON_GetObjectItem(check, "file");
    references = cJSON_GetObjectItem(check, "reference");
    pci_dss = cJSON_GetObjectItem(check, "pci_dss");
    cis = cJSON_GetObjectItem(check, "cis");
    description = cJSON_GetObjectItem(check, "description");
    result = cJSON_GetObjectItem(check, "result");


   /* result_db = FindEventcheck(lf, pm_id->valuestring, socket, result);
    switch (result_db)
    {
    case -1:
        merror("Error querying rootcheck database for agent %s", lf->agent_id);
        goto end;
    case 0: // It exists, update
        result = SaveEventcheck(lf, 1, socket,pm_id->valuestring,description ? description->valuestring : "unknown",files,NULL,pci_dss,cis ? cis->valuestring : "unknown",result ? result->valuestring : "unknown");
        if (result < 0)
        {
            merror("Error updating rootcheck database for agent %s", lf->agent_id);
            goto end;
        }
        goto end;
    case 1: // It not exists, insert
        result = SaveEventcheck(lf, 0, socket,pm_id->valuestring,description ? description->valuestring : "unknown",files,NULL,pci_dss,cis ? cis->valuestring : "unknown",result ? result->valuestring : "unknown");
        if (result < 0)
        {
            merror("Error storing rootcheck information for agent %s", lf->agent_id);
            goto end;
        }
        break;
    default:
        goto end;
    }*/

    ret_val = 1;

end:
    cJSON_Delete(json_event);
    return (ret_val);
}

int FindEventcheck(Eventinfo *lf, char *pm_id, int *socket, char *check_result)
{

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s rootcheck query %s", lf->agent_id, pm_id);

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

int SaveEventcheck(Eventinfo *lf, int exists, int *socket, char * pm_id, char * description, char * file, char * reference,char * pci_dss,char * cis,char * result)
{

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if (exists)
        snprintf(msg, OS_MAXSTR - 1, "agent %s rootcheck update %ld|%s", lf->agent_id, (long int)lf->time.tv_sec, lf->log);
    else
        snprintf(msg, OS_MAXSTR - 1, "agent %s rootcheck insert %ld|%s", lf->agent_id, (long int)lf->time.tv_sec, lf->log);

    if (pm_send_db(msg, response, socket) == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
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
            mterror(ARGV0, "at sc_send_db(): Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            goto end;
        }
    }

    // Send msg to Wazuh DB
    if (OS_SendSecureTCP(*sock, size + 1, msg) != 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            merror("at sc_send_db(): database socket is full");
        }
        else if (errno == EPIPE)
        {
            // Retry to connect
            merror("at sc_send_db(): Connection with wazuh-db lost. Reconnecting.");
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
    length = OS_RecvSecureTCP(*sock, response, OS_SIZE_128);
    switch (length)
    {
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