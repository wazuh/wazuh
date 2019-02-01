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

static int FindEventcheck(Eventinfo *lf, int pm_id, int *socket);
static int FindGlobal(Eventinfo *lf, char *name, int *socket);
static int FindScanInfo(Eventinfo *lf, char *module, int *socket);
static int SaveEventcheck(Eventinfo *lf, int exists, int *socket,int id,char * name,char * title,char *cis_control,char *description,char *rationale,char *remediation,char *default_value, char * file,char * directory,char * process,char * registry,char * reference,char * result);
static int SaveGlobalInfo(Eventinfo *lf, int *socket,int scan_id, char *name,char *description,char *os_required,int pass,int failed,int score,int update);
static int SaveScanInfo(Eventinfo *lf,int *socket, char * module,int scan_id, int pm_start_scan, int pm_end_scan, int update,int start);
static int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value);
static void HandleCheckEvent(Eventinfo *lf,int *socket,cJSON *event);
static void HandleGlobalInfo(Eventinfo *lf,int *socket,cJSON *event);
static void HandleScanInfo(Eventinfo *lf,int *socket,cJSON *event,int start);
static int CheckEventJSON(cJSON *event,cJSON **scan_id,cJSON **id,cJSON **name,cJSON **title, cJSON **cis_control,cJSON **description,cJSON **rationale,cJSON **remediation,cJSON **default_value,cJSON **compliance,cJSON **check,cJSON **reference,cJSON **file,cJSON **directory,cJSON **process,cJSON **registry,cJSON **result);
static int CheckGlobalJSON(cJSON *event,cJSON **scan_id,cJSON **name,cJSON **description,cJSON **os_required,cJSON **pass,cJSON **failed,cJSON **score);
static int pm_send_db(char *msg, char *response, int *sock);

static OSDecoderInfo *rootcheck_json_dec = NULL;

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
        else if (strcmp(type->valuestring,"check") == 0){
            minfo("%s",cJSON_PrintUnformatted(json_event));

            HandleCheckEvent(lf,socket,json_event);

            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } 
        else if (strcmp(type->valuestring,"summary") == 0){
            minfo("%s",cJSON_PrintUnformatted(json_event));

            HandleGlobalInfo(lf,socket,json_event);
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } 
        else if (strcmp(type->valuestring,"scan-started") == 0){
            minfo("%s",cJSON_PrintUnformatted(json_event));

            cJSON *pm_scan_id;
            cJSON *pm_scan_start;

            pm_scan_id = cJSON_GetObjectItem(json_event, "scan_id");
            pm_scan_start = cJSON_GetObjectItem(json_event, "time");

            if(!pm_scan_id || !pm_scan_start) {
                cJSON_Delete(json_event);
                ret_val = 0;
                return ret_val;
            }

            HandleScanInfo(lf,socket,json_event,1);

            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } 
        else if (strcmp(type->valuestring,"scan-ended") == 0){
            minfo("%s",cJSON_PrintUnformatted(json_event));

            cJSON *pm_scan_id;
            cJSON *pm_scan_end;

            pm_scan_id = cJSON_GetObjectItem(json_event, "scan_id");
            pm_scan_end = cJSON_GetObjectItem(json_event, "time");


            if(!pm_scan_id || !pm_scan_end) {
                cJSON_Delete(json_event);
                ret_val = 0;
                return ret_val;
            }

            HandleScanInfo(lf,socket,json_event,0);

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

int FindEventcheck(Eventinfo *lf, int pm_id, int *socket)
{

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring query %d", lf->agent_id, pm_id);

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

static int FindGlobal(Eventinfo *lf, char *name, int *socket){
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring query_global %s", lf->agent_id, name);

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

static int FindScanInfo(Eventinfo *lf, char *module, int *socket) {
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring query_scan %s", lf->agent_id, module);

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

static int SaveEventcheck(Eventinfo *lf, int exists, int *socket,int id,char * name,char * title,char *cis_control,char *description,char *rationale,char *remediation,char *default_value, char * file,char * directory,char * process,char * registry,char * reference,char * result)
{

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if (exists)
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring update %d|%s", lf->agent_id, id, result);
    else
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring insert %d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s", lf->agent_id,id,name,title,cis_control,description,rationale,remediation,default_value,file,directory,process,registry,reference,result);

    if (pm_send_db(msg, response, socket) == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

static int SaveScanInfo(Eventinfo *lf,int *socket,char * module,int scan_id, int pm_start_scan, int pm_end_scan,int update,int start) {
    
    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if(!update) {
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring insert_scan_info %s|%d|%d|%d",lf->agent_id, module, scan_id,pm_start_scan,pm_end_scan );
    } else {
        if(start) {
            snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring update_scan_info_start %s|%d",lf->agent_id, module,pm_start_scan );
        } else {
            snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring update_scan_info %s|%d",lf->agent_id, module,pm_end_scan );
        }
    }
   
    if (pm_send_db(msg, response, socket) == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

static int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value) {
    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring insert_compliance %d|%s|%s",lf->agent_id, id_check,key,value );
   
    if (pm_send_db(msg, response, socket) == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

static void HandleCheckEvent(Eventinfo *lf,int *socket,cJSON *event) {

    cJSON *scan_id;
    cJSON *id;
    cJSON *name;
    cJSON *cis_control;
    cJSON *title;
    cJSON *description;
    cJSON *rationale;
    cJSON *remediation;
    cJSON *default_value;
    cJSON *check;
    cJSON *compliance;
    cJSON *reference;
    cJSON *file;
    cJSON *directory;
    cJSON *process;
    cJSON *registry;
    cJSON *result;

    if(!CheckEventJSON(event,&scan_id,&id,&name,&title,&cis_control,&description,&rationale,&remediation,&default_value,&compliance,&check,&reference,&file,&directory,&process,&registry,&result)) {
       
        int result_event = 0;
        int result_db = FindEventcheck(lf, id->valueint, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying policy monitoring database for agent %s", lf->agent_id);
                break;
            case 0: // It exists, update
                result_event = SaveEventcheck(lf, 1, socket,id->valueint,name ? name->valuestring : NULL,title ? title->valuestring : NULL,cis_control ? cis_control->valuestring : NULL,description ? description->valuestring : NULL,rationale ? rationale->valuestring : NULL,remediation ? remediation->valuestring : NULL,default_value ? default_value->valuestring : NULL,file ? file->valuestring : NULL,directory ? directory->valuestring : NULL,process ? process->valuestring : NULL,registry ? registry->valuestring : NULL,reference ? reference->valuestring : NULL,result ? result->valuestring : NULL);
                if (result_event < 0)
                {
                    merror("Error updating policy monitoring database for agent %s", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveEventcheck(lf, 0, socket,id->valueint,name ? name->valuestring : NULL,title ? title->valuestring : NULL,cis_control ? cis_control->valuestring : NULL,description ? description->valuestring : NULL,rationale ? rationale->valuestring : NULL,remediation ? remediation->valuestring : NULL,default_value ? default_value->valuestring : NULL,file ? file->valuestring : NULL,directory ? directory->valuestring : NULL,process ? process->valuestring : NULL,registry ? registry->valuestring : NULL,reference ? reference->valuestring : NULL,result ? result->valuestring : NULL);
                if (result_event < 0)
                {
                    merror("Error storing policy monitoring information for agent %s", lf->agent_id);
                }

                // Save compliance
                cJSON *comp;
                cJSON_ArrayForEach(comp,compliance){

                    char *key = comp->string;
                    char *value = NULL;
                    int free_value = 0;

                    if(!comp->valuestring){
                        if(comp->valueint) {
                            os_calloc(OS_SIZE_1024, sizeof(char), value);
                            sprintf(value, "%d", comp->valueint);
                            free_value = 1;
                        } else if(comp->valuedouble) {
                            os_calloc(OS_SIZE_1024, sizeof(char), value);
                            sprintf(value, "%lf", comp->valuedouble);
                            free_value = 1;
                        }
                    } else {
                        value = comp->valuestring;
                    }

                    SaveCompliance(lf,socket,id->valueint,key,value);

                    if(free_value) {
                        os_free(value);
                    }
                }

                break;
            default:
                break;
        }
    }
}

static void HandleGlobalInfo(Eventinfo *lf,int *socket,cJSON *event) {

    cJSON *scan_id;
    cJSON *name;
    cJSON *description;
    cJSON *os_required;
    cJSON *pass;
    cJSON *failed;
    cJSON *scored;

    if(!CheckGlobalJSON(event,&scan_id,&name,&description,&os_required,&pass,&failed,&scored)) {
        int result_event = 0;
        int result_db = FindGlobal(lf, name->valuestring, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying policy monitoring database for agent %s", lf->agent_id);
                break;
            case 0: // It exists, update
                result_event = SaveGlobalInfo(lf,socket,scan_id->valueint,name->valuestring,description->valuestring,os_required ? os_required->valuestring: NULL,pass->valueint,failed->valueint,scored->valueint,1);
                if (result_event < 0)
                {
                    merror("Error updating global policy monitoring database for agent %s", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveGlobalInfo(lf,socket,scan_id->valueint,name->valuestring,description->valuestring,os_required ? os_required->valuestring : NULL,pass->valueint,failed->valueint,scored->valueint,0);
                if (result_event < 0)
                {
                    merror("Error storing global policy monitoring information for agent %s", lf->agent_id);
                }
                break;
            default:
                break;
        }
    }
}

static void HandleScanInfo(Eventinfo *lf,int *socket,cJSON *event,int start) {

    cJSON *pm_scan_id;
    cJSON *pm_scan_start;
    cJSON *pm_scan_end;

    pm_scan_id = cJSON_GetObjectItem(event, "scan_id");

    if(!pm_scan_id){
        return;
    }

    if(start) {
        pm_scan_start = cJSON_GetObjectItem(event, "time");

        if(!pm_scan_start) {
            return;
        }
    } else {
        pm_scan_end= cJSON_GetObjectItem(event, "time");

        if(!pm_scan_end) {
            return;
        }
    }
   

    int result_event = 0;
    int result_db = FindScanInfo(lf,"policy-monitoring",socket);

    switch (result_db)
    {
        case -1:
            merror("Error querying policy monitoring database for agent %s", lf->agent_id);
            break;
        case 0: // It exists, update
            if(start){
                result_event = SaveScanInfo(lf,socket,"policy-monitoring",pm_scan_id->valueint,pm_scan_start->valueint,0,1,1);
                if (result_event < 0)
                {
                    merror("Error updating scan policy monitoring database for agent %s", lf->agent_id);
                }
            } else {
                result_event = SaveScanInfo(lf,socket,"policy-monitoring",pm_scan_id->valueint,0,pm_scan_end->valueint,1,0);
                if (result_event < 0)
                {
                    merror("Error updating scan policy monitoring database for agent %s", lf->agent_id);
                }
            }
            break;
        case 1: // It not exists, insert
            if(start) {
                result_event = SaveScanInfo(lf,socket,"policy-monitoring",pm_scan_id->valueint,pm_scan_start->valueint,0,0,1);
                if (result_event < 0)
                {
                    merror("Error storing scan policy monitoring information for agent %s", lf->agent_id);
                }
            } else {
                result_event = SaveScanInfo(lf,socket,"policy-monitoring",pm_scan_id->valueint,0,pm_scan_end->valueint,0,0);
                if (result_event < 0)
                {
                    merror("Error storing scan policy monitoring information for agent %s", lf->agent_id);
                }
            }
            
            break;
        default:
            break;
    }
    
}

static int CheckEventJSON(cJSON *event,cJSON **scan_id,cJSON **id,cJSON **name,cJSON **title, cJSON **cis_control,cJSON **description,cJSON **rationale,cJSON **remediation,cJSON **default_value,cJSON **compliance,cJSON **check,cJSON **reference,cJSON **file,cJSON **directory,cJSON **process,cJSON **registry,cJSON **result) {
    int retval = 1;

    if( *scan_id = cJSON_GetObjectItem(event, "id"), !*scan_id) {
        merror("Malformed JSON: field 'id' not found");
        return retval;
    }

    if( *name = cJSON_GetObjectItem(event, "profile"), !*name) {
        merror("Malformed JSON: field 'profile' not found");
        return retval;
    }

    if( *check = cJSON_GetObjectItem(event, "check"), !*check) {
        merror("Malformed JSON: field 'check' not found");
        return retval;

    } else {

        if( *id = cJSON_GetObjectItem(*check, "id"), !*id) {
            merror("Malformed JSON: field 'id' not found");
            return retval;
        }

        if( *title = cJSON_GetObjectItem(*check, "title"), !*title) {
            merror("Malformed JSON: field 'title' not found");
            return retval;
        }

        if( *cis_control = cJSON_GetObjectItem(*check, "cis_control"), !*cis_control) {
            merror("Malformed JSON: field 'cis_control' not found");
            return retval;
        }

        if( *description = cJSON_GetObjectItem(*check, "description"), !*description) {
            merror("Malformed JSON: field 'description' not found");
            return retval;
        }

        if( *rationale = cJSON_GetObjectItem(*check, "rationale"), !*rationale) {
            merror("Malformed JSON: field 'rationale' not found");
            return retval;
        }

        if( *remediation = cJSON_GetObjectItem(*check, "remediation"), !*remediation) {
            merror("Malformed JSON: field 'remediation' not found");
            return retval;
        }

        if( *default_value = cJSON_GetObjectItem(*check, "default_value"), !*default_value) {
            merror("Malformed JSON: field 'default_value' not found");
            return retval;
        }

        *reference = cJSON_GetObjectItem(*check, "reference");
            
        if( *compliance = cJSON_GetObjectItem(*check, "compliance"), !*compliance) {
            merror("Malformed JSON: field 'compliance' not found");
            return retval;
        }

        *file = cJSON_GetObjectItem(*check, "file");
        *directory = cJSON_GetObjectItem(*check, "directory");
        *process = cJSON_GetObjectItem(*check, "process");
        *registry = cJSON_GetObjectItem(*check, "registry");

        if(!*file && !*directory && !*process && !*registry){
            merror("Malformed JSON: field 'file' or 'directory' or 'process' or 'registry' not found");
            return retval;
        }
        
        if( *result = cJSON_GetObjectItem(*check, "result"), !*result) {
            merror("Malformed JSON: field 'result' not found");
            return retval;
        }
    }

    retval = 0;
    return retval;
}

static int CheckGlobalJSON(cJSON *event,cJSON **scan_id,cJSON **name,cJSON **description,cJSON **os_required,cJSON **pass,cJSON **failed,cJSON **score){
    int retval = 1;

    if( *scan_id = cJSON_GetObjectItem(event, "scan_id"), !*scan_id) {
        merror("Malformed JSON: field 'id' not found");
        return retval;
    }

    if( *name = cJSON_GetObjectItem(event, "name"), !*name) {
        merror("Malformed JSON: field 'name' not found");
        return retval;
    }

    if( *description = cJSON_GetObjectItem(event, "description"), !*description) {
        merror("Malformed JSON: field 'description' not found");
        return retval;
    }

    *os_required = cJSON_GetObjectItem(event, "os_required");
     
    if( *pass = cJSON_GetObjectItem(event, "passed"), !*pass) {
        merror("Malformed JSON: field 'passed' not found");
        return retval;
    }

    if( *failed = cJSON_GetObjectItem(event, "failed"), !*failed) {
        merror("Malformed JSON: field 'failed' not found");
        return retval;
    }

    if( *score = cJSON_GetObjectItem(event, "score"), !*score) {
        merror("Malformed JSON: field 'score' not found");
        return retval;
    }

    retval = 0;
    return retval;
}


static int SaveGlobalInfo(Eventinfo *lf, int *socket,int scan_id, char *name,char *description,char *os_required,int pass,int failed,int score,int update) {

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

 
    if(update) {
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring update_global %d|%s|%s|%s|%d|%d|%d",lf->agent_id, scan_id,name,description,os_required,pass,failed,score);
    } else {
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring insert_global %d|%s|%s|%s|%d|%d|%d",lf->agent_id, scan_id,name,description,os_required,pass,failed,score);
    }
   
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