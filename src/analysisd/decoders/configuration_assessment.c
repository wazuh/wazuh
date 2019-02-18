/*
* Copyright (C) 2015-2019, Wazuh Inc.
* December 05, 2018.
*
* This program is a free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* Configuration assessment decoder */

#include "config.h"
#include "eventinfo.h"
#include "alerts/alerts.h"
#include "decoder.h"
#include "external/cJSON/cJSON.h"
#include "plugin_decoders.h"
#include "wazuh_modules/wmodules.h"
#include "os_net/os_net.h"
#include "os_crypto/md5/md5_op.h"
#include "string_op.h"
#include "../../remoted/remoted.h"
#include <time.h>

static int FindEventcheck(Eventinfo *lf, int pm_id, int *socket,char *wdb_response);
static int FindScanInfo(Eventinfo *lf, char *policy_id, int *socket,char *wdb_response);
static int FindPolicyInfo(Eventinfo *lf, char *policy, int *socket);
static int FindCheckResults(Eventinfo *lf, int scan_id, int *socket,char *wdb_response);
static int FindPoliciesIds(Eventinfo *lf, int *socket,char *wdb_response);
static int DeletePolicy(Eventinfo *lf, char *policy, int *socket);
static int DeletePolicyCheck(Eventinfo *lf, char *policy, int *socket);
static int SaveEventcheck(Eventinfo *lf, int exists, int *socket, __attribute__((unused)) int id , __attribute__((unused)) int scan_id,__attribute__((unused)) char * title,__attribute__((unused)) char *description, __attribute__((unused)) char *rationale, __attribute__((unused)) char *remediation,__attribute__((unused)) char * file, __attribute__((unused))char * directory,__attribute__((unused)) char * process, __attribute__((unused)) char * registry,__attribute__((unused)) char * reference,__attribute__((unused))char * result,__attribute__((unused))char * policy_id,cJSON *event);
static int SaveScanInfo(Eventinfo *lf,int *socket, char * policy_id,int scan_id, int pm_start_scan, int pm_end_scan, int pass,int failed, int score,char * hash,int update);
static int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value);
static int SavePolicyInfo(Eventinfo *lf,int *socket, char *name,char *file, char * id,char *description,char * references);
static int UpdateCheckScanId(Eventinfo *lf,int *socket,int scan_id_old,int scan_id_new,char *policy_id);
static void HandleCheckEvent(Eventinfo *lf,int *socket,cJSON *event);
static void HandleScanInfo(Eventinfo *lf,int *socket,cJSON *event);
static void HandlePoliciesInfo(Eventinfo *lf,int *socket,cJSON *event);
static int CheckEventJSON(cJSON *event,cJSON **scan_id,cJSON **id,cJSON **name,cJSON **title,cJSON **description,cJSON **rationale,cJSON **remediation,cJSON **compliance,cJSON **check,cJSON **reference,cJSON **file,cJSON **directory,cJSON **process,cJSON **registry,cJSON **result,cJSON **policy_id);
static int CheckPoliciesJSON(cJSON *event,cJSON **policies);
static void FillCheckEventInfo(Eventinfo *lf,cJSON *scan_id,cJSON *id,cJSON *name,cJSON *title,cJSON *description,cJSON *rationale,cJSON *remediation,cJSON *compliance,cJSON *reference,cJSON *file,cJSON *directory,cJSON *process,cJSON *registry,cJSON *result,char *old_result);
static void FillScanInfo(Eventinfo *lf,cJSON *scan_id,cJSON *name,cJSON *description,cJSON *pass,cJSON *failed,cJSON *score,cJSON *file);
static int pm_send_db(char *msg, char *response, int *sock);
static void *RequestDBThread();
static int ConnectToConfigurationAssessmentSocket();
static int ConnectToConfigurationAssessmentSocketRemoted();
static OSDecoderInfo *configuration_assessment_json_dec = NULL;

static int cfga_socket;
static int cfgar_socket;

static w_queue_t * request_queue;

void ConfigurationAssessmentInit()
{

    os_calloc(1, sizeof(OSDecoderInfo), configuration_assessment_json_dec);
    configuration_assessment_json_dec->id = getDecoderfromlist(CONFIGURATION_ASSESSMENT_MOD);
    configuration_assessment_json_dec->type = OSSEC_RL;
    configuration_assessment_json_dec->name = CONFIGURATION_ASSESSMENT_MOD;
    configuration_assessment_json_dec->fts = 0;

    request_queue = queue_init(1024);

    w_create_thread(RequestDBThread,NULL);

    mdebug1("ConfigurationAssessmentInit completed.");
}

static void *RequestDBThread() {

    while(1) {
        char *msg;

        if (msg = queue_pop_ex(request_queue), msg) {
            int rc;
            char *agent_id = msg;
            char *dump_db_msg = strchr(msg,':');
            char *dump_db_msg_original = dump_db_msg;

            if(dump_db_msg) {
                *dump_db_msg++ = '\0';
            } else {
                goto end;
            }

            if(strcmp(agent_id,"000") == 0) {
                if(ConnectToConfigurationAssessmentSocket() == 0){
                    if ((rc = OS_SendUnix(cfga_socket, dump_db_msg, 0)) < 0) {
                        /* Error on the socket */
                        if (rc == OS_SOCKTERR) {
                            merror("socketerr (not available).");
                            close(cfga_socket);
                        }
                        /* Unable to send. Socket busy */
                        mdebug2("Socket busy, discarding message.");
                    } else {
                        close(cfga_socket);
                    }
                }
            } else {
               
                /* Send to agent */
                if(!ConnectToConfigurationAssessmentSocketRemoted()) {
                    *dump_db_msg_original = ':';

                    if ((rc = OS_SendUnix(cfgar_socket, msg, 0)) < 0) {
                        /* Error on the socket */
                        if (rc == OS_SOCKTERR) {
                            merror("socketerr (not available).");
                            close(cfgar_socket);
                        }
                        /* Unable to send. Socket busy */
                        mdebug2("Socket busy, discarding message.");
                    } else {
                        close(cfgar_socket);
                    }
                }
            }
end:
            os_free(msg);
        }
    }

    return NULL;
}

static int ConnectToConfigurationAssessmentSocket() {

    if ((cfga_socket = StartMQ(CFGAQUEUE, WRITE)) < 0) {
        merror(QUEUE_ERROR, CFGAQUEUE, strerror(errno));
        return -1;
    }

    return 0;
}

static int ConnectToConfigurationAssessmentSocketRemoted() {

    if ((cfgar_socket = StartMQ(CFGARQUEUE, WRITE)) < 0) {
        merror(QUEUE_ERROR, CFGARQUEUE, strerror(errno));
        return -1;
    }

    return 0;
}

int DecodeConfigurationAssessment(Eventinfo *lf, int *socket)
{
    int ret_val = 1;
    cJSON *json_event = NULL;
    cJSON *type = NULL;
    lf->decoder_info = configuration_assessment_json_dec;

    if (json_event = cJSON_Parse(lf->log), !json_event)
    {
        merror("Malformed configuration assessment JSON event");
        return ret_val;
    }

    /* TODO - Check if the event is a final event */
    type = cJSON_GetObjectItem(json_event, "type");

    if(type) {

        if (strcmp(type->valuestring,"check") == 0){

            HandleCheckEvent(lf,socket,json_event);
            
            lf->decoder_info = configuration_assessment_json_dec;

            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } 
        else if (strcmp(type->valuestring,"summary") == 0){

            HandleScanInfo(lf,socket,json_event);
            lf->decoder_info = configuration_assessment_json_dec;

            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"policies") == 0){

            HandlePoliciesInfo(lf,socket,json_event);

            lf->decoder_info = configuration_assessment_json_dec;

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

int FindEventcheck(Eventinfo *lf, int pm_id, int *socket,char *wdb_response)
{

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment query %d", lf->agent_id, pm_id);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok found", 8))
        {
            char *result_passed_or_failed = response + 9;
            snprintf(wdb_response,OS_MAXSTR,"%s",result_passed_or_failed);
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

static int FindScanInfo(Eventinfo *lf, char *policy_id, int *socket,char *wdb_response) {
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment query_scan %s", lf->agent_id, policy_id);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok found", 8))
        {
            char *result_hash = response + 9;
            snprintf(wdb_response,OS_MAXSTR,"%s",result_hash);
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

static int FindCheckResults(Eventinfo *lf, int scan_id, int *socket,char *wdb_response) {

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment query_results %d", lf->agent_id, scan_id);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok found", 8))
        {
            char *result_checks = response + 9;
            snprintf(wdb_response,OS_MAXSTR,"%s",result_checks);
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

static int FindPoliciesIds(Eventinfo *lf, int *socket,char *wdb_response) {
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment query_policies ", lf->agent_id);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok found", 8))
        {
            char *result_checks = response + 9;
            snprintf(wdb_response,OS_MAXSTR,"%s",result_checks);
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

static int FindPolicyInfo(Eventinfo *lf, char *policy, int *socket) {

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment query_policy %s", lf->agent_id, policy);

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

static int DeletePolicy(Eventinfo *lf, char *policy, int *socket) {
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment delete_policy %s", lf->agent_id, policy);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok", 2))
        {
            retval = 0;
        }
        else if (!strncmp(response, "err",3))
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

static int DeletePolicyCheck(Eventinfo *lf, char *policy, int *socket) {
    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment delete_check %s", lf->agent_id, policy);

    if (pm_send_db(msg, response, socket) == 0)
    {
        if (!strncmp(response, "ok", 2))
        {
            retval = 0;
        }
        else if (!strncmp(response, "err",3))
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

static int SaveEventcheck(Eventinfo *lf, int exists, int *socket, __attribute__((unused)) int id , __attribute__((unused)) int scan_id,__attribute__((unused)) char * title,__attribute__((unused)) char *description, __attribute__((unused)) char *rationale, __attribute__((unused)) char *remediation,__attribute__((unused)) char * file, __attribute__((unused))char * directory,__attribute__((unused)) char * process, __attribute__((unused)) char * registry,__attribute__((unused)) char * reference,__attribute__((unused))char * result,__attribute__((unused))char * policy_id,cJSON *event)
{

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if (exists) {
        snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment update %d|%s", lf->agent_id, id, result);
    }
    else {
        char *json_event = cJSON_PrintUnformatted(event);
        snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment insert %s", lf->agent_id,json_event);
        os_free(json_event);
    }
       

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

static int SaveScanInfo(Eventinfo *lf,int *socket, char * policy_id,int scan_id, int pm_start_scan, int pm_end_scan, int pass,int failed, int score,char * hash,int update) {
    
    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if(!update) {
        snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment insert_scan_info %d|%d|%d|%s|%d|%d|%d|%s",lf->agent_id,pm_start_scan,pm_end_scan,scan_id,policy_id,pass,failed,score,hash);
    } else {
        snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment update_scan_info_start %s|%d|%d|%d|%d|%d|%d|%s",lf->agent_id, policy_id,pm_start_scan,pm_end_scan,scan_id,pass,failed,score,hash );
    }
   
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

static int SavePolicyInfo(Eventinfo *lf,int *socket, char *name,char *file, char * id,char *description,char * references) {
    
    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment insert_policy %s|%s|%s|%s|%s",lf->agent_id,name,file,id,description,references);
   
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

static int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value) {
    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment insert_compliance %d|%s|%s",lf->agent_id, id_check,key,value );
   
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

static void HandleCheckEvent(Eventinfo *lf,int *socket,cJSON *event) {

    cJSON *scan_id = NULL;
    cJSON *id = NULL;
    cJSON *name = NULL;
    cJSON *title = NULL;
    cJSON *description = NULL;
    cJSON *rationale = NULL;
    cJSON *remediation = NULL;
    cJSON *check = NULL;
    cJSON *compliance = NULL;
    cJSON *reference = NULL;
    cJSON *file = NULL;
    cJSON *directory = NULL;
    cJSON *process = NULL;
    cJSON *registry = NULL;
    cJSON *result = NULL;
    cJSON *policy_id = NULL;

    if(!CheckEventJSON(event,&scan_id,&id,&name,&title,&description,&rationale,&remediation,&compliance,&check,&reference,&file,&directory,&process,&registry,&result,&policy_id)) {
       
        int result_event = 0;
        char *wdb_response = NULL;
        os_calloc(OS_MAXSTR,sizeof(char),wdb_response);

        int result_db = FindEventcheck(lf, id->valueint, socket,wdb_response);

        switch (result_db)
        {
            case -1:
                merror("Error querying policy monitoring database for agent %s", lf->agent_id);
                break;
            case 0: // It exists, update
                result_event = SaveEventcheck(lf, 1, socket,id->valueint,scan_id ? scan_id->valueint : -1,title ? title->valuestring : NULL,description ? description->valuestring : NULL,rationale ? rationale->valuestring : NULL,remediation ? remediation->valuestring : NULL,file ? file->valuestring : NULL,directory ? directory->valuestring : NULL,process ? process->valuestring : NULL,registry ? registry->valuestring : NULL,reference ? reference->valuestring : NULL,result ? result->valuestring : NULL,policy_id ? policy_id->valuestring : NULL,event);
               
                if(strcmp(wdb_response,result->valuestring)) {
                    FillCheckEventInfo(lf,scan_id,id,name,title,description,rationale,remediation,compliance,reference,file,directory,process,registry,result,wdb_response);
                }
                if (result_event < 0)
                {
                    merror("Error updating policy monitoring database for agent %s", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveEventcheck(lf, 0, socket,id->valueint,scan_id ? scan_id->valueint : -1,title ? title->valuestring : NULL,description ? description->valuestring : NULL,rationale ? rationale->valuestring : NULL,remediation ? remediation->valuestring : NULL,file ? file->valuestring : NULL,directory ? directory->valuestring : NULL,process ? process->valuestring : NULL,registry ? registry->valuestring : NULL,reference ? reference->valuestring : NULL,result ? result->valuestring : NULL,policy_id ? policy_id->valuestring : NULL,event);

                if(strcmp(wdb_response,result->valuestring)) {
                    FillCheckEventInfo(lf,scan_id,id,name,title,description,rationale,remediation,compliance,reference,file,directory,process,registry,result,NULL);
                }

                if (result_event < 0)
                {
                    merror("Error storing policy monitoring information for agent %s", lf->agent_id);
                } else {
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
                }
                break;
            default:
                break;
        }
        os_free(wdb_response);
    }
}

static void HandleScanInfo(Eventinfo *lf,int *socket,cJSON *event) {

    cJSON *pm_scan_id = NULL;
    cJSON *pm_scan_start = NULL;
    cJSON *pm_scan_end = NULL;
    cJSON *policy_id = NULL;
    cJSON *description = NULL;
    cJSON *references = NULL;
    cJSON *passed = NULL;
    cJSON *failed = NULL;
    cJSON *score = NULL;
    cJSON *hash = NULL;
    cJSON *file = NULL;
    cJSON *policy = NULL;

    pm_scan_id = cJSON_GetObjectItem(event, "scan_id");
    policy_id =  cJSON_GetObjectItem(event, "policy_id");
    description = cJSON_GetObjectItem(event,"description");
    references = cJSON_GetObjectItem(event,"references");
    pm_scan_start = cJSON_GetObjectItem(event,"start_time");
    pm_scan_end = cJSON_GetObjectItem(event,"end_time");
    passed = cJSON_GetObjectItem(event,"passed");
    failed = cJSON_GetObjectItem(event,"failed");
    score = cJSON_GetObjectItem(event,"score");
    hash = cJSON_GetObjectItem(event,"hash");
    file = cJSON_GetObjectItem(event,"file");
    policy = cJSON_GetObjectItem(event,"name");

    if(!policy_id) {
        return;
    }

    if(!policy_id->valuestring) {
        merror("Malformed JSON: field 'policy_id' must be a string");
        return;
    }

    if(!pm_scan_id){
        return;
    }

    if(!pm_scan_id->valueint) {
        merror("Malformed JSON: field 'scan_id' must be a string");
        return;
    }

    if(!description){
        return;
    }

    if(!description->valuestring) {
        merror("Malformed JSON: field 'description' must be a string");
        return;
    }

    if(!references){
        return;
    }

    if(!references->valuestring) {
        merror("Malformed JSON: field 'references' must be a string");
        return;
    }

    if(!pm_scan_start) {
        return;
    }

    if(!pm_scan_start->valueint) {
        merror("Malformed JSON: field 'start_time' must be a string");
        return;
    }

    if(!pm_scan_end) {
        return;
    }

    if(!pm_scan_end->valueint) {
        merror("Malformed JSON: field 'end_time' must be a string");
        return;
    }

    if(!passed){
        return;
    }

    if(!passed->valueint) {
        merror("Malformed JSON: field 'passed' must be a string");
        return;
    }

    if(!failed){
        return;
    }

    if(!failed->valueint) {
        merror("Malformed JSON: field 'failed' must be a string");
        return;
    }

    if(!score){
        return;
    }

    if(!score->valueint) {
        merror("Malformed JSON: field 'score' must be a string");
        return;
    }

    if(!hash){
        return;
    }

    if(!hash->valuestring) {
        merror("Malformed JSON: field 'hash' must be a string");
        return;
    }

    if(!file){
        return;
    }

    if(!file->valuestring) {
        merror("Malformed JSON: field 'file' must be a string");
        return;
    }

    if(!policy){
        return;
    }

    if(!policy->valuestring) {
        merror("Malformed JSON: field 'policy' must be a string");
        return;
    }

    int result_event = 0;
    char *hash_scan_info = NULL;
    os_md5 hash_md5;
    os_calloc(OS_MAXSTR,sizeof(char),hash_scan_info);
    
    int result_db = FindScanInfo(lf,policy_id->valuestring,socket,hash_scan_info);

    int scan_id_old;
    sscanf(hash_scan_info,"%s %d",hash_md5,&scan_id_old);

    switch (result_db)
    {
        case -1:
            merror("Error querying policy monitoring database for agent %s", lf->agent_id);
            break;
        case 0: // It exists, update

            result_event = SaveScanInfo(lf,socket,policy_id->valuestring,pm_scan_id->valueint,pm_scan_start->valueint,pm_scan_end->valueint,passed->valueint,failed->valueint,score->valueint,hash->valuestring,1);
            if (result_event < 0)
            {
                merror("Error updating scan policy monitoring database for agent %s", lf->agent_id);
            } else {

                /* Compare hash with previous hash */
                if(strcmp(hash_md5,hash->valuestring)) {
                    FillScanInfo(lf,pm_scan_id,policy,description,passed,failed,score,file);
                }
            }
            break;
        case 1: // It not exists, insert
            
            result_event = SaveScanInfo(lf,socket,policy_id->valuestring,pm_scan_id->valueint,pm_scan_start->valueint,pm_scan_end->valueint,passed->valueint,failed->valueint,score->valueint,hash->valuestring,0);
            if (result_event < 0)
            {
                merror("Error storing scan policy monitoring information for agent %s", lf->agent_id);
            } else {

                /* Compare hash with previous hash */
                if(strcmp(hash_md5,hash->valuestring)) {
                    FillScanInfo(lf,pm_scan_id,policy,description,passed,failed,score,file);
                }
            }
            
            break;
        default:
            break;
    }

    result_db = FindPolicyInfo(lf,policy_id->valuestring,socket);

    switch (result_db)
    {
        case -1:
            merror("Error querying policy monitoring database for agent %s", lf->agent_id);
            break;
        case 1: // It not exists, insert
            
            result_event = SavePolicyInfo(lf,socket,policy->valuestring,file->valuestring,policy_id->valuestring,description->valuestring,references->valuestring);
            if (result_event < 0)
            {
                merror("Error storing scan policy monitoring information for agent %s", lf->agent_id);
            }
            
            break;
        default:
            break;
    }

    UpdateCheckScanId(lf,socket,scan_id_old,pm_scan_id->valueint,policy_id->valuestring);
    os_free(hash_scan_info);

    char *wdb_response = NULL;
    os_calloc(OS_MAXSTR,sizeof(char),wdb_response);

    result_db = FindCheckResults(lf,pm_scan_id->valueint,socket,wdb_response);
    char request_db[OS_SIZE_4096 + 1] = {0};

    switch (result_db)
    {
        case -1:
            merror("Error querying policy monitoring database for agent %s", lf->agent_id);
            break;
        case 0: 
            
            /* Integrity check */
            if(strcmp(wdb_response,hash->valuestring)) {

                mdebug2("MD5 from DB: %s MD5 from summary: %s",wdb_response,hash->valuestring);
                mdebug2("Requesting DB dump");
                snprintf(request_db,OS_SIZE_4096,"%s:configuration-assessment-dump:%s",lf->agent_id,policy_id->valuestring);
                char *msg = NULL;

                os_strdup(request_db,msg);
                queue_push_ex(request_queue,msg);
            }

            break;
        default:
            break;
    }

    os_free(wdb_response);
}

static int CheckEventJSON(cJSON *event,cJSON **scan_id,cJSON **id,cJSON **name,cJSON **title,cJSON **description,cJSON **rationale,cJSON **remediation,cJSON **compliance,cJSON **check,cJSON **reference,cJSON **file,cJSON **directory,cJSON **process,cJSON **registry,cJSON **result,cJSON **policy_id) {
    int retval = 1;
    cJSON *obj;

    if( *scan_id = cJSON_GetObjectItem(event, "id"), !*scan_id) {
        merror("Malformed JSON: field 'id' not found");
        return retval;
    }

    obj = *scan_id;
    if( !obj->valueint ) {
        merror("Malformed JSON: field 'id' must be a number");
        return retval;
    }

    if( *name = cJSON_GetObjectItem(event, "policy"), !*name) {
        merror("Malformed JSON: field 'profile' not found");
        return retval;
    }

    obj = *name;
    if( !obj->valuestring ) {
        merror("Malformed JSON: field 'policy' must be a string");
        return retval;
    }

    if( *policy_id = cJSON_GetObjectItem(event, "policy_id"), !*policy_id) {
        merror("Malformed JSON: field 'policy_id' not found");
        return retval;
    }

    obj = *policy_id;
    if( !obj->valuestring ) {
        merror("Malformed JSON: field 'policy_id' must be a string");
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

        obj = *id;
        if( !obj->valueint ) {
            merror("Malformed JSON: field 'id' must be a string");
            return retval;
        }

        if( *title = cJSON_GetObjectItem(*check, "title"), !*title) {
            merror("Malformed JSON: field 'title' not found");
            return retval;
        }

        obj = *title;
        if( !obj->valuestring ) {
            merror("Malformed JSON: field 'title' must be a string");
            return retval;
        }

        *description = cJSON_GetObjectItem(*check, "description");

        obj = *description;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'description' must be a string");
            return retval;
        }

        *rationale = cJSON_GetObjectItem(*check, "rationale");

        obj = *rationale;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'rationale' must be a string");
            return retval;
        }

        *remediation = cJSON_GetObjectItem(*check, "remediation");

        obj = *remediation;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'remediation' must be a string");
            return retval;
        }

        *reference = cJSON_GetObjectItem(*check, "references");

        obj = *reference;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'reference' must be a string");
            return retval;
        }
            
        *compliance = cJSON_GetObjectItem(*check, "compliance");

        *file = cJSON_GetObjectItem(*check, "file");
        obj = *file;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'file' must be a string");
            return retval;
        }

        *directory = cJSON_GetObjectItem(*check, "directory");
        obj = *directory;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'directory' must be a string");
            return retval;
        }

        *process = cJSON_GetObjectItem(*check, "process");
        obj = *process;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'process' must be a string");
            return retval;
        }

        *registry = cJSON_GetObjectItem(*check, "registry");
        obj = *registry;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'registry' must be a string");
            return retval;
        }
        
        if( *result = cJSON_GetObjectItem(*check, "result"), !*result) {
            merror("Malformed JSON: field 'result' not found");
            return retval;
        }

        obj = *result;
        if(!obj->valuestring ) {
            merror("Malformed JSON: field 'result' must be a string");
            return retval;
        }
    }

    retval = 0;
    return retval;
}

static void HandlePoliciesInfo(Eventinfo *lf,int *socket,cJSON *event) {
    cJSON *policies = NULL;

    if(!CheckPoliciesJSON(event,&policies)) {
        
        char *policies_ids = NULL;
        char *p_id;
        os_calloc(OS_MAXSTR, sizeof(char), policies_ids);

        int result_db = FindPoliciesIds(lf,socket,policies_ids);
        switch (result_db)
        {
            case -1:
                merror("Error querying policy monitoring database for agent %s", lf->agent_id);
                break;

            default:
                /* For each policy id, look if we have scanned it */
               
                p_id = strtok(policies_ids, ",");
                
                while( p_id != NULL ) {

                    int exists = 0;
                    cJSON *policy;
                    cJSON_ArrayForEach(policy,policies) {
                        if(policy->valuestring) {
                          if(strcmp(policy->valuestring,p_id) == 0) {
                              exists = 1;
                              break;
                          }
                        }
                    }

                    /* This policy is not being scanned anymore, delete it */
                    if(!exists) {
                       int result_delete = DeletePolicy(lf,p_id,socket);

                        switch (result_delete)
                        {
                            case 0:
                                /* Delete checks */
                                DeletePolicyCheck(lf,p_id,socket);
                                break;

                            default:
                                mdebug1("Error deleting policy with id '%s' from database",p_id);
                                break;
                        }
                    }
                    
                    p_id = strtok(NULL, ",");
                }

                break; 
        }

        os_free(policies_ids);
    }
}

static int CheckPoliciesJSON(cJSON *event,cJSON **policies) {
    int retval = 1;

    if( *policies = cJSON_GetObjectItem(event, "policies"), !*policies) {
        merror("Malformed JSON: field 'policies' not found");
        return retval;
    }

    retval = 0;
    return retval;
}

static void FillCheckEventInfo(Eventinfo *lf,cJSON *scan_id,cJSON *id,cJSON *name,cJSON *title,cJSON *description,cJSON *rationale,cJSON *remediation,cJSON *compliance,cJSON *reference,cJSON *file,cJSON *directory,cJSON *process,cJSON *registry,cJSON *result,char *old_result) {
    
    fillData(lf, "configuration_assessment.type", "check");

    if(scan_id) {
        char value[OS_SIZE_128];

        if(scan_id->valueint){
            sprintf(value, "%d", scan_id->valueint);
        } else if (scan_id->valuedouble) {
             sprintf(value, "%lf", scan_id->valuedouble);
        } 
        fillData(lf, "configuration_assessment.scan_id", value);
    }

    if(name) {
        fillData(lf, "configuration_assessment.policy", name->valuestring);
    }

    if(id) {
        char value[OS_SIZE_128];

        if(id->valueint){
            sprintf(value, "%d", id->valueint);
        } else if (id->valuedouble) {
             sprintf(value, "%lf", id->valuedouble);
        } 

        fillData(lf, "configuration_assessment.check.id", value);
    }

    if(title) {
        fillData(lf, "configuration_assessment.check.title", title->valuestring);
    }

    if(description) {
        fillData(lf, "configuration_assessment.check.description", description->valuestring);
    }

    if(rationale) {
        fillData(lf, "configuration_assessment.check.rationale", rationale->valuestring);
    }

    if(remediation) {
        fillData(lf, "configuration_assessment.check.remediation", remediation->valuestring);
    }

    if(compliance) {
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

            char compliance_key[OS_SIZE_1024];
            snprintf(compliance_key,OS_SIZE_1024,"configuration_assessment.check.compliance.%s",key);

            if(value) {
                fillData(lf, compliance_key, value);
            } else {
                mdebug1("Could not fill event compliance data, alert not generated");
            }

            if(free_value) {
                os_free(value);
            }
        }
    }

    if(reference) {
        fillData(lf, "configuration_assessment.check.references", reference->valuestring);
    }

    if(file){
        fillData(lf, "configuration_assessment.check.file", file->valuestring);
    }

    if(directory) {
        fillData(lf, "configuration_assessment.check.directory", directory->valuestring);
    }

    if(registry) {
        fillData(lf, "configuration_assessment.check.registry", registry->valuestring);
    }

    if(process){
        fillData(lf, "configuration_assessment.check.process", process->valuestring);
    }

    if(result) {
        fillData(lf, "configuration_assessment.check.result", result->valuestring);
    }

    if(old_result) {
        fillData(lf, "configuration_assessment.check.previous_result", old_result);
    }
}

static void FillScanInfo(Eventinfo *lf,cJSON *scan_id,cJSON *name,cJSON *description,cJSON *pass,cJSON *failed,cJSON *score,cJSON *file) {
    
    fillData(lf, "configuration_assessment.type", "summary");

    if(scan_id) {
        char value[OS_SIZE_128];

        if(scan_id->valueint){
            sprintf(value, "%d", scan_id->valueint);
        } else if (scan_id->valuedouble) {
            sprintf(value, "%lf", scan_id->valuedouble);
        } 
        fillData(lf, "configuration_assessment.scan_id", value);
    }

    if(name) {
        fillData(lf, "configuration_assessment.name", name->valuestring);
    }

    if(description) {
        fillData(lf, "configuration_assessment.description", description->valuestring);
    }

    if(pass) {
        char value[OS_SIZE_128];

        if(pass->valueint){
            sprintf(value, "%d", pass->valueint);
        } else if (pass->valuedouble) {
             sprintf(value, "%lf", pass->valuedouble);
        } 

        fillData(lf, "configuration_assessment.passed", value);
    }

    if(failed) {
        char value[OS_SIZE_128];

        if(failed->valueint){
            sprintf(value, "%d", failed->valueint);
        } else if (failed->valuedouble) {
            sprintf(value, "%lf", failed->valuedouble);
        } 

        fillData(lf, "configuration_assessment.failed", value);
    }

    if(score) {
        char value[OS_SIZE_128];

        if(score->valueint){
            sprintf(value, "%d", score->valueint);
        } else if (score->valuedouble) {
            sprintf(value, "%lf", score->valuedouble);
        } 

        fillData(lf, "configuration_assessment.score", value);
    }

    if(file){
        fillData(lf, "configuration_assessment.file", file->valuestring);
    }
}

static int UpdateCheckScanId(Eventinfo *lf,int *socket,int scan_id_old,int scan_id_new,char * policy_id) {
    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s configuration-assessment update_check_scan %d|%d|%s",lf->agent_id, scan_id_old,scan_id_new,policy_id);
    
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