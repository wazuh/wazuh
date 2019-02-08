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
#include "os_crypto/md5/md5_op.h"
#include "string_op.h"
#include <time.h>

/* Logging levels */
#define AUDIT 0
#define CRITICAL 1
#define ERROR 2
#define WARNING 3
#define INFORMATION 4
#define VERBOSE 5

static int FindEventcheck(Eventinfo *lf, int pm_id, int *socket,char *wdb_response);
static int FindScanInfo(Eventinfo *lf, char *policy_id, int *socket,char *wdb_response);
static int FindPolicyInfo(Eventinfo *lf, char *policy, int *socket);
static int SaveEventcheck(Eventinfo *lf, int exists, int *socket,int id,int scan_id,char * title,char *description,char *rationale,char *remediation, char * file,char * directory,char * process,char * registry,char * reference,char * result);
static int SaveScanInfo(Eventinfo *lf,int *socket, char * policy_id,int scan_id, int pm_start_scan, int pm_end_scan, int pass,int failed, int score,char * hash,int update);
static int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value);
static int SavePolicyInfo(Eventinfo *lf,int *socket, char *name,char *file, char * id,char *description,char * references);
static int UpdateCheckScanId(Eventinfo *lf,int *socket,int scan_id_old,int scan_id_new);
static void HandleCheckEvent(Eventinfo *lf,int *socket,cJSON *event);
static void HandleScanInfo(Eventinfo *lf,int *socket,cJSON *event);
static int CheckEventJSON(cJSON *event,cJSON **scan_id,cJSON **id,cJSON **name,cJSON **title,cJSON **description,cJSON **rationale,cJSON **remediation,cJSON **compliance,cJSON **check,cJSON **reference,cJSON **file,cJSON **directory,cJSON **process,cJSON **registry,cJSON **result);
static void FillCheckEventInfo(Eventinfo *lf,cJSON *scan_id,cJSON *id,cJSON *name,cJSON *title,cJSON *description,cJSON *rationale,cJSON *remediation,cJSON *compliance,cJSON *reference,cJSON *file,cJSON *directory,cJSON *process,cJSON *registry,cJSON *result,char *old_result);
static void FillScanInfo(Eventinfo *lf,cJSON *scan_id,cJSON *name,cJSON *description,cJSON *pass,cJSON *failed,cJSON *score,cJSON *file);
static int pm_send_db(char *msg, char *response, int *sock);

static OSDecoderInfo *rootcheck_json_dec = NULL;

void ConfigurationAssessmentInit()
{

    os_calloc(1, sizeof(OSDecoderInfo), rootcheck_json_dec);
    rootcheck_json_dec->id = getDecoderfromlist(CONFIGURATION_ASSESSMENT_MOD);
    rootcheck_json_dec->type = OSSEC_RL;
    rootcheck_json_dec->name = CONFIGURATION_ASSESSMENT_MOD;
    rootcheck_json_dec->fts = 0;

    mdebug1("ConfigurationAssessmentInit completed.");
}

int DecodeRootcheckJSON(Eventinfo *lf, int *socket)
{
    int ret_val = 1;
    cJSON *json_event = NULL;
    cJSON *type = NULL;
    lf->decoder_info = rootcheck_json_dec;

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
                cJSON_Delete(json_event);
                ret_val = 1;
                return ret_val;
            }
        }
        else if (strcmp(type->valuestring,"check") == 0){
            char *final_evt;
            final_evt = cJSON_PrintUnformatted(json_event);

            HandleCheckEvent(lf,socket,json_event);
            
            lf->decoder_info = rootcheck_json_dec;

            os_free(final_evt);
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } 
        else if (strcmp(type->valuestring,"summary") == 0){
            char *final_evt;
            final_evt = cJSON_PrintUnformatted(json_event);

            HandleScanInfo(lf,socket,json_event);

            lf->decoder_info = rootcheck_json_dec;

            os_free(final_evt);
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

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring query %d", lf->agent_id, pm_id);

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

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring query_scan %s", lf->agent_id, policy_id);

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

static int FindPolicyInfo(Eventinfo *lf, char *policy, int *socket) {

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring query_policy %s", lf->agent_id, policy);

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

static int SaveEventcheck(Eventinfo *lf, int exists, int *socket,int id,int scan_id,char * title,char *description,char *rationale,char *remediation, char * file,char * directory,char * process,char * registry,char * reference,char * result)
{

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if (exists)
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring update %d|%s", lf->agent_id, id, result);
    else
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring insert %d|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s", lf->agent_id,id,scan_id,title,description,rationale,remediation,file,directory,process,registry,reference,result);

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
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring insert_scan_info %d|%d|%d|%s|%d|%d|%d|%s",lf->agent_id,pm_start_scan,pm_end_scan,scan_id,policy_id,pass,failed,score,hash);
    } else {
        snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring update_scan_info_start %s|%d|%d|%d|%d|%d|%d|%s",lf->agent_id, policy_id,pm_start_scan,pm_end_scan,scan_id,pass,failed,score,hash );
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

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring insert_policy %s|%s|%s|%s|%s",lf->agent_id,name,file,id,description,references);
   
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
    cJSON *title;
    cJSON *description;
    cJSON *rationale;
    cJSON *remediation;
    cJSON *check;
    cJSON *compliance;
    cJSON *reference;
    cJSON *file;
    cJSON *directory;
    cJSON *process;
    cJSON *registry;
    cJSON *result;

    if(!CheckEventJSON(event,&scan_id,&id,&name,&title,&description,&rationale,&remediation,&compliance,&check,&reference,&file,&directory,&process,&registry,&result)) {
       
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
                result_event = SaveEventcheck(lf, 1, socket,id->valueint,scan_id ? scan_id->valueint : -1,title ? title->valuestring : NULL,description ? description->valuestring : NULL,rationale ? rationale->valuestring : NULL,remediation ? remediation->valuestring : NULL,file ? file->valuestring : NULL,directory ? directory->valuestring : NULL,process ? process->valuestring : NULL,registry ? registry->valuestring : NULL,reference ? reference->valuestring : NULL,result ? result->valuestring : NULL);
               
                if(strcmp(wdb_response,result->valuestring)) {
                    FillCheckEventInfo(lf,scan_id,id,name,title,description,rationale,remediation,compliance,reference,file,directory,process,registry,result,wdb_response);
                }
                if (result_event < 0)
                {
                    merror("Error updating policy monitoring database for agent %s", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveEventcheck(lf, 0, socket,id->valueint,scan_id ? scan_id->valueint : -1,title ? title->valuestring : NULL,description ? description->valuestring : NULL,rationale ? rationale->valuestring : NULL,remediation ? remediation->valuestring : NULL,file ? file->valuestring : NULL,directory ? directory->valuestring : NULL,process ? process->valuestring : NULL,registry ? registry->valuestring : NULL,reference ? reference->valuestring : NULL,result ? result->valuestring : NULL);

                if(strcmp(wdb_response,result->valuestring)) {
                    FillCheckEventInfo(lf,scan_id,id,name,title,description,rationale,remediation,compliance,reference,file,directory,process,registry,result,NULL);
                }

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
        os_free(wdb_response);
    }
}

static void HandleScanInfo(Eventinfo *lf,int *socket,cJSON *event) {

    cJSON *pm_scan_id;
    cJSON *pm_scan_start;
    cJSON *pm_scan_end;
    cJSON *policy_id;
    cJSON *description;
    cJSON *references;
    cJSON *passed;
    cJSON *failed;
    cJSON *score;
    cJSON *hash;
    cJSON *file;
    cJSON *policy;

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

    if(!pm_scan_id){
        return;
    }

    if(!description){
        return;
    }

    if(!references){
        return;
    }

    if(!pm_scan_start) {
        return;
    }

    if(!pm_scan_end) {
        return;
    }

    if(!passed){
        return;
    }

    if(!failed){
        return;
    }

    if(!score){
        return;
    }

    if(!hash){
        return;
    }

    if(!file){
        return;
    }

    if(!policy){
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

    UpdateCheckScanId(lf,socket,scan_id_old,pm_scan_id->valueint);

    os_free(hash_scan_info);
}

static int CheckEventJSON(cJSON *event,cJSON **scan_id,cJSON **id,cJSON **name,cJSON **title,cJSON **description,cJSON **rationale,cJSON **remediation,cJSON **compliance,cJSON **check,cJSON **reference,cJSON **file,cJSON **directory,cJSON **process,cJSON **registry,cJSON **result) {
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

        *description = cJSON_GetObjectItem(*check, "description");

        *rationale = cJSON_GetObjectItem(*check, "rationale");

        *remediation = cJSON_GetObjectItem(*check, "remediation");

        *reference = cJSON_GetObjectItem(*check, "references");
            
        *compliance = cJSON_GetObjectItem(*check, "compliance");

        *file = cJSON_GetObjectItem(*check, "file");
        *directory = cJSON_GetObjectItem(*check, "directory");
        *process = cJSON_GetObjectItem(*check, "process");
        *registry = cJSON_GetObjectItem(*check, "registry");
        
        if( *result = cJSON_GetObjectItem(*check, "result"), !*result) {
            merror("Malformed JSON: field 'result' not found");
            return retval;
        }
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
            fillData(lf, compliance_key, value);

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
        } else if (failed->valuedouble) {
            sprintf(value, "%lf", score->valuedouble);
        } 

        fillData(lf, "configuration_assessment.score", value);
    }

    if(file){
        fillData(lf, "configuration_assessment.file", file->valuestring);
    }
}

static int UpdateCheckScanId(Eventinfo *lf,int *socket,int scan_id_old,int scan_id_new) {
    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s policy-monitoring update_check_scan %d|%d",lf->agent_id, scan_id_old,scan_id_new);
    
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