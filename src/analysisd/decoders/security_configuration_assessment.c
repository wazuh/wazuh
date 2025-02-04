/*
* Copyright (C) 2015, Wazuh Inc.
* December 05, 2018.
*
* This program is free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* Security configuration assessment decoder */

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
#include "wazuhdb_op.h"
#include <time.h>

static int FindEventcheck(Eventinfo *lf, int pm_id, int *socket, char *wdb_response);
static int FindScanInfo(Eventinfo *lf, char *policy_id, int *socket, char *wdb_response);
static int FindPolicyInfo(Eventinfo *lf, char *policy, int *socket);
static int FindPolicySHA256(Eventinfo *lf, char *policy, int *socket, char *wdb_response);
static int FindCheckResults(Eventinfo *lf, char *policy_id, int *socket, char *wdb_response);
static int FindPoliciesIds(Eventinfo *lf, int *socket, char *wdb_response);
static int DeletePolicy(Eventinfo *lf, char *policy, int *socket);
static int DeletePolicyCheck(Eventinfo *lf, char *policy, int *socket);
static int DeletePolicyCheckDistinct(Eventinfo *lf, char *policy_id,int scan_id, int *socket);
static int SaveEventcheck(Eventinfo *lf, int exists, int *socket, int id , int scan_id, char * result,
        char *reason, cJSON *event);
static int SaveScanInfo(Eventinfo *lf,int *socket, char * policy_id,int scan_id, int pm_start_scan, int pm_end_scan,
        int pass,int failed, int invalid, int total_checks, int score,char * hash,int update);
static int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value);
static int SaveRules(Eventinfo *lf,int *socket, int id_check, char *type, char *rule);
static int SavePolicyInfo(Eventinfo *lf, int *socket, char *name, char *file, char * id, char *description, char *references,
        char *hash_file);
static void HandleCheckEvent(Eventinfo *lf, int *socket, cJSON *event);
static void HandleScanInfo(Eventinfo *lf, int *socket, cJSON *event);
static void HandlePoliciesInfo(Eventinfo *lf, int *socket, cJSON *event);
static void HandleDumpEvent(Eventinfo *lf, int *socket, cJSON *event);
static int CheckEventJSON(cJSON *event, cJSON **scan_id, cJSON **id, cJSON **name, cJSON **title, cJSON **description,
        cJSON **rationale, cJSON **remediation, cJSON **compliance, cJSON **condition, cJSON **check, cJSON **reference,
        cJSON **file, cJSON **directory, cJSON **process, cJSON **registry, cJSON **result, cJSON **reason,
        cJSON **policy_id, cJSON **command, cJSON **rules);
static int CheckPoliciesJSON(cJSON *event, cJSON **policies);
static int CheckDumpJSON(cJSON *event, cJSON **elements_sent, cJSON **policy_id, cJSON **scan_id);
static void FillCheckEventInfo(Eventinfo *lf, cJSON *scan_id, cJSON *id, cJSON *name, cJSON *title, cJSON *description,
        cJSON *rationale, cJSON *remediation, cJSON *compliance, cJSON *reference, cJSON *file,
        cJSON *directory, cJSON *process, cJSON *registry, cJSON *result, cJSON *reason, char *old_result,
        cJSON *command);
static void FillScanInfo(Eventinfo *lf, cJSON *scan_id, cJSON *name, cJSON *description, cJSON *pass, cJSON *failed,
        cJSON *invalid, cJSON *total_checks, cJSON *score, cJSON *file, cJSON *policy_id);
static void PushDumpRequest(char *agent_id, char *policy_id, int first_scan);
static void *RequestDBThread();
static int ConnectToSecurityConfigurationAssessmentSocket();
static int ConnectToSecurityConfigurationAssessmentSocketRemoted();
static OSDecoderInfo *sca_json_dec = NULL;

static int cfga_socket;
static int cfgar_socket;

static w_queue_t * request_queue;

void SecurityConfigurationAssessmentInit()
{

    os_calloc(1, sizeof(OSDecoderInfo), sca_json_dec);
    sca_json_dec->id = getDecoderfromlist(SCA_MOD, &os_analysisd_decoder_store);
    sca_json_dec->type = OSSEC_RL;
    sca_json_dec->name = SCA_MOD;
    sca_json_dec->fts = 0;

    request_queue = queue_init(1024);

    w_create_thread(RequestDBThread,NULL);

    mdebug1("SecurityConfigurationAssessmentInit completed.");
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
                mdebug1("Wrong dump request format: '%s'. Expected ':'", msg);
                goto end;
            }

            mdebug1("Database dump request for agent: %s", agent_id);

            if(strcmp(agent_id,"000") == 0) {
                if(ConnectToSecurityConfigurationAssessmentSocket() == 0){
                    if ((rc = OS_SendUnix(cfga_socket, dump_db_msg, 0)) < 0) {
                        /* Error on the socket */
                        if (rc == OS_SOCKTERR) {
                            merror("socketerr (not available)");
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
                if(!ConnectToSecurityConfigurationAssessmentSocketRemoted()) {
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

static int ConnectToSecurityConfigurationAssessmentSocket() {

    if ((cfga_socket = StartMQ(CFGAQUEUE, WRITE, 1)) < 0) {
        mwarn(QUEUE_ERROR, CFGAQUEUE, strerror(errno));
        return -1;
    }

    return 0;
}

static int ConnectToSecurityConfigurationAssessmentSocketRemoted() {

    if ((cfgar_socket = StartMQ(CFGARQUEUE, WRITE, 1)) < 0) {
        mwarn(QUEUE_ERROR, CFGARQUEUE, strerror(errno));
        return -1;
    }

    return 0;
}

int DecodeSCA(Eventinfo *lf, int *socket)
{
    assert(lf);

    int ret_val = 1;
    cJSON *json_event = NULL;
    cJSON *type = NULL;
    lf->decoder_info = sca_json_dec;
    const char *jsonErrPtr;

    if (json_event = cJSON_ParseWithOpts(lf->log, &jsonErrPtr, 0), !json_event)
    {
        merror("Malformed configuration assessment JSON event.");
        return ret_val;
    }

    assert(json_event);

    /* TODO - Check if the event is a final event */
    type = cJSON_GetObjectItem(json_event, "type");

    if(type && cJSON_IsString(type)) {

        if (strcmp(type->valuestring,"check") == 0){
            char *msg_unformatted = cJSON_PrintUnformatted(json_event);

            if (msg_unformatted) {
                mdebug1("Got check event: '%s'", msg_unformatted);
                os_free(msg_unformatted);
            }

            HandleCheckEvent(lf,socket,json_event);

            lf->decoder_info = sca_json_dec;

            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        }
        else if (strcmp(type->valuestring,"summary") == 0){
            char *msg_unformatted = cJSON_PrintUnformatted(json_event);

            if (msg_unformatted) {
                mdebug1("Got summary event: '%s'", msg_unformatted);
                os_free(msg_unformatted);
            }

            HandleScanInfo(lf,socket,json_event);
            lf->decoder_info = sca_json_dec;

            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"policies") == 0){
            char *msg_unformatted = cJSON_PrintUnformatted(json_event);

            if (msg_unformatted) {
                mdebug1("Got policies event: '%s'", msg_unformatted);
                os_free(msg_unformatted);
            }

            HandlePoliciesInfo(lf,socket,json_event);

            lf->decoder_info = sca_json_dec;

            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"dump_end") == 0) {
            char *msg_unformatted = cJSON_PrintUnformatted(json_event);

            if (msg_unformatted) {
                mdebug1("Got dump finished event: '%s'", msg_unformatted);
                os_free(msg_unformatted);
            }

            HandleDumpEvent(lf,socket,json_event);
            lf->decoder_info = sca_json_dec;

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
    assert(lf);
    assert(wdb_response);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca query %d", lf->agent_id, pm_id);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;
}

static int FindScanInfo(Eventinfo *lf, char *policy_id, int *socket,char *wdb_response) {
    assert(lf);
    assert(wdb_response);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Find scan information for policy id: %s",policy_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca query_scan %s", lf->agent_id, policy_id);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;
}

static int FindCheckResults(Eventinfo *lf, char * policy_id, int *socket,char *wdb_response) {
    assert(lf);
    assert(wdb_response);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Find check results for policy id: %s", policy_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca query_results %s", lf->agent_id, policy_id);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;

}

static int FindPoliciesIds(Eventinfo *lf, int *socket,char *wdb_response) {
    assert(lf);
    assert(wdb_response);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Find policies IDs for agent id: %s", lf->agent_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca query_policies ", lf->agent_id);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;
}

static int FindPolicyInfo(Eventinfo *lf, char *policy, int *socket) {
    assert(lf);
    assert(policy);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Find policies IDs for policy '%s', agent id '%s'", policy, lf->agent_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca query_policy %s", lf->agent_id, policy);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;
}

static int FindPolicySHA256(Eventinfo *lf, char *policy, int *socket, char *wdb_response) {
    assert(lf);
    assert(policy);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Find sha256 for policy '%s', agent id '%s'", policy, lf->agent_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca query_policy_sha256 %s", lf->agent_id, policy);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR)) {
        if (!strncmp(response, "ok found", 8)) {
            char *result_checks = response + 9;
            snprintf(wdb_response,OS_MAXSTR,"%s",result_checks);
            retval = 0;
        } else if (!strcmp(response, "ok not found")) {
            retval = 1;
        } else {
            retval = -1;
        }
    }

    free(msg);
    free(response);
    return retval;
}

static int DeletePolicy(Eventinfo *lf, char *policy, int *socket) {
    assert(lf);
    assert(policy);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Deleting policy '%s', agent id '%s'", policy, lf->agent_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca delete_policy %s", lf->agent_id, policy);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;
}

static int DeletePolicyCheck(Eventinfo *lf, char *policy, int *socket) {
    assert(lf);
    assert(policy);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Deleting check for policy '%s', agent id '%s'", policy, lf->agent_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca delete_check %s", lf->agent_id, policy);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;
}

static int DeletePolicyCheckDistinct(Eventinfo *lf, char *policy_id,int scan_id, int *socket) {
    assert(lf);
    assert(policy_id);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Deleting check distinct policy id '%s', agent id '%s'", policy_id, lf->agent_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca delete_check_distinct %s|%d", lf->agent_id, policy_id,scan_id);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
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

    free(msg);
    free(response);
    return retval;
}

static int SaveEventcheck(Eventinfo *lf, int exists, int *socket, int id , int scan_id, char * result, char *reason, cJSON *event)
{

    assert(lf);
    assert(event);

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    if (exists) {
        snprintf(msg, OS_MAXSTR - 1, "agent %s sca update %d|%s|%s|%d", lf->agent_id, id, result ? result : "", reason ? reason : "", scan_id);
    }
    else {
        char *json_event = cJSON_PrintUnformatted(event);
        snprintf(msg, OS_MAXSTR - 1, "agent %s sca insert %s", lf->agent_id, json_event);
        os_free(json_event);
    }

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
    {
        free(msg);
        os_free(response);
        return 0;
    }
    else
    {
        free(msg);
        os_free(response);
        return -1;
    }
}

static int SaveScanInfo(Eventinfo *lf,int *socket, char * policy_id,int scan_id, int pm_start_scan, int pm_end_scan, int pass,int failed, int invalid,int total_checks,int score,char * hash,int update) {
    assert(lf);

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Saving scan info for policy id '%s', agent id '%s'", policy_id, lf->agent_id);

    if(!update) {
        snprintf(msg, OS_MAXSTR - 1, "agent %s sca insert_scan_info %d|%d|%d|%s|%d|%d|%d|%d|%d|%s",lf->agent_id,pm_start_scan,pm_end_scan,scan_id,policy_id,pass,failed,invalid,total_checks,score,hash);
    } else {
        snprintf(msg, OS_MAXSTR - 1, "agent %s sca update_scan_info_start %s|%d|%d|%d|%d|%d|%d|%d|%d|%s",lf->agent_id, policy_id,pm_start_scan,pm_end_scan,scan_id,pass,failed,invalid,total_checks,score,hash );
    }

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
    {
        free(msg);
        os_free(response);
        return 0;
    }
    else
    {
        free(msg);
        os_free(response);
        return -1;
    }
}

static int SavePolicyInfo(Eventinfo *lf,int *socket, char *name,char *file, char * id,char *description,char * references, char *hash_file) {
    assert(lf);

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Saving policy info for policy id '%s', agent id '%s'", id, lf->agent_id);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca insert_policy %s|%s|%s|%s|%s|%s",lf->agent_id,name,file,id,description ? description : "NULL",references ? references : "NULL",hash_file);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
    {
        free(msg);
        os_free(response);
        return 0;
    }
    else
    {
        free(msg);
        os_free(response);
        return -1;
    }
}

static int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value) {
    assert(lf);
    assert(key);
    assert(value);

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Saving compliance key:'%s', value:'%s' for check: %d", key, value, id_check);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca insert_compliance %d|%s|%s",lf->agent_id, id_check,key,value );

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
    {
        free(msg);
        os_free(response);
        return 0;
    }
    else
    {
        free(msg);
        os_free(response);
        return -1;
    }
}

static int SaveRules(Eventinfo *lf,int *socket, int id_check, char *type, char *rule) {
    assert(lf);

    char *msg = NULL;
    char *response = NULL;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    mdebug1("Saving rules for check id '%d'. Rule: %s", id_check, rule);

    snprintf(msg, OS_MAXSTR - 1, "agent %s sca insert_rules %d|%s|%s",lf->agent_id, id_check, type, rule);

    if (!wdbc_query_ex(socket, msg, response, OS_MAXSTR))
    {
        free(msg);
        os_free(response);
        return 0;
    }
    else
    {
        free(msg);
        os_free(response);
        return -1;
    }
}

static void HandleCheckEvent(Eventinfo *lf,int *socket,cJSON *event) {

    assert(lf);
    assert(event);

    cJSON *scan_id = NULL;
    cJSON *id = NULL;
    cJSON *name = NULL;
    cJSON *title = NULL;
    cJSON *description = NULL;
    cJSON *rationale = NULL;
    cJSON *remediation = NULL;
    cJSON *condition = NULL;
    cJSON *check = NULL;
    cJSON *compliance = NULL;
    cJSON *reference = NULL;
    cJSON *file = NULL;
    cJSON *directory = NULL;
    cJSON *process = NULL;
    cJSON *registry = NULL;
    cJSON *command = NULL;
    cJSON *result = NULL;
    cJSON *reason = NULL;
    cJSON *policy_id = NULL;
    cJSON *rules = NULL;

    mdebug1("Checking event JSON fields.");

    if(!CheckEventJSON(event, &scan_id, &id, &name, &title, &description, &rationale,
            &remediation, &compliance, &condition, &check, &reference, &file, &directory,
            &process, &registry, &result, &reason, &policy_id, &command, &rules))
    {

        int result_event = 0;
        char *wdb_response = NULL;
        os_calloc(OS_MAXSTR,sizeof(char),wdb_response);

        mdebug1("Querying database for check id: %d", id->valueint);
        int result_db = FindEventcheck(lf, id->valueint, socket, wdb_response);

        switch (result_db)
        {
            case -1:
                merror("Error querying policy monitoring database for agent '%s'", lf->agent_id);
                break;
            case 0: // It exists, update
                result_event = SaveEventcheck(lf, 1, socket, id->valueint,
                        scan_id ? scan_id->valueint : -1,
                        result ? result->valuestring : NULL,
                        reason ? reason->valuestring : NULL,
                        event
                );

                if (result && strcmp(wdb_response, result->valuestring)) {
                    FillCheckEventInfo(lf, scan_id, id, name, title, description, rationale, remediation,
                        compliance, reference, file, directory, process, registry, result,
                        reason, wdb_response, command);
                }

                if (result_event < 0)
                {
                    merror("Error updating policy monitoring database for agent '%s'", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveEventcheck(lf, 0, socket, id->valueint,
                        scan_id ? scan_id->valueint : -1,
                        result ? result->valuestring : NULL,
                        reason ? reason->valuestring : NULL,
                        event
                );

                if (result && strcmp(wdb_response, result->valuestring)) {
                    FillCheckEventInfo(lf, scan_id, id, name, title, description, rationale, remediation,
                        compliance, reference, file, directory, process, registry, result,
                        reason, NULL, command);
                }

                if (result_event < 0)
                {
                    merror("Error storing policy monitoring information for agent '%s'", lf->agent_id);
                } else {

                    mdebug1("Saving compliance fields to database for event id: %d", id->valueint);

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

                    mdebug1("Saving rules to database for event id: %d", id->valueint);
                    //Save rules
                    cJSON *rule;
                    cJSON_ArrayForEach(rule, rules){
                        if(rule->valuestring){
                            char flag = rule->valuestring[0];
                            char *type = NULL;
                            switch (flag) {
                                case 'f':
                                    os_calloc(5, sizeof(char), type);
                                    strncpy(type, "file", 5);
                                    break;
                                case 'd':
                                    os_calloc(10, sizeof(char), type);
                                    strncpy(type, "directory", 10);
                                    break;
                                case 'r':
                                    os_calloc(9, sizeof(char), type);
                                    strncpy(type, "registry", 9);
                                    break;
                                case 'c':
                                    os_calloc(8, sizeof(char), type);
                                    strncpy(type, "command", 8);
                                    break;
                                case 'p':
                                    os_calloc(8, sizeof(char), type);
                                    strncpy(type, "process", 8);
                                    break;
                                case 'n':
                                    os_calloc(8, sizeof(char), type);
                                    strncpy(type, "numeric", 8);
                                    break;
                                default:
                                    merror("Invalid type: %c", flag);
                                    continue;
                            }

                            SaveRules(lf, socket, id->valueint, type, rule->valuestring);

                            os_free(type);
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

    int alert_data_fill = 0;

    assert(lf);
    assert(event);

    cJSON *pm_scan_id = NULL;
    cJSON *pm_scan_start = NULL;
    cJSON *pm_scan_end = NULL;
    cJSON *policy_id = NULL;
    cJSON *description = NULL;
    cJSON *references = NULL;
    cJSON *passed = NULL;
    cJSON *failed = NULL;
    cJSON *invalid = NULL;
    cJSON *total_checks = NULL;
    cJSON *score = NULL;
    cJSON *hash = NULL;
    cJSON *hash_file = NULL;
    cJSON *file = NULL;
    cJSON *policy = NULL;
    cJSON *first_scan = NULL;
    cJSON *force_alert = NULL;

    pm_scan_id = cJSON_GetObjectItem(event, "scan_id");
    policy_id =  cJSON_GetObjectItem(event, "policy_id");
    description = cJSON_GetObjectItem(event,"description");
    references = cJSON_GetObjectItem(event,"references");
    pm_scan_start = cJSON_GetObjectItem(event,"start_time");
    pm_scan_end = cJSON_GetObjectItem(event,"end_time");
    passed = cJSON_GetObjectItem(event,"passed");
    failed = cJSON_GetObjectItem(event,"failed");
    invalid = cJSON_GetObjectItem(event,"invalid");
    total_checks = cJSON_GetObjectItem(event,"total_checks");
    score = cJSON_GetObjectItem(event,"score");
    hash = cJSON_GetObjectItem(event,"hash");
    hash_file = cJSON_GetObjectItem(event, "hash_file");
    file = cJSON_GetObjectItem(event,"file");
    policy = cJSON_GetObjectItem(event,"name");
    first_scan = cJSON_GetObjectItem(event,"first_scan");
    force_alert = cJSON_GetObjectItem(event,"force_alert");

    if(!policy_id) {
        return;
    }

    if(!policy_id->valuestring) {
        merror("Malformed JSON: field 'policy_id' must be a string.");
        return;
    }

    if(!pm_scan_id){
        return;
    }

    if(!cJSON_IsNumber(pm_scan_id)){
        merror("Malformed JSON: field 'scan_id' must be a number.");
        return;
    }

    if(pm_scan_id->valueint < 0) {
        merror("Malformed JSON: field 'scan_id' cannot be negative.");
        return;
    }

    if(!pm_scan_start) {
        merror("Malformed JSON: field 'start_time' not found.");
        return;
    }

    if(!pm_scan_end) {
        merror("Malformed JSON: field 'end_time' not found.");
        return;
    }

    if(!passed){
        merror("Malformed JSON: field 'passed' not found.");
        return;
    }

    if(!failed){
        merror("Malformed JSON: field 'failed' not found.");
        return;
    }

    if(!invalid){
        merror("Malformed JSON: field 'invalid' not found.");
        return;
    }

    if(!total_checks){
        merror("Malformed JSON: field 'total_checks' not found.");
        return;
    }

    if(!score){
        merror("Malformed JSON: field 'score' not found.");
        return;
    }

    if(!hash){
        merror("Malformed JSON: field 'hash' not found.");
        return;
    }

    if(!hash->valuestring) {
        merror("Malformed JSON: field 'hash' must be a string.");
        return;
    }

    if(!hash_file){
        merror("Malformed JSON: field 'hash_file' not found.");
        return;
    }

    if(!hash_file->valuestring) {
        merror("Malformed JSON: field 'hash_file' must be a string.");
        return;
    }

    if(!file){
        merror("Malformed JSON: field 'file' not found.");
        return;
    }

    if(!file->valuestring) {
        merror("Malformed JSON: field 'file' must be a string.");
        return;
    }

    if(!policy){
        merror("Malformed JSON: field 'policy' not found.");
        return;
    }

    if(!policy->valuestring) {
        merror("Malformed JSON: field 'policy' must be a string.");
        return;
    }


    int result_event = 0;
    char *hash_scan_info = NULL;
    os_sha256 hash_sha256 = {0};
    os_calloc(OS_MAXSTR,sizeof(char),hash_scan_info);

    mdebug1("Retrieving sha256 hash for policy id: %s", policy_id->valuestring);

    int result_db = FindScanInfo(lf,policy_id->valuestring,socket,hash_scan_info);

    int scan_id_old = 0;

    if (sscanf(hash_scan_info, "%64s %d", hash_sha256, &scan_id_old) < 2) {
        mdebug1("Retrieving sha256 hash for policy: '%s'", policy_id->valuestring);
    }

    os_free(hash_scan_info);

    switch (result_db)
    {
        case -1:
            merror("Error querying policy monitoring database for agent '%s'", lf->agent_id);
            break;
        case 0: // It exists, update
            result_event = SaveScanInfo(lf,socket,policy_id->valuestring,pm_scan_id->valueint,pm_scan_start->valueint,pm_scan_end->valueint,passed->valueint,failed->valueint,invalid->valueint,total_checks->valueint,score->valueint,hash->valuestring,1);
            if (result_event < 0)
            {
                merror("Error updating scan policy monitoring database for agent '%s'", lf->agent_id);
            } else {

                /* Compare hash with previous hash */
                if(strcmp(hash_sha256, hash->valuestring)) {
                    if (!first_scan) {
                        FillScanInfo(lf,pm_scan_id,policy,description,passed,failed,invalid,total_checks,score,file,policy_id);
                        alert_data_fill = 1;
                    }
                }

                if (force_alert && !alert_data_fill) {
                    FillScanInfo(lf,pm_scan_id,policy,description,passed,failed,invalid,total_checks,score,file,policy_id);
                }
            }
            break;
        case 1: // It not exists, insert
            result_event = SaveScanInfo(lf,socket,policy_id->valuestring,pm_scan_id->valueint,pm_scan_start->valueint,pm_scan_end->valueint,passed->valueint,failed->valueint,invalid->valueint,total_checks->valueint,score->valueint,hash->valuestring,0);
            if (result_event < 0)
            {
                merror("Error storing scan policy monitoring information for agent '%s'", lf->agent_id);
            } else {

                /* Compare hash with previous hash */
                if(strcmp(hash_sha256, hash->valuestring)) {
                    if (!first_scan) {
                        FillScanInfo(lf,pm_scan_id,policy,description,passed,failed,invalid,total_checks,score,file,policy_id);
                        alert_data_fill = 1;
                    } else {
                        /* Request dump */
                        PushDumpRequest(lf->agent_id,policy_id->valuestring,1);
                    }
                }

                if (force_alert && !alert_data_fill) {
                    FillScanInfo(lf,pm_scan_id,policy,description,passed,failed,invalid,total_checks,score,file,policy_id);
                }
            }

            break;
        default:
            break;
    }

    char *references_db = NULL;
    char *description_db = NULL;
    char *old_hash = NULL;

    result_db = FindPolicyInfo(lf,policy_id->valuestring,socket);

    switch (result_db)
    {
        case -1:
            merror("Error querying policy monitoring database for agent '%s'", lf->agent_id);
            break;
        case 1: // It not exists, insert
            if(references) {
                if(!references->valuestring) {
                    merror("Malformed JSON: field 'references' must be a string");
                    return;
                }
                references_db = references->valuestring;
            }

            if(description) {
                if(!description->valuestring) {
                    merror("Malformed JSON: field 'description' must be a string");
                    return;
                }
                description_db = description->valuestring;
            }
            result_event = SavePolicyInfo(lf,socket,policy->valuestring,file->valuestring,policy_id->valuestring,description_db,references_db,hash_file->valuestring);
            if (result_event < 0)
            {
                merror("Error storing scan policy monitoring information for agent '%s'", lf->agent_id);
            }
            break;
        default:
            os_calloc(OS_MAXSTR, sizeof(char), old_hash);
            if(FindPolicySHA256(lf, policy_id->valuestring, socket, old_hash) == 0){
                if(strcmp(hash_file->valuestring, old_hash)){
                    int delete_status = DeletePolicy(lf, policy_id->valuestring, socket);
                    switch (delete_status) {
                        case 0:
                            /* Delete checks */
                            DeletePolicyCheck(lf, policy_id->valuestring, socket);
                            PushDumpRequest(lf->agent_id, policy_id->valuestring, 1);
                            minfo("Policy '%s' information for agent '%s' is outdated. Requested latest scan results.", policy_id->valuestring, lf->agent_id);
                            break;
                        default:
                            merror("Unable to purge DB content for policy '%s'", policy_id->valuestring);
                            break;
                    }
                }
            }
            os_free(old_hash);
            break;
    }

    char *wdb_response = NULL;
    os_calloc(OS_MAXSTR,sizeof(char),wdb_response);

    result_db = FindCheckResults(lf,policy_id->valuestring,socket,wdb_response);

    switch (result_db)
    {
        case 0:

            /* Integrity check */
            if(strcmp(wdb_response,hash->valuestring)) {
                mdebug1("Scan result integrity failed for policy '%s'. Hash from DB: '%s', hash from summary: '%s'. Requesting DB dump.",
                        policy_id->valuestring, wdb_response, hash->valuestring);
                if (!first_scan) {
                    PushDumpRequest(lf->agent_id,policy_id->valuestring,0);
                } else {
                    PushDumpRequest(lf->agent_id,policy_id->valuestring,1);
                }
            }

            break;
        case 1:

            /* Empty DB */
            mdebug1("Check results DB empty for policy '%s'. Requesting DB dump.",
                    policy_id->valuestring);
            if (!first_scan) {
                PushDumpRequest(lf->agent_id,policy_id->valuestring,0);
            } else {
                PushDumpRequest(lf->agent_id,policy_id->valuestring,1);
            }

            break;
        default:
            merror("Error querying policy monitoring database for agent '%s'", lf->agent_id);
            break;
    }

    os_free(wdb_response);
}

static void HandleDumpEvent(Eventinfo *lf,int *socket,cJSON *event) {
    assert(lf);
    assert(event);

    cJSON *elements_sent = NULL;
    cJSON *policy_id = NULL;
    cJSON *scan_id = NULL;

    mdebug1("Checking dump event JSON fields.");

    if(!CheckDumpJSON(event,&elements_sent,&policy_id,&scan_id)) {

        int result_db = DeletePolicyCheckDistinct(lf, policy_id->valuestring,scan_id->valueint,socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying policy monitoring database for agent '%s'", lf->agent_id);
                break;
            default:
                break;
        }

        /* Check the new sha256 */
        char *wdb_response = NULL;
        os_calloc(OS_MAXSTR,sizeof(char),wdb_response);

        result_db = FindCheckResults(lf,policy_id->valuestring,socket,wdb_response);
        if (!result_db)
        {
            char *hash_scan_info = NULL;
            os_sha256 hash_sha256 = {0};
            os_calloc(OS_MAXSTR,sizeof(char),hash_scan_info);

            int result_db_hash = FindScanInfo(lf,policy_id->valuestring,socket,hash_scan_info);

            if (sscanf(hash_scan_info, "%64s", hash_sha256) < 1) {
                mdebug1("Retrieving sha256 hash while handling dump for policy: '%s'", policy_id->valuestring);
            }

            if(!result_db_hash) {
                /* Integrity check */
                if(strcmp(wdb_response, hash_sha256)) {
                    mdebug1("Scan result integrity failed for policy '%s'. Hash from DB: '%s' hash from summary: '%s'. Requesting DB dump.",
                        policy_id->valuestring, wdb_response, hash_sha256);
                    PushDumpRequest(lf->agent_id,policy_id->valuestring,0);
                }
            }
            os_free(hash_scan_info);
        }
        os_free(wdb_response);
    }
}

static int CheckDumpJSON(cJSON *event,cJSON **elements_sent,cJSON **policy_id,cJSON **scan_id) {
    assert(event);

    int retval = 1;
    cJSON *obj;

    if( *elements_sent = cJSON_GetObjectItem(event, "elements_sent"), !*elements_sent) {
        merror("Malformed JSON: field 'elements_sent' not found.");
        return retval;
    }

    if( *policy_id = cJSON_GetObjectItem(event, "policy_id"), !*policy_id) {
        merror("Malformed JSON: field 'policy_id' not found.");
        return retval;
    }

    obj = *policy_id;
    if( !obj->valuestring ) {
        merror("Malformed JSON: field 'policy_id' must be a string.");
        return retval;
    }

    if( *scan_id = cJSON_GetObjectItem(event, "scan_id"), !*scan_id) {
        merror("Malformed JSON: field 'scan_id' not found.");
        return retval;
    }

    retval = 0;
    return retval;
}

static int CheckEventJSON(cJSON *event, cJSON **scan_id, cJSON **id, cJSON **name, cJSON **title,
        cJSON **description, cJSON **rationale, cJSON **remediation, cJSON **compliance,
        cJSON **condition, cJSON **check, cJSON **reference, cJSON **file, cJSON **directory,
        cJSON **process, cJSON **registry, cJSON **result, cJSON **reason,
        cJSON **policy_id, cJSON **command, cJSON **rules)
{
    assert(event);

    int retval = 1;
    cJSON *obj;

    if( *scan_id = cJSON_GetObjectItem(event, "id"), !*scan_id) {
        merror("Malformed JSON: field 'id' not found.");
        return retval;
    }

    obj = *scan_id;
    if( !obj->valueint ) {
        merror("Malformed JSON: field 'id' must be a number.");
        return retval;
    }

    if( *name = cJSON_GetObjectItem(event, "policy"), !*name) {
        merror("Malformed JSON: field 'policy' not found.");
        return retval;
    }

    obj = *name;
    if( !obj->valuestring ) {
        merror("Malformed JSON: field 'policy' must be a string.");
        return retval;
    }

    if( *policy_id = cJSON_GetObjectItem(event, "policy_id"), !*policy_id) {
        merror("Malformed JSON: field 'policy_id' not found.");
        return retval;
    }

    obj = *policy_id;
    if( !obj->valuestring ) {
        merror("Malformed JSON: field 'policy_id' must be a string.");
        return retval;
    }

    if( *check = cJSON_GetObjectItem(event, "check"), !*check) {
        merror("Malformed JSON: field 'check' not found.");
        return retval;

    } else {

        if( *id = cJSON_GetObjectItem(*check, "id"), !*id) {
            merror("Malformed JSON: field 'id' not found.");
            return retval;
        }

        obj = *id;
        if( !obj->valueint ) {
            merror("Malformed JSON: field 'id' must be a string.");
            return retval;
        }

        if( *title = cJSON_GetObjectItem(*check, "title"), !*title) {
            merror("Malformed JSON: field 'title' not found.");
            return retval;
        }

        obj = *title;
        if( !obj->valuestring ) {
            merror("Malformed JSON: field 'title' must be a string.");
            return retval;
        }

        *description = cJSON_GetObjectItem(*check, "description");

        obj = *description;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'description' must be a string.");
            return retval;
        }

        *rationale = cJSON_GetObjectItem(*check, "rationale");

        obj = *rationale;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'rationale' must be a string.");
            return retval;
        }

        *remediation = cJSON_GetObjectItem(*check, "remediation");

        obj = *remediation;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'remediation' must be a string.");
            return retval;
        }

        *reference = cJSON_GetObjectItem(*check, "references");

        obj = *reference;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'reference' must be a string.");
            return retval;
        }

        *compliance = cJSON_GetObjectItem(*check, "compliance");

        *file = cJSON_GetObjectItem(*check, "file");
        obj = *file;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'file' must be a string.");
            return retval;
        }

        *condition = cJSON_GetObjectItem(*check, "condition");
        obj = *condition;
        if( obj && !obj->valuestring){
            merror ("Malformed JSON: field 'condition' must be a string");
            return retval;
        }

        *directory = cJSON_GetObjectItem(*check, "directory");
        obj = *directory;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'directory' must be a string.");
            return retval;
        }

        *process = cJSON_GetObjectItem(*check, "process");
        obj = *process;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'process' must be a string.");
            return retval;
        }

        *registry = cJSON_GetObjectItem(*check, "registry");
        obj = *registry;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'registry' must be a string.");
            return retval;
        }

        *command = cJSON_GetObjectItem(*check, "command");
        obj = *command;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'command' must be a string.");
            return retval;
        }

        *rules = cJSON_GetObjectItem(*check, "rules");

        *reason = cJSON_GetObjectItem(*check, "reason");
        obj = *reason;
        if( obj && !obj->valuestring ) {
            merror("Malformed JSON: field 'reason' must be a string.");
            return retval;
        }

        if ( *result = cJSON_GetObjectItem(*check, "result"), !*result) {
            *result = cJSON_CreateString("not applicable");
            cJSON_AddItemToObject(*check, "result", *result);
        } else {
            obj = *result;
            if(!obj->valuestring ) {
                merror("Malformed JSON: field 'result' must be a string.");
                return retval;
            }
        }
    }

    retval = 0;
    return retval;
}

static void HandlePoliciesInfo(Eventinfo *lf,int *socket,cJSON *event) {
    assert(lf);
    assert(event);
    cJSON *policies = NULL;

    mdebug1("Checking policy JSON fields.");

    if(!CheckPoliciesJSON(event,&policies)) {

        char *policies_ids = NULL;
        char *p_id;
        char *saveptr;
        os_calloc(OS_MAXSTR, sizeof(char), policies_ids);

        mdebug1("Retrieving policies from database.");

        int result_db = FindPoliciesIds(lf,socket,policies_ids);
        switch (result_db)
        {
            case -1:
                merror("Error querying policy monitoring database for agent '%s'", lf->agent_id);
                break;

            default:
                /* For each policy id, look if we have scanned it */
                p_id = strtok_r(policies_ids, ",", &saveptr);

                while( p_id != NULL ) {

                    int exists = 0;
                    cJSON *policy;
                    cJSON_ArrayForEach(policy,policies) {
                        if(policy->valuestring) {
                            mdebug1("Comparing policy: '%s' '%s'", policy->valuestring, p_id);
                            if(strcmp(policy->valuestring,p_id) == 0) {
                                exists = 1;
                                break;
                            }
                        }
                    }

                    /* This policy is not being scanned anymore, delete it */
                    if(!exists) {
                        mdebug1("Policy id doesn't exist: '%s'. Deleting it.", p_id);
                        int result_delete = DeletePolicy(lf,p_id,socket);

                        switch (result_delete)
                        {
                            case 0:
                                /* Delete checks */
                                DeletePolicyCheck(lf,p_id,socket);
                                break;

                            default:
                                merror("Unable to purge DB content for policy '%s'", p_id);
                                break;
                        }
                    }

                    p_id = strtok_r(NULL, ",", &saveptr);
                }

                break;
        }

        os_free(policies_ids);
    }
}

static int CheckPoliciesJSON(cJSON *event,cJSON **policies) {
    assert(event);
    int retval = 1;

    if( *policies = cJSON_GetObjectItem(event, "policies"), !*policies) {
        merror("Malformed JSON: field 'policies' not found.");
        return retval;
    }

    retval = 0;
    return retval;
}

static void FillCheckEventInfo(Eventinfo *lf, cJSON *scan_id, cJSON *id, cJSON *name, cJSON *title, cJSON *description,
        cJSON *rationale, cJSON *remediation, cJSON *compliance, cJSON *reference, cJSON *file,
        cJSON *directory, cJSON *process, cJSON *registry, cJSON *result, cJSON *reason,
        char *old_result, cJSON *command)
{
    assert(lf);
    fillData(lf, "sca.type", "check");

    if(scan_id) {
        char value[OS_SIZE_128];

        if(scan_id->valueint >= 0){
            sprintf(value, "%d", scan_id->valueint);
        } else if (scan_id->valuedouble) {
             sprintf(value, "%lf", scan_id->valuedouble);
        }
        fillData(lf, "sca.scan_id", value);
    }

    if(name) {
        fillData(lf, "sca.policy", name->valuestring);
    }

    if(id) {
        char value[OS_SIZE_128];

        if(id->valueint){
            sprintf(value, "%d", id->valueint);
        } else if (id->valuedouble) {
             sprintf(value, "%lf", id->valuedouble);
        }

        fillData(lf, "sca.check.id", value);
    }

    if(title) {
        fillData(lf, "sca.check.title", title->valuestring);
    }

    if(description) {
        fillData(lf, "sca.check.description", description->valuestring);
    }

    if(rationale) {
        fillData(lf, "sca.check.rationale", rationale->valuestring);
    }

    if(remediation) {
        fillData(lf, "sca.check.remediation", remediation->valuestring);
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
            snprintf(compliance_key,OS_SIZE_1024,"sca.check.compliance.%s",key);

            if(value) {
                fillData(lf, compliance_key, value);
            } else {
                mdebug1("Could not fill event compliance data, alert not generated.");
            }

            if(free_value) {
                os_free(value);
            }
        }
    }

    if(reference) {
        fillData(lf, "sca.check.references", reference->valuestring);
    }

    char *array_buffer = NULL;

    if(file){
        csv_list_to_json_str_array(file->valuestring, &array_buffer);
        fillData(lf, "sca.check.file", array_buffer);
        os_free(array_buffer);
    }

    if(directory) {
        csv_list_to_json_str_array(directory->valuestring, &array_buffer);
        fillData(lf, "sca.check.directory", array_buffer);
        os_free(array_buffer);
    }

    if(registry) {
        csv_list_to_json_str_array(registry->valuestring, &array_buffer);
        fillData(lf, "sca.check.registry", array_buffer);
        os_free(array_buffer);
    }

    if(process){
        csv_list_to_json_str_array(process->valuestring, &array_buffer);
        fillData(lf, "sca.check.process", array_buffer);
        os_free(array_buffer);
    }

    if(command){
        csv_list_to_json_str_array(command->valuestring, &array_buffer);
        fillData(lf, "sca.check.command", array_buffer);
        os_free(array_buffer);
    }

    if(result) {
        fillData(lf, "sca.check.result", result->valuestring);
    }

    if (reason) {
        fillData(lf, "sca.check.reason", reason->valuestring);
    }

    if(old_result) {
        fillData(lf, "sca.check.previous_result", old_result);
    }
}

static void FillScanInfo(Eventinfo *lf,cJSON *scan_id,cJSON *name,cJSON *description,cJSON *pass,cJSON *failed,cJSON *invalid,cJSON *total_checks,cJSON *score,cJSON *file,cJSON *policy_id) {
    assert(lf);
    fillData(lf, "sca.type", "summary");

    if(scan_id) {
        char value[OS_SIZE_128];

        if(scan_id->valueint >= 0){
            sprintf(value, "%d", scan_id->valueint);
        } else if (scan_id->valuedouble) {
            sprintf(value, "%lf", scan_id->valuedouble);
        } else {
            mdebug1("Unexpected 'sca.scan_id' type: %d.", scan_id->type);
            return;
        }

        fillData(lf, "sca.scan_id", value);
    }

    if(name && cJSON_IsString(name)) {
        fillData(lf, "sca.policy", name->valuestring);
    }

    if(description && cJSON_IsString(description)) {
        fillData(lf, "sca.description", description->valuestring);
    }

    if(policy_id && cJSON_IsString(policy_id)) {
        fillData(lf, "sca.policy_id", policy_id->valuestring);
    }

    if(pass) {
        char value[OS_SIZE_128];

        if(pass->valueint >= 0){
            sprintf(value, "%d", pass->valueint);
        } else if (pass->valuedouble >= 0) {
            sprintf(value, "%lf", pass->valuedouble);
        } else {
            mdebug1("Unexpected 'sca.passed' type: %d", pass->type);
            return;
        }

        fillData(lf, "sca.passed", value);
    }

    if(failed) {
        char value[OS_SIZE_128];

        if(failed->valueint >= 0){
            sprintf(value, "%d", failed->valueint);
        } else if (failed->valuedouble >= 0) {
            sprintf(value, "%lf", failed->valuedouble);
        } else {
            mdebug1("Unexpected 'sca.failed' type: %d", failed->type);
            return;
        }

        fillData(lf, "sca.failed", value);
    }

    if(invalid) {
        char value[OS_SIZE_128];

        if(invalid->valueint >= 0){
            sprintf(value, "%d", invalid->valueint);
        } else if (invalid->valuedouble >= 0) {
            sprintf(value, "%lf", invalid->valuedouble);
        } else {
            mdebug1("Unexpected 'sca.invalid' type: %d", invalid->type);
            return;
        }

        fillData(lf, "sca.invalid", value);
    }

    if(total_checks) {
        char value[OS_SIZE_128];

        if(total_checks->valueint >= 0){
            sprintf(value, "%d", total_checks->valueint);
        } else if (total_checks->valuedouble >= 0) {
            sprintf(value, "%lf", total_checks->valuedouble);
        } else {
            mdebug1("Unexpected 'sca.total_checks' type: %d", total_checks->type);
            return;
        }

        fillData(lf, "sca.total_checks", value);
    }

    if(score) {
        char value[OS_SIZE_128];

        if(score->valueint >= 0){
            sprintf(value, "%d", score->valueint);
        } else if (score->valuedouble >= 0) {
            sprintf(value, "%lf", score->valuedouble);
        } else {
            mdebug1("Unexpected 'sca.score' type: %d", score->type);
            return;
        }

        fillData(lf, "sca.score", value);
    }

    if(file && cJSON_IsString(file)) {
        fillData(lf, "sca.file", file->valuestring);
    }
}

static void PushDumpRequest(char * agent_id, char * policy_id, int first_scan) {
    assert(agent_id);
    assert(policy_id);

    int result;
    char request_db[OS_SIZE_4096 + 1] = {0};

    mdebug1("Requesting dump for policy: %s", policy_id);

    snprintf(request_db,OS_SIZE_4096,"%s:sca-dump:%s:%d",agent_id,policy_id,first_scan);
    char *msg = NULL;

    os_strdup(request_db,msg);

    result = queue_push_ex(request_queue,msg);

    if (result < 0) {
        mwarn("SCA request queue is full.");
        free(msg);
    }
}
