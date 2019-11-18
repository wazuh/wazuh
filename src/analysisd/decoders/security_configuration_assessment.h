/*
* Copyright (C) 2015-2019, Wazuh Inc.
* November, 2019.
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
#include <time.h>

/** SCA decoder */
OSDecoderInfo *sca_json_dec;

int FindEventcheck(Eventinfo *lf, int pm_id, int *socket, char *wdb_response);
int FindScanInfo(Eventinfo *lf, char *policy_id, int *socket, char *wdb_response);
int FindPolicyInfo(Eventinfo *lf, char *policy, int *socket);
int FindPolicySHA256(Eventinfo *lf, char *policy, int *socket, char *wdb_response);
int FindCheckResults(Eventinfo *lf, char *policy_id, int *socket, char *wdb_response);
int FindPoliciesIds(Eventinfo *lf, int *socket, char *wdb_response);

int DeletePolicy(Eventinfo *lf, char *policy, int *socket);
int DeletePolicyCheck(Eventinfo *lf, char *policy, int *socket);
int DeletePolicyCheckDistinct(Eventinfo *lf, char *policy_id,int scan_id, int *socket);

int SaveEventcheck(Eventinfo *lf, int exists, int *socket, int id , int scan_id, char * result, char *status,
    char *reason, cJSON *event);
int SaveScanInfo(Eventinfo *lf,int *socket, char * policy_id,int scan_id, int pm_start_scan, int pm_end_scan,
    int pass,int failed, int invalid, int total_checks, int score,char * hash,int update);
int SaveCompliance(Eventinfo *lf,int *socket, int id_check, char *key, char *value);
int SaveRules(Eventinfo *lf,int *socket, int id_check, char *type, char *rule);
int SavePolicyInfo(Eventinfo *lf, int *socket, char *name, char *file, char * id, char *description, char *references,
    char *hash_file);

void HandleCheckEvent(Eventinfo *lf, int *socket, cJSON *event);
void HandleScanInfo(Eventinfo *lf, int *socket, cJSON *event);
void HandlePoliciesInfo(Eventinfo *lf, int *socket, cJSON *event);
void HandleDumpEvent(Eventinfo *lf, int *socket, cJSON *event);

int CheckEventJSON(cJSON *event, cJSON **scan_id, cJSON **id, cJSON **name, cJSON **title, cJSON **description,
    cJSON **rationale, cJSON **remediation, cJSON **compliance, cJSON **condition, cJSON **check, cJSON **reference,
    cJSON **file, cJSON **directory, cJSON **process, cJSON **registry, cJSON **result, cJSON **status, cJSON **reason,
    cJSON **policy_id, cJSON **command, cJSON **rules);
int CheckPoliciesJSON(cJSON *event, cJSON **policies);
int CheckDumpJSON(cJSON *event, cJSON **elements_sent, cJSON **policy_id, cJSON **scan_id);

void FillCheckEventInfo(Eventinfo *lf, cJSON *scan_id, cJSON *id, cJSON *name, cJSON *title, cJSON *description,
    cJSON *rationale, cJSON *remediation, cJSON *compliance, cJSON *reference, cJSON *file,
    cJSON *directory, cJSON *process, cJSON *registry, cJSON *result, cJSON *status, cJSON *reason, char *old_result,
    cJSON *command);
void FillScanInfo(Eventinfo *lf, cJSON *scan_id, cJSON *name, cJSON *description, cJSON *pass, cJSON *failed,
    cJSON *invalid, cJSON *total_checks, cJSON *score, cJSON *file, cJSON *policy_id);

void PushDumpRequest(char *agent_id, char *policy_id, int first_scan);
int pm_send_db(char *msg, char *response, int *sock);
void *RequestDBThread();
int ConnectToSecurityConfigurationAssessmentSocket();
int ConnectToSecurityConfigurationAssessmentSocketRemoted();
