/*
* Copyright (C) 2015, Wazuh Inc.
* December 05, 2018.
*
* This program is free software; you can redistribute it
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
#define AUDIT		0
#define CRITICAL	1
#define ERROR		2
#define WARNING	    3
#define INFORMATION	4
#define VERBOSE	    5

/* Audit types */
#define AUDIT_FAILURE 0x10000000000000LL
#define AUDIT_SUCCESS 0x20000000000000LL

static OSDecoderInfo *winevt_decoder = NULL;
static int first_time = 0;

void WinevtInit(){

    os_calloc(1, sizeof(OSDecoderInfo), winevt_decoder);
    winevt_decoder->id = getDecoderfromlist(WINEVT_MOD, &os_analysisd_decoder_store);
    winevt_decoder->name = WINEVT_MOD;
    winevt_decoder->type = OSSEC_RL;
    winevt_decoder->fts = 0;

    mdebug1("WinevtInit completed.");
}

void WinevtHotReload()
{
    if (winevt_decoder)
    {
        winevt_decoder->id = getDecoderfromlist(WINEVT_MOD, &os_analysisd_decoder_store);
        winevt_decoder->fts = 0;
        mdebug1("WinevtHotReload completed.");
    }
    else
    {
        mdebug1("Winevt decoder not initialized.");
    }
}

char *replace_win_format(char *str, int message){
    char *result = NULL;
    char *end = NULL;
    int spaces = 0;

    // Remove undesired characters from the string
    if (message) {
        result = wstr_unescape_json(str);
    } else {
        os_strdup(str, result);
    }

    // Remove trailing spaces at the end of the string
    end = result + strlen(result) - 1;
    while(end > result && isspace((unsigned char)*end)) {
        end--;
        spaces = 1;
    }

    if(spaces)
        end[1] = '\0';

    return result;
}

/* Special decoder for Windows eventchannel */
int DecodeWinevt(Eventinfo *lf){
    OS_XML xml;
    int xml_init = 0;
    int ret_val = 0;
    char *categoryId = NULL;
    char *subcategoryId = NULL;
    char *auditPolicyChangesId = NULL;
    cJSON *final_event = cJSON_CreateObject();
    cJSON *json_event = cJSON_CreateObject();
    cJSON *json_system_in = cJSON_CreateObject();
    cJSON *json_eventdata_in = cJSON_CreateObject();
    cJSON *json_extra_in = cJSON_CreateObject();
    cJSON *json_received_event = NULL;
    cJSON *json_find_msg = NULL;
    cJSON *received_event = NULL;
    int level_n;
    unsigned long long int keywords_n;
    XML_NODE node, child;
    char *extra = NULL;
    char *filtered_string = NULL;
    char *level = NULL;
    char *keywords = NULL;
    char *msg_from_prov = NULL;
    char *returned_event = NULL;
    char *event = NULL;
    char *find_msg = NULL;
    char *severityValue = NULL;
    char *join_data = NULL;
    char *join_data2 = NULL;
    lf->decoder_info = winevt_decoder;

    os_calloc(OS_MAXSTR, sizeof(char), msg_from_prov);
    os_calloc(OS_MAXSTR, sizeof(char), join_data);

    // force a clean event
    lf->program_name = NULL;
    lf->dec_timestamp = NULL;

    const char *jsonErrPtr;

    if (received_event = cJSON_ParseWithOpts(lf->log, &jsonErrPtr, 0), !received_event) {
        merror("Malformed EventChannel JSON event.");
        ret_val = 1;
        cJSON_Delete(json_event);
        cJSON_Delete(json_system_in);
        cJSON_Delete(json_eventdata_in);
        cJSON_Delete(json_extra_in);
        goto cleanup;
    }

    json_received_event = cJSON_GetObjectItem(received_event, "Event");

    if(json_received_event == NULL) {
        mdebug1("Malformed JSON received. No 'Event' field found.");
        ret_val = 1;
        cJSON_Delete(json_event);
        cJSON_Delete(json_system_in);
        cJSON_Delete(json_eventdata_in);
        cJSON_Delete(json_extra_in);
        goto cleanup;
    }

    event = cJSON_PrintUnformatted(json_received_event);

    if(event){
        if (OS_ReadXMLString(event, &xml) < 0){
            first_time++;
            if (first_time > 1){
                mdebug2("Could not read XML string: '%s'", event);
            } else {
                mwarn("Could not read XML string: '%s'", event);
            }
            OS_ClearXML(&xml);
        } else {
            node = OS_GetElementsbyNode(&xml, NULL);

            if (node && node[0] && (child = OS_GetElementsbyNode(&xml, node[0]))) {
                for (int j = 0; child && child[j]; j++){

                    XML_NODE child_attr = NULL;
                    child_attr = OS_GetElementsbyNode(&xml, child[j]);

                    for (int p = 0; child_attr && child_attr[p]; p++) {

                        if(child[j]->element && !strcmp(child[j]->element, "System") && child_attr[p]->element){

                            if (!strcmp(child_attr[p]->element, "Provider") && child_attr[p]->attributes != NULL) {
                                for (int l = 0; child_attr[p]->attributes[l]; l++) {
                                    if (!strcmp(child_attr[p]->attributes[l], "Name")){
                                        cJSON_AddStringToObject(json_system_in, "providerName", child_attr[p]->values[l]);
                                    } else if (!strcmp(child_attr[p]->attributes[l], "Guid")){
                                        cJSON_AddStringToObject(json_system_in, "providerGuid", child_attr[p]->values[l]);
                                    } else if (!strcmp(child_attr[p]->attributes[l], "EventSourceName")){
                                        cJSON_AddStringToObject(json_system_in, "eventSourceName", child_attr[p]->values[l]);
                                    }
                                }
                            } else if (!strcmp(child_attr[p]->element, "TimeCreated") && child_attr[p]->attributes != NULL) {
                                if(!strcmp(child_attr[p]->attributes[0], "SystemTime")){
                                    cJSON_AddStringToObject(json_system_in, "systemTime", child_attr[p]->values[0]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Execution") && child_attr[p]->attributes != NULL) {
                                for (int l = 0; child_attr[p]->attributes[l]; l++) {
                                    if (!strcmp(child_attr[p]->attributes[l], "ProcessID")){
                                        cJSON_AddStringToObject(json_system_in, "processID", child_attr[p]->values[l]);
                                    }
                                    else if (!strcmp(child_attr[p]->attributes[l], "ThreadID")){
                                        cJSON_AddStringToObject(json_system_in, "threadID", child_attr[p]->values[l]);
                                    }
                                }
                            } else if (!strcmp(child_attr[p]->element, "Channel")) {
                                cJSON_AddStringToObject(json_system_in, "channel", child_attr[p]->content);
                                if(child_attr[p]->attributes && child_attr[p]->values && !strcmp(child_attr[p]->values[0], "UserID")){
                                    cJSON_AddStringToObject(json_system_in, "userID", child_attr[p]->values[0]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Security")) {
                                if(child_attr[p]->attributes && child_attr[p]->values && !strcmp(child_attr[p]->values[0], "UserID")){
                                    cJSON_AddStringToObject(json_system_in, "securityUserID", child_attr[p]->values[0]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Level")) {
                                if (level){
                                    free(level);
                                }
                                os_strdup(child_attr[p]->content, level);
                                *child_attr[p]->element = tolower(*child_attr[p]->element);
                                cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                            } else if (!strcmp(child_attr[p]->element, "Keywords")) {
                                if (keywords){
                                    free(keywords);
                                }
                                os_strdup(child_attr[p]->content, keywords);
                                *child_attr[p]->element = tolower(*child_attr[p]->element);
                                cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                            } else if (!strcmp(child_attr[p]->element, "Correlation")) {
                            } else if(strlen(child_attr[p]->content) > 0){
                                *child_attr[p]->element = tolower(*child_attr[p]->element);
                                cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                            }
                        } else if (child[j]->element && !strcmp(child[j]->element, "EventData") && child_attr[p]->element){
                            if (!strcmp(child_attr[p]->element, "Data") && child_attr[p]->values && strlen(child_attr[p]->content) > 0){
                                for (int l = 0; child_attr[p]->attributes[l]; l++) {
                                    if (!strcmp(child_attr[p]->attributes[l], "Name") && strcmp(child_attr[p]->content, "(NULL)") != 0
                                            && strcmp(child_attr[p]->content, "-") != 0) {
                                        filtered_string = replace_win_format(child_attr[p]->content, 0);
                                        *child_attr[p]->values[l] = tolower(*child_attr[p]->values[l]);

                                        // Save category ID
                                        if (!strcmp(child_attr[p]->values[l], "categoryId")){
                                            if (categoryId){
                                                free(categoryId);
                                            }
                                            os_strdup(filtered_string, categoryId);

                                        // Save subcategory ID
                                        } else if (!strcmp(child_attr[p]->values[l], "subcategoryId")){
                                            if (subcategoryId){
                                                free(subcategoryId);
                                            }
                                            os_strdup(filtered_string, subcategoryId);
                                        }

                                        // Save Audit Policy Changes
                                        if (!strcmp(child_attr[p]->values[l], "auditPolicyChanges")){
                                            if (auditPolicyChangesId){
                                                free(auditPolicyChangesId);
                                            }
                                            os_strdup(filtered_string, auditPolicyChangesId);
                                            cJSON_AddStringToObject(json_eventdata_in, "auditPolicyChangesId", filtered_string);
                                        } else {
                                            cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->values[l], filtered_string);
                                        }

                                        os_free(filtered_string);
                                        break;

                                    } else if(child_attr[p]->content && strcmp(child_attr[p]->content, "(NULL)") != 0
                                            && strcmp(child_attr[p]->content, "-") != 0){
                                        filtered_string = replace_win_format(child_attr[p]->content, 0);
                                        mdebug2("Unexpected attribute at EventData (%s).", child_attr[p]->attributes[l]);
                                        *child_attr[p]->values[l] = tolower(*child_attr[p]->values[l]);
                                        cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->values[l], filtered_string);
                                        os_free(filtered_string);
                                    }
                                }
                            } else if (child_attr[p]->content && strcmp(child_attr[p]->content, "(NULL)") != 0
                                    && strcmp(child_attr[p]->content, "-") != 0 && strlen(child_attr[p]->content) > 0){
                                filtered_string = replace_win_format(child_attr[p]->content, 0);

                                if (strcmp(filtered_string, "") && !strcmp(child_attr[p]->element, "Data")){
                                    if(strcmp(join_data, "")){
                                        snprintf(join_data, strlen(join_data) + strlen(filtered_string) + 3, "%s, %s", join_data2, filtered_string);
                                    } else {
                                        snprintf(join_data, strlen(filtered_string) + 1, "%s", filtered_string);
                                    }
                                    if (join_data2){
                                        free(join_data2);
                                    }
                                    os_strdup(join_data,join_data2);
                                } else if (strcmp(child_attr[p]->element, "Data")){
                                    *child_attr[p]->element = tolower(*child_attr[p]->element);
                                    cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->element, filtered_string);
                                }

                                os_free(filtered_string);
                            }
                        } else {
                            if (child[j]->element) {
                                mdebug1("Unexpected element (%s). Decoding it.", child[j]->element);
                            } else {
                                mdebug1("Unexpected element. Decoding it.");
                            }

                            XML_NODE extra_data_child = NULL;
                            extra_data_child = OS_GetElementsbyNode(&xml, child_attr[p]);
                            int h=0;

                            while(extra_data_child && extra_data_child[h]){
                                if(strcmp(extra_data_child[h]->content, "(NULL)") != 0 && strcmp(extra_data_child[h]->content, "-") != 0 && strlen(extra_data_child[h]->content) > 0){
                                    filtered_string = replace_win_format(extra_data_child[h]->content, 0);
                                    *extra_data_child[h]->element = tolower(*extra_data_child[h]->element);
                                    cJSON_AddStringToObject(json_extra_in, extra_data_child[h]->element, filtered_string);
                                    os_free(filtered_string);
                                }
                                h++;
                            }
                            if(extra){
                                os_free(extra);
                            }
                            if (child_attr[p]->element) {
                                os_strdup(child_attr[p]->element, extra);
                            }
                            OS_ClearNode(extra_data_child);
                        }
                    }

                    OS_ClearNode(child_attr);
                }

                OS_ClearNode(child);
            }

            OS_ClearNode(node);
            OS_ClearXML(&xml);

            if(level && keywords){
                level_n = strtol(level, NULL, 10);
                keywords_n = strtoull(keywords, NULL, 16);

                switch (level_n) {
                    case CRITICAL:
                        severityValue = "CRITICAL";
                        break;
                    case ERROR:
                        severityValue = "ERROR";
                        break;
                    case WARNING:
                        severityValue = "WARNING";
                        break;
                    case INFORMATION:
                        severityValue = "INFORMATION";
                        break;
                    case VERBOSE:
                        severityValue = "VERBOSE";
                        break;
                    case AUDIT:
                        if (keywords_n & AUDIT_FAILURE) {
                            severityValue = "AUDIT_FAILURE";
                            break;
                        } else if (keywords_n & AUDIT_SUCCESS) {
                            severityValue = "AUDIT_SUCCESS";
                            break;
                        }
                        // fall through
                    default:
                        severityValue = "UNKNOWN";
                }

                cJSON_AddStringToObject(json_system_in, "severityValue", severityValue);

                // Event category, subcategory and Audit Policy Changes

                if (categoryId && subcategoryId){

                    char *category = NULL;
                    char *subcategory = NULL;
                    int categoryId_n;
                    int subcategoryId_n;
                    char * filtered_categoryId = wstr_replace(categoryId, "%%", "");
                    char * filtered_subcategoryId = wstr_replace(subcategoryId, "%%", "");

                    categoryId_n = strtol(filtered_categoryId, NULL, 10);
                    subcategoryId_n = strtol(filtered_subcategoryId, NULL, 10);

                    switch (categoryId_n) {
                        case 8272:
                            category = "System";
                            switch (subcategoryId_n) {
                                case 12288:
                                    subcategory = "Security State Change";
                                    break;
                                case 12289:
                                    subcategory = "Security System Extension";
                                    break;
                                case 12290:
                                    subcategory = "System Integrity";
                                    break;
                                case 12291:
                                    subcategory = "IPsec Driver";
                                    break;
                                case 12292:
                                    subcategory = "Other System Events";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8273:
                            category = "Logon/Logoff";
                            switch (subcategoryId_n) {
                                case 12544:
                                    subcategory = "Logon";
                                    break;
                                case 12545:
                                    subcategory = "Logoff";
                                    break;
                                case 12546:
                                    subcategory = "Account Lockout";
                                    break;
                                case 12547:
                                    subcategory = "IPsec Main Mode";
                                    break;
                                case 12548:
                                    subcategory = "Special Logon";
                                    break;
                                case 12549:
                                    subcategory = "IPSec Extended Mode";
                                    break;
                                case 12550:
                                    subcategory = "IPSec Quick Mode";
                                    break;
                                case 12551:
                                    subcategory = "Other Logon/Logoff Events";
                                    break;
                                case 12552:
                                    subcategory = "Network Policy Server";
                                    break;
                                case 12553:
                                    subcategory = "User/Device Claims";
                                    break;
                                case 12554:
                                    subcategory = "Group Membership";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8274:
                            category = "Object Access";
                            switch (subcategoryId_n) {
                                case 12800:
                                    subcategory = "File System";
                                    break;
                                case 12801:
                                    subcategory = "Registry";
                                    break;
                                case 12802:
                                    subcategory = "Kernel Object";
                                    break;
                                case 12803:
                                    subcategory = "SAM";
                                    break;
                                case 12804:
                                    subcategory = "Other Object Access Events";
                                    break;
                                case 12805:
                                    subcategory = "Certification Services";
                                    break;
                                case 12806:
                                    subcategory = "Application Generated";
                                    break;
                                case 12807:
                                    subcategory = "Handle Manipulation";
                                    break;
                                case 12808:
                                    subcategory = "File Share";
                                    break;
                                case 12809:
                                    subcategory = "Filtering Platform Packet Drop";
                                    break;
                                case 12810:
                                    subcategory = "Filtering Platform Connection";
                                    break;
                                case 12811:
                                    subcategory = "Detailed File Share";
                                    break;
                                case 12812:
                                    subcategory = "Removable Storage";
                                    break;
                                case 12813:
                                    subcategory = "Central Policy Staging";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8275:
                            category = "Privilege Use";
                            switch (subcategoryId_n) {
                                case 13056:
                                    subcategory = "Sensitive Privilege Use";
                                    break;
                                case 13057:
                                    subcategory = "Non Sensitive Privilege Use";
                                    break;
                                case 13058:
                                    subcategory = "Other Privilege Use Events";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8276:
                            category = "Detailed Tracking";
                            switch (subcategoryId_n) {
                                case 13312:
                                    subcategory = "Process Creation";
                                    break;
                                case 13313:
                                    subcategory = "Process Termination";
                                    break;
                                case 13314:
                                    subcategory = "DPAPI Activity";
                                    break;
                                case 13315:
                                    subcategory = "RPC Events";
                                    break;
                                case 13316:
                                    subcategory = "Plug and Play Events";
                                    break;
                                case 13317:
                                    subcategory = "Token Right Adjusted Events";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8277:
                            category = "Policy Change";
                            switch (subcategoryId_n) {
                                case 13568:
                                    subcategory = "Audit Policy Change";
                                    break;
                                case 13569:
                                    subcategory = "Authentication Policy Change";
                                    break;
                                case 13570:
                                    subcategory = "Authorization Policy Change";
                                    break;
                                case 13571:
                                    subcategory = "MPSSVC Rule-Level Policy Change";
                                    break;
                                case 13572:
                                    subcategory = "Filtering Platform Policy Change";
                                    break;
                                case 13573:
                                    subcategory = "Other Policy Change Events";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8278:
                            category = "Account Management";
                            switch (subcategoryId_n) {
                                case 13824:
                                    subcategory = "User Account Management";
                                    break;
                                case 13825:
                                    subcategory = "Computer Account Management";
                                    break;
                                case 13826:
                                    subcategory = "Security Group Management";
                                    break;
                                case 13827:
                                    subcategory = "Distribution Group Management";
                                    break;
                                case 13828:
                                    subcategory = "Application Group Management";
                                    break;
                                case 13829:
                                    subcategory = "Other Account Management Events";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8279:
                            category = "DS Access";
                            switch (subcategoryId_n) {
                                case 14080:
                                    subcategory = "Directory Service Access";
                                    break;
                                case 14081:
                                    subcategory = "Directory Service Changes";
                                    break;
                                case 14082:
                                    subcategory = "Directory Service Replication";
                                    break;
                                case 14083:
                                    subcategory = "Detailed Directory Service Replication";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        case 8280:
                            category = "Account Logon";
                            switch (subcategoryId_n) {
                                case 14336:
                                    subcategory = "Credential Validation";
                                    break;
                                case 14337:
                                    subcategory = "Kerberos Service Ticket Operations";
                                    break;
                                case 14338:
                                    subcategory = "Other Account Logon Events";
                                    break;
                                case 14339:
                                    subcategory = "Kerberos Authentication Service";
                                    break;
                                default:
                                    break;
                            }
                            break;
                        default:
                            break;
                    }
                    if (category) {
                        cJSON_AddStringToObject(json_eventdata_in, "category", category);
                    }
                    if (subcategory) {
                        cJSON_AddStringToObject(json_eventdata_in, "subcategory", subcategory);
                    }

                    os_free(categoryId);
                    os_free(subcategoryId);
                    os_free(filtered_categoryId);
                    os_free(filtered_subcategoryId);
                }
            }

            if (auditPolicyChangesId) {
                int audit_split_n = 0;
                char **audit_split;
                char *audit_pol_changes = NULL;
                char *audit_final_field = NULL;

                char * filtered_changes = wstr_replace(auditPolicyChangesId, "%%", "");
                os_free(auditPolicyChangesId);

                audit_split = OS_StrBreak(',', filtered_changes, 4);

                for (int i = 0; audit_split[i]; i++) {
                    audit_split_n = strtol(audit_split[i], NULL, 10);

                    switch (audit_split_n) {
                        case 8448:
                            wm_strcat(&audit_pol_changes, "Success removed", ',');
                            break;
                        case 8449:
                            wm_strcat(&audit_pol_changes, "Success added", ',');
                            break;
                        case 8450:
                            wm_strcat(&audit_pol_changes, "Failure removed", ',');
                            break;
                        case 8451:
                            wm_strcat(&audit_pol_changes, "Failure added", ',');
                            break;
                        default:
                            break;
                    }
                }
                audit_final_field = wstr_replace(audit_pol_changes, ",", ", ");
                cJSON_AddStringToObject(json_eventdata_in, "auditPolicyChanges", audit_final_field);
                os_free(filtered_changes);
                os_free(audit_pol_changes);
                os_free(audit_final_field);
                free_strarray(audit_split);
            }

            xml_init = 1;
        }
    }

    json_find_msg = cJSON_GetObjectItem(received_event, "Message");

    find_msg = cJSON_PrintUnformatted(json_find_msg);

    if(find_msg){
        filtered_string = replace_win_format(find_msg, 1);
        cJSON_AddStringToObject(json_system_in, "message", filtered_string);
        os_free(find_msg);
    }

    if(json_system_in){
        cJSON_AddItemToObject(json_event, "system", json_system_in);
    }

    if (json_eventdata_in){
        if(strcmp(join_data,"")){
            cJSON_AddStringToObject(json_eventdata_in, "data", join_data);
        }

        cJSON *element;
        int n_elements=0;

        cJSON_ArrayForEach(element, json_eventdata_in){
            n_elements+=1;
        }

        if(n_elements > 0){
            cJSON_AddItemToObject(json_event, "eventdata", json_eventdata_in);
        } else {
            cJSON_Delete(json_eventdata_in);
        }
        cJSON_Delete(element);
    }
    if (extra){
        *extra = tolower(*extra);
        cJSON_AddItemToObject(json_event, extra, json_extra_in);
    } else {
        cJSON_Delete(json_extra_in);
    }

    cJSON_AddItemToObject(final_event, "win", json_event);

    returned_event = cJSON_PrintUnformatted(final_event);

    if (returned_event) {
        free(lf->full_log);
        lf->full_log = returned_event;
    } else {
        lf->full_log[0] = '\0';
    }

    lf->log = lf->full_log;
    lf->decoder_info = winevt_decoder;

    JSON_Decoder_Exec(lf, NULL);

cleanup:
    os_free(level);
    os_free(event);
    os_free(extra);
    os_free(join_data);
    os_free(join_data2);
    os_free(filtered_string);
    os_free(keywords);
    os_free(msg_from_prov);
    os_free(categoryId);
    os_free(subcategoryId);
    os_free(auditPolicyChangesId);
    if (xml_init){
        OS_ClearXML(&xml);
    }
    cJSON_Delete(final_event);
    cJSON_Delete(received_event);

    return (ret_val);
}
