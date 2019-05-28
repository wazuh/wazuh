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
    winevt_decoder->id = getDecoderfromlist(WINEVT_MOD);
    winevt_decoder->name = WINEVT_MOD;
    winevt_decoder->type = OSSEC_RL;
    winevt_decoder->fts = 0;

    mdebug1("WinevtInit completed.");
}

char *replace_formatting_bytes(const char * string, const char * search, const char * replace) {
    char * result;
    const char * scur;
    const char * snext;
    const char * prev_char;
    const char * snext_search;
    size_t wi = 0;
    size_t zcur;
    size_t znext_search;

    if (!(string && search && replace)) {
        return NULL;
    }

    const size_t ZSEARCH = strlen(search);
    const size_t ZREPLACE = strlen(replace);

    os_malloc(sizeof(char), result);

    scur = string;

    while (snext = strstr(scur, search), snext) {
        // Check if the previous character is not a backslash, which would mean it is not a formatting character
        prev_char = snext - 1;

        if (*prev_char != '\\') {
            zcur = snext - scur;
            os_realloc(result, wi + zcur + ZREPLACE + 1, result);
            memcpy(result + wi, scur, zcur);
            wi += zcur;
            memcpy(result + wi, replace, ZREPLACE);
            wi += ZREPLACE;
            scur = snext + ZSEARCH;
        } else {
            if (snext_search = strstr(snext + ZSEARCH, search), snext_search) {
                znext_search = snext_search - scur;
                os_realloc(result, wi + znext_search + 1, result);
                memcpy(result + wi, scur, znext_search);
                wi += znext_search;
                scur = snext_search;
            }
        }
    }

    zcur = strlen(scur);
    os_realloc(result, wi + zcur + 1, result);
    memcpy(result + wi, scur, zcur);
    wi += zcur;
    result[wi] = '\0';

    return result;
}

char *replace_win_format(char *str, int message){
    char *ret1 = NULL;
    char *ret2 = NULL;
    char *result = NULL;
    char *end = NULL;
    int spaces = 0;

    // Remove undesired characters from the string
    if (message) {
        ret1 = replace_formatting_bytes(str, "\\n", "\n");
        ret2 = replace_formatting_bytes(ret1, "\\r", "\r");
        result = replace_formatting_bytes(ret2, "\\t", "\t");
        os_free(ret1);
        os_free(ret2);
    } else {
        os_strdup(str, result);
    }

    ret1 = wstr_replace(result, "\\\"", "\"");
    os_free(result);
    result = wstr_replace(ret1, "\\\\", "\\");
    os_free(ret1);

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
    cJSON *final_event = cJSON_CreateObject();
    cJSON *json_event = cJSON_CreateObject();
    cJSON *json_system_in = cJSON_CreateObject();
    cJSON *json_eventdata_in = cJSON_CreateObject();
    cJSON *json_extra_in = cJSON_CreateObject();
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

    if (received_event = cJSON_Parse(lf->log), !received_event)
    {
        merror("Malformed EventChannel JSON event");
        ret_val = 1;
        cJSON_Delete(json_event);
        cJSON_Delete(json_system_in);
        cJSON_Delete(json_eventdata_in);
        cJSON_Delete(json_extra_in);
        goto cleanup;
    }

    event = cJSON_PrintUnformatted(cJSON_GetObjectItem(received_event, "Event"));

    if(event){
        if (OS_ReadXMLString(event, &xml) < 0){
            first_time++;
            if (first_time > 1){
                mdebug2("Could not read XML string: '%s'", event);
            } else {
                mwarn("Could not read XML string: '%s'", event);
            }
        } else {
            node = OS_GetElementsbyNode(&xml, NULL);
            int i = 0, l = 0;
            if (node && node[i] && (child = OS_GetElementsbyNode(&xml, node[i]))) {
                int j = 0;

                while (child && child[j]){

                    XML_NODE child_attr = NULL;
                    child_attr = OS_GetElementsbyNode(&xml, child[j]);
                    int p = 0;

                    while (child_attr && child_attr[p]){

                        if(child[j]->element && !strcmp(child[j]->element, "System") && child_attr[p]->element){

                            if (!strcmp(child_attr[p]->element, "Provider")) {
                                while(child_attr[p]->attributes[l]){
                                    if (!strcmp(child_attr[p]->attributes[l], "Name")){
                                        cJSON_AddStringToObject(json_system_in, "providerName", child_attr[p]->values[l]);
                                    } else if (!strcmp(child_attr[p]->attributes[l], "Guid")){
                                        cJSON_AddStringToObject(json_system_in, "providerGuid", child_attr[p]->values[l]);
                                    } else if (!strcmp(child_attr[p]->attributes[l], "EventSourceName")){
                                        cJSON_AddStringToObject(json_system_in, "eventSourceName", child_attr[p]->values[l]);
                                    }
                                    l++;
                                }
                            } else if (!strcmp(child_attr[p]->element, "TimeCreated")) {
                                if(!strcmp(child_attr[p]->attributes[0], "SystemTime")){
                                    cJSON_AddStringToObject(json_system_in, "systemTime", child_attr[p]->values[0]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Execution")) {
                                if(!strcmp(child_attr[p]->attributes[0], "ProcessID")){
                                    cJSON_AddStringToObject(json_system_in, "processID", child_attr[p]->values[0]);
                                }
                                if(!strcmp(child_attr[p]->attributes[1], "ThreadID")){
                                    cJSON_AddStringToObject(json_system_in, "threadID", child_attr[p]->values[1]);
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
                                    os_free(level);
                                }
                                os_strdup(child_attr[p]->content, level);
                                *child_attr[p]->element = tolower(*child_attr[p]->element);
                                cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                            } else if (!strcmp(child_attr[p]->element, "Keywords")) {
                                if (keywords){
                                    os_free(keywords);
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
                                for (l = 0; child_attr[p]->attributes[l]; l++) {
                                    if (!strcmp(child_attr[p]->attributes[l], "Name") && strcmp(child_attr[p]->content, "(NULL)") != 0
                                            && strcmp(child_attr[p]->content, "-") != 0) {
                                        filtered_string = replace_win_format(child_attr[p]->content, 0);
                                        *child_attr[p]->values[l] = tolower(*child_attr[p]->values[l]);

                                        cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->values[l], filtered_string);
                                        os_free(filtered_string);
                                        break;

                                    } else if(child_attr[p]->content && strcmp(child_attr[p]->content, "(NULL)") != 0
                                            && strcmp(child_attr[p]->content, "-") != 0){
                                        filtered_string = replace_win_format(child_attr[p]->content, 0);
                                        mdebug2("Unexpected attribute at EventData (%s).", child_attr[p]->attributes[j]);
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
                                        os_free(join_data2);
                                    }
                                    os_strdup(join_data,join_data2);
                                } else if (strcmp(child_attr[p]->element, "Data")){
                                    *child_attr[p]->element = tolower(*child_attr[p]->element);
                                    cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->element, filtered_string);
                                }

                                os_free(filtered_string);
                            }
                        } else {
                            mdebug1("Unexpected element (%s). Decoding it.", child[j]->element);

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
                            os_strdup(child_attr[p]->element, extra);
                            OS_ClearNode(extra_data_child);
                        }
                        p++;
                    }

                    OS_ClearNode(child_attr);

                    j++;
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
            }
        }
        xml_init = 1;
    }

    find_msg = cJSON_PrintUnformatted(cJSON_GetObjectItem(received_event, "Message"));

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

    if (returned_event){
        lf->full_log[strlen(returned_event)] = '\0';
        memcpy(lf->full_log, returned_event, strlen(returned_event));
    } else {
        lf->full_log = NULL;
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
    os_free(returned_event);
    if (xml_init){
        OS_ClearXML(&xml);
    }
    cJSON_Delete(final_event);
    cJSON_Delete(received_event);

    return (ret_val);
}
