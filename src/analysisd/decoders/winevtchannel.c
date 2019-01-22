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

char *replace_win_format(char *str){
    char *ret1 = NULL;
    char *ret2 = NULL;
    char *ret3 = NULL;

    ret1 = wstr_replace(str, "\\r", "");
    ret2 = wstr_replace(ret1, "\\t", "");
    ret3 = wstr_replace(ret2, "\\n", "");

    os_free(ret1);
    os_free(ret2);

    return ret3;
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
    int level_n;
    unsigned long long int keywords_n;
    XML_NODE node, child;
    int num;
    char *extra = NULL;
    char *filtered_string = NULL;
    char *level = NULL;
    char *keywords = NULL;
    char *msg_from_prov = NULL;
    char *returned_event = NULL;
    char *event = NULL;
    char *find_event = NULL;
    char *end_event = NULL;
    char *real_end = NULL;
    char *find_msg = NULL;
    char *end_msg = NULL;
    char *next = NULL;
    char *category = NULL;
    char aux = 0;
    lf->decoder_info = winevt_decoder;

    os_calloc(OS_MAXSTR, sizeof(char), event);
    os_calloc(OS_MAXSTR, sizeof(char), msg_from_prov);

    find_event = strstr(lf->log, "Event");

    if(find_event){
        find_event = find_event + 8;
        end_event = strchr(find_event, '"');

        if(end_event){
            real_end = end_event;
            aux = *(end_event + 1);

            if(aux != '}' && aux != ','){
                while(1){
                    next = real_end + 1;
                    real_end = strchr(next,'"');

                    if(real_end) {
                        aux = *(real_end + 1);
                        if (aux == '}' || aux == ','){
                            end_event = real_end;
                            break;
                        }
                    } else {
                        mdebug1("Malformed 'Event' field");
                        break;
                    }
                }
            }

            num = end_event - find_event;

            if(num > OS_MAXSTR - 1){
                mwarn("The event message has exceeded the maximum size.");
                cJSON_Delete(json_system_in);
                cJSON_Delete(json_event);
                cJSON_Delete(json_eventdata_in);
                cJSON_Delete(json_extra_in);
                ret_val = 1;
                goto cleanup;
            }

            memcpy(event, find_event, num);
            event[num] = '\0';
            find_event = NULL;
            end_event = NULL;
            real_end = NULL;
            next = NULL;
            aux = 0;
        }
    } else {
        mdebug1("Malformed JSON output received. No 'Event' field found");
    }

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
                                        cJSON_AddStringToObject(json_system_in, "ProviderName", child_attr[p]->values[l]);
                                    } else if (!strcmp(child_attr[p]->attributes[l], "Guid")){
                                        cJSON_AddStringToObject(json_system_in, "ProviderGuid", child_attr[p]->values[l]);
                                    } else if (!strcmp(child_attr[p]->attributes[l], "EventSourceName")){
                                        cJSON_AddStringToObject(json_system_in, "EventSourceName", child_attr[p]->values[l]);
                                    }
                                    l++;
                                }
                            } else if (!strcmp(child_attr[p]->element, "TimeCreated")) {
                                if(!strcmp(child_attr[p]->attributes[0], "SystemTime")){
                                    cJSON_AddStringToObject(json_system_in, "SystemTime", child_attr[p]->values[0]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Execution")) {
                                if(!strcmp(child_attr[p]->attributes[0], "ProcessID")){
                                    cJSON_AddStringToObject(json_system_in, "ProcessID", child_attr[p]->values[0]);
                                }
                                if(!strcmp(child_attr[p]->attributes[1], "ThreadID")){
                                    cJSON_AddStringToObject(json_system_in, "ThreadID", child_attr[p]->values[1]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Channel")) {
                                cJSON_AddStringToObject(json_system_in, "Channel", child_attr[p]->content);
                                if(child_attr[p]->attributes && child_attr[p]->values && !strcmp(child_attr[p]->values[0], "UserID")){
                                    cJSON_AddStringToObject(json_system_in, "UserID", child_attr[p]->values[0]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Security")) {
                                if(child_attr[p]->attributes && child_attr[p]->values && !strcmp(child_attr[p]->values[0], "UserID")){
                                    cJSON_AddStringToObject(json_system_in, "SecurityUserID", child_attr[p]->values[0]);
                                }
                            } else if (!strcmp(child_attr[p]->element, "Level")) {
                                if (level){
                                    os_free(level);
                                }
                                os_strdup(child_attr[p]->content, level);
                                cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                            } else if (!strcmp(child_attr[p]->element, "Keywords")) {
                                if (keywords){
                                    os_free(keywords);
                                }
                                os_strdup(child_attr[p]->content, keywords);
                                cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                            } else if (!strcmp(child_attr[p]->element, "Correlation")) {
                            } else {
                                cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                            }

                        } else if (child[j]->element && !strcmp(child[j]->element, "EventData") && child_attr[p]->element){
                            if (!strcmp(child_attr[p]->element, "Data") && child_attr[p]->values){
                                for (l = 0; child_attr[p]->attributes[l]; l++) {
                                    if (!strcmp(child_attr[p]->attributes[l], "Name")) {
                                        filtered_string = replace_win_format(child_attr[p]->content);
                                        cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->values[l], filtered_string);
                                        os_free(filtered_string);
                                        break;
                                    } else if(child_attr[p]->content && strcmp(child_attr[p]->content, "(NULL)") != 0){
                                        filtered_string = replace_win_format(child_attr[p]->content);
                                        mdebug2("Unexpected attribute at EventData (%s).", child_attr[p]->attributes[j]);
                                        cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->values[l], filtered_string);
                                        os_free(filtered_string);
                                    }
                                }
                            } else if (child_attr[p]->content && strcmp(child_attr[p]->content, "(NULL)") != 0){
                                filtered_string = replace_win_format(child_attr[p]->content);
                                cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->element, filtered_string);
                                os_free(filtered_string);
                            }
                        } else {
                            mdebug1("Unexpected element (%s). Decoding it.", child[j]->element);

                            XML_NODE extra_data_child = NULL;
                            extra_data_child = OS_GetElementsbyNode(&xml, child_attr[p]);
                            int h=0;

                            while(extra_data_child && extra_data_child[h]){
                                filtered_string = replace_win_format(extra_data_child[h]->content);
                                cJSON_AddStringToObject(json_extra_in, extra_data_child[h]->element, filtered_string);
                                os_free(filtered_string);
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
                        category = "CRITICAL";
                        break;
                    case ERROR:
                        category = "ERROR";
                        break;
                    case WARNING:
                        category = "WARNING";
                        break;
                    case INFORMATION:
                        category = "INFORMATION";
                        break;
                    case VERBOSE:
                        category = "VERBOSE";
                        break;
                    case AUDIT:
                        if (keywords_n & AUDIT_FAILURE) {
                            category = "AUDIT_FAILURE";
                            break;
                        } else if (keywords_n & AUDIT_SUCCESS) {
                            category = "AUDIT_SUCCESS";
                            break;
                        }
                        // fall through
                    default:
                        category = "UNKNOWN";
                }

                cJSON_AddStringToObject(json_system_in, "SeverityValue", category);
            }
        }
        xml_init = 1;
    }

    find_msg = strstr(lf->log, "Message");
    if(find_msg){
        find_msg = find_msg + 10;
        end_msg = strchr(find_msg,'\"');

        if(end_msg){
            real_end = end_msg;
            aux = *(end_msg + 1);

            if(aux != '}' && aux != ','){
                while(1){
                    next = real_end + 1;
                    real_end = strchr(next,'"');

                    if(real_end){
                        aux = *(real_end + 1);
                        if (aux == '}' || aux == ','){
                            end_msg = real_end;
                            break;
                        }
                    } else {
                        mdebug1("Malformed 'Message' field");
                        break;
                    }
                }
            }

            num = end_msg - find_msg;
            if(num > OS_MAXSTR - 1){
                cJSON_Delete(json_system_in);
                cJSON_Delete(json_event);
                cJSON_Delete(json_eventdata_in);
                cJSON_Delete(json_extra_in);
                mwarn("The event message has exceeded the maximum size.");
                ret_val = 1;
                goto cleanup;
            }
            memcpy(msg_from_prov, find_msg, num);
            msg_from_prov[num] = '\0';
            cJSON_AddStringToObject(json_system_in, "Message", msg_from_prov);

            find_msg = NULL;
            end_msg = NULL;
            real_end = NULL;
            next = NULL;
            aux = 0;
        }
    } else {
        mdebug1("Malformed JSON output received. No 'Message' field found");
        cJSON_AddStringToObject(json_system_in, "Message", "No message");
    }

    if(json_system_in){
        cJSON_AddItemToObject(json_event, "System", json_system_in);
    }
    if (json_eventdata_in){
        cJSON_AddItemToObject(json_event, "EventData", json_eventdata_in);
    }
    if (extra){
        cJSON_AddItemToObject(json_event, extra, json_extra_in);
    } else {
        cJSON_Delete(json_extra_in);
    }

    cJSON_AddItemToObject(final_event, "EventChannel", json_event);

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
    os_free(filtered_string);
    os_free(keywords);
    os_free(msg_from_prov);
    os_free(returned_event);
    if (xml_init){
        OS_ClearXML(&xml);
    }
    cJSON_Delete(final_event);

    return (ret_val);
}
