/*
* Copyright (C) 2018 Wazuh Inc.
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

void WinevtInit(){

    os_calloc(1, sizeof(OSDecoderInfo), winevt_decoder);
    winevt_decoder->id = getDecoderfromlist(WINEVT_MOD);
    winevt_decoder->name = WINEVT_MOD;
    winevt_decoder->type = OSSEC_RL;
    winevt_decoder->fts = 0;

    mdebug1("WinevtInit completed.");
}

/* Special decoder for Windows eventchannel */
int DecodeWinevt(Eventinfo *lf){
    OS_XML xml;
    cJSON *final_event = cJSON_CreateObject();
    cJSON *json_event = cJSON_CreateObject();
    cJSON *json_system_in = cJSON_CreateObject();
    cJSON *json_eventdata_in = cJSON_CreateObject();
    int level_n, category;
    unsigned long long int keywords_n;
    XML_NODE node, child;
    size_t num;
    char *level = NULL, *keywords = NULL, *provider_name = NULL,
        *msg_from_prov = NULL, *returned_event = NULL, *event = NULL;
    char *find_event = NULL, *end_event = NULL,
        *find_msg = NULL, *end_msg = NULL;
    char aux = 0;
    lf->decoder_info = winevt_decoder;

    os_malloc(OS_MAXSTR, event);
    os_malloc(OS_MAXSTR, msg_from_prov);

    find_event = strstr(lf->log, "Event");

    if(find_event){
        find_event = find_event + 8;
        end_event = strchr(find_event,'"');
        if(end_event){
            aux = *(end_event + 1);
            if(aux == '}' || aux == ','){
                num = end_event-find_event;
                memcpy(event, find_event, num);
                event[num] = '\0';               
            }
            find_event = '\0';
            end_event = '\0';
            aux = 0;
        }
    } else {
        mdebug1("Malformed JSON output received. No 'Event' field found");
    }

    if(event) {            
        if (OS_ReadXMLString(event, &xml) < 0){
            merror("Could not read XML string: '%s'", event);
        }

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
                                    os_strdup(child_attr[p]->values[l], provider_name);
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
                                cJSON_AddStringToObject(json_system_in, "Security UserID", child_attr[p]->values[0]);
                            }
                        } else if (!strcmp(child_attr[p]->element, "Level")) {
                            os_strdup(child_attr[p]->content, level);
                            cJSON_AddStringToObject(json_system_in, child_attr[p]->element, child_attr[p]->content);
                        } else if (!strcmp(child_attr[p]->element, "Keywords")) {
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
                                    cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->values[l], child_attr[p]->content);
                                    break;
                                } else {
                                    mdebug2("Unexpected attribute at EventData (%s).", child_attr[p]->attributes[j]);
                                    cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->values[l], child_attr[p]->content);
                                }
                            }
                        } else if (child_attr[p]->content){
                            cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->element, child_attr[p]->content);
                        }
                    } else {
                        mdebug1("Unexpected element (%s).", child[j]->element);
                        cJSON_AddStringToObject(json_eventdata_in, child_attr[p]->element, child_attr[p]->content);
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
                    category = 1;
                    break;
                case ERROR:
                    category = 2;
                    break;
                case WARNING:
                    category = 3;
                    break;
                case INFORMATION:
                    category = 4;
                    break;
                case VERBOSE:
                    category = 5;
                    break;
                case AUDIT:
                    if (keywords_n & AUDIT_FAILURE) {
                        category = 6;
                        break;
                    } else if (keywords_n & AUDIT_SUCCESS) {
                        category = 7;
                        break;
                    }
                    // fall through
                default:
                    category = 8;
            }

            cJSON_AddNumberToObject(json_system_in, "SeverityValue", category);    
        }
    }

    find_msg = strstr(lf->log, "Message");
    if(find_msg){
        find_msg = find_msg + 10;
        end_msg = strchr(find_msg,'\"');
        if(end_msg){
            aux = *(end_msg + 1);
            if(aux == '}' || aux == ','){
                num = end_msg-find_msg;
                memcpy(msg_from_prov, find_msg, num);
                msg_from_prov[num] = '\0';
                cJSON_AddStringToObject(json_system_in, "Message", msg_from_prov);
            }
            
            find_msg = '\0';
            end_msg = '\0';
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

    cJSON_AddItemToObject(final_event, "WinEvtChannel", json_event);

    returned_event = cJSON_PrintUnformatted(final_event);
    
    os_strdup(returned_event, lf->full_log);

    free(level);
    free(event);
    free(keywords);
    free(provider_name);
    free(msg_from_prov);
    free(find_event);
    free(end_event);
    free(find_msg);
    free(end_msg);
    free(returned_event);
    OS_ClearXML(&xml);
    cJSON_Delete(final_event);

    return (0);
}