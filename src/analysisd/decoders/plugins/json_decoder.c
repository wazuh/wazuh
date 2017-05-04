/*
* Copyright (C) 2017 Wazuh Inc.
* April 18, 2017.
*
* This program is a free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

#include "../plugin_decoders.h"

#include "shared.h"
#include "eventinfo.h"
#include "../../config.h"
#include "../../external/cJSON/cJSON.h"

static void fillData(Eventinfo *lf, const char *key, const char *value)
{

    if (strcmp(key, "srcip") == 0){
        lf->srcip = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       srcip: '%s'", lf->srcip);
        }
#endif
        return;
    }

    if (strcmp(key, "dstip") == 0){
        lf->dstip = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       dstip: '%s'", lf->dstip);
        }
#endif
    return;
    }

    if (strcmp(key, "dstport") == 0){
        lf->dstport = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       dstport: '%s'", lf->dstport);
        }
#endif
        return;
    }

    if (strcmp(key, "srcport") == 0){
        lf->srcport = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       srcport: '%s'", lf->srcport);
        }
#endif
        return;
    }

    if (strcmp(key, "protocol") == 0){
        lf->protocol = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       protocol: '%s'", lf->protocol);
        }
#endif
        return;
    }

    if (strcmp(key, "action") == 0){
        lf->action = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       action: '%s'", lf->action);
        }
#endif
        return;
    }

    if (strcmp(key, "srcuser") == 0){
        lf->srcuser = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       srcuser: '%s'", lf->srcuser);
        }
#endif
        return;
    }

    if (strcmp(key, "dstuser") == 0){
        lf->dstuser = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       dstuser: '%s'", lf->dstuser);
        }
#endif
        return;
    }

    if (strcmp(key, "id") == 0){
        lf->id = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       id: '%s'", lf->id);
        }
#endif
        return;
    }

    if (strcmp(key, "status") == 0){
        lf->status = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       status: '%s'", lf->status);
        }
#endif
        return;
    }

    if (strcmp(key, "command") == 0){
        lf->command = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       command: '%s'", lf->command);
        }
#endif
        return;
    }

    if (strcmp(key, "url") == 0){
        lf->url = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       url: '%s'", lf->url);
        }
#endif
        return;
    }

    if (strcmp(key, "data") == 0){
        lf->data = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       data: '%s'", lf->data);
        }
#endif
        return;
    }

    if (strcmp(key, "systemname") == 0){
        lf->systemname = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       systemname: '%s'", lf->systemname);
        }
#endif
        return;
    }

    // Dynamic fields
    if (lf->nfields >= Config.decoder_order_size) {
        merror(ARGV0 ": ERROR: too many fields for JSON decoder.");
        return;
    }
#ifdef TESTRULE
    if (!alert_only) {
        print_out("       %s: '%s'", key, value);
    }
#endif
    lf->fields[lf->nfields].key = strdup(key);
    lf->fields[lf->nfields].value = strdup(value);
    lf->nfields++;
}

static void readJSON (cJSON *logJSON, char *parent, Eventinfo *lf)
{
    static const char * VALUE_NULL = "null";
    static const char * VALUE_TRUE = "true";
    static const char * VALUE_FALSE = "false";
    static const char * VALUE_COMMA = ",";

    cJSON *next, *array;
    char *key = NULL;
    char *value = NULL;
    size_t  n;

    while (logJSON) {
        next = logJSON->next;
        if (logJSON->string) {
            if (parent) {
                n = strlen(parent);
                key = malloc(n + strlen(logJSON->string) + 2);
                strcpy(key, parent);
                key[n++] = '.';
                strcpy(key + n, logJSON->string);
            }
            else {
                key = strdup(logJSON->string);
            }
        }

        switch ((logJSON->type)&255) {

            case cJSON_String:
                fillData(lf, key, logJSON->valuestring);
                break;

            case cJSON_Number:
                if ((double)logJSON->valueint == logJSON->valuedouble){
                    char value_char[64];
                    snprintf(value_char, 64, "%i", logJSON->valueint);
                    fillData(lf, key, value_char);
                }
                else{
                    char value_char[64];
                    snprintf(value_char, 64, "%f", logJSON->valuedouble);
                    fillData(lf, key, value_char);
                }
                break;

            case cJSON_Array:
                array = logJSON->child;
                os_malloc(OS_MAXSTR, value);
                *value = '\0';
                size_t n = 0;
                size_t z;
                while (array){
                    if (array->type == cJSON_String) {
                        z = strlen(array->valuestring);
                        if (n + z < OS_MAXSTR) {
                            strcpy(value + n, array->valuestring);
                            n += z;
                        } else {
                            *value = '\0';
                            break;
                        }
                    }
                    else if (array->type == cJSON_Number) {
                        char value_char[64];
                        z = (double)array->valueint == array->valuedouble ? snprintf(value_char, 64, "%i", array->valueint) : snprintf(value_char, 64, "%f", array->valuedouble);

                        if (n + z < OS_MAXSTR) {
                            strcpy(value + n, value_char);
                            n += z;
                        } else {
                            *value = '\0';
                            break;
                        }
                    }
                    else if (array->type == cJSON_NULL) {
                        z = strlen(VALUE_NULL);

                        if (n + z < OS_MAXSTR) {
                            strcpy(value + n, VALUE_NULL);
                            n += z;
                        } else {
                            *value = '\0';
                            break;
                        }
                    }
                    else if (array->type == cJSON_True) {
                        z = strlen(VALUE_TRUE);

                        if (n + z < OS_MAXSTR) {
                            strcpy(value + n, VALUE_TRUE);
                            n += z;
                        } else {
                            *value = '\0';
                            break;
                        }
                    }
                    else if (array->type == cJSON_False) {
                        z = strlen(VALUE_FALSE);

                        if (n + z < OS_MAXSTR) {
                            strcpy(value + n, VALUE_FALSE);
                            n += z;
                        } else {
                            *value = '\0';
                            break;
                        }
                    }

                    z = strlen(VALUE_COMMA);

                    if (n + z < OS_MAXSTR) {
                        strcpy(value + n, VALUE_COMMA);
                        n += z;
                    } else {
                        *value = '\0';
                        break;
                    }

                    array = array->next;
                }

                fillData(lf, key, value);
                cJSON_Delete(array);
                free(value);
                break;

            case cJSON_NULL:
                fillData(lf, key, VALUE_NULL);
                break;

            case cJSON_True:
                fillData(lf, key, VALUE_TRUE);
                break;

            case cJSON_False:
                fillData(lf, key, VALUE_FALSE);
                break;

            case cJSON_Object:
                readJSON (logJSON->child, key, lf);
                break;

        } // switch
        logJSON = next;
        free(key);
    } // while
    cJSON_Delete(next);
}

void *JSON_Decoder_Init()
{
    debug1 ("%s: Initializing JSON decoder.", ARGV0);
    return (NULL);
}

void *JSON_Decoder_Exec(Eventinfo *lf)
{
    cJSON *logJSON;
    logJSON = cJSON_Parse(lf->log);
    if (!logJSON)
        debug2 ("%s: ERROR: Error parsing JSON string. %s", ARGV0, cJSON_GetErrorPtr());
    else
    {
        readJSON (logJSON, NULL, lf);
        cJSON_Delete (logJSON);
    }
    return (NULL);
}
