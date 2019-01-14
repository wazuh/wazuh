/*
* Copyright (C) 2015-2019, Wazuh Inc.
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

    if (!key)
        return;

    if (strcmp(key, "srcip") == 0){
        lf->srcip = strdup(value);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       srcip: '%s'", lf->srcip);
        }
#endif

#ifdef LIBGEOIP_ENABLED
    if (!lf->srcgeoip) {
        lf->srcgeoip = GetGeoInfobyIP(lf->srcip);
#ifdef TESTRULE
        if (lf->srcgeoip && !alert_only)
            print_out("       srcgeoip: '%s'", lf->srcgeoip);
#endif
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

#ifdef LIBGEOIP_ENABLED
    if(!lf->dstgeoip) {
        lf->dstgeoip = GetGeoInfobyIP(lf->dstip);
#ifdef TESTRULE
            if (lf->dstgeoip && !alert_only)
                print_out("       dstgeoip: '%s'", lf->dstgeoip);
#endif
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
        os_strdup(value, lf->data);
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
        merror("Too many fields for JSON decoder.");
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
    static const char * VALUE_EMPTY = "";

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
                os_malloc(OS_MAXSTR, value);
                *value = '\0';
                size_t n = 0;
                size_t z;
                for (array = logJSON->child; array; array = array->next){
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
                    } else {
                        continue;
                    }

                    z = strlen(VALUE_COMMA);

                    if (n + z < OS_MAXSTR) {
                        strcpy(value + n, VALUE_COMMA);
                        n += z;
                    } else {
                        *value = '\0';
                        break;
                    }
                }

                if (*value) {
                    fillData(lf, key, value);
                }

                free(value);
                break;

            case cJSON_NULL:
                if (lf->decoder_info->flags == EMPTY) {
                    fillData(lf, key, VALUE_EMPTY);
                } else if (lf->decoder_info->flags == SHOW_STRING) {
                    fillData(lf, key, VALUE_NULL);
                }
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
        free (key);
        key = NULL;
    } // while

}

void *JSON_Decoder_Init()
{
    mdebug1 ("Initializing JSON decoder.");
    return (NULL);
}

void *JSON_Decoder_Exec(Eventinfo *lf, __attribute__((unused)) regex_matching *decoder_match)
{
    cJSON *logJSON;
    const char * input;

    switch (lf->decoder_info->plugin_offset) {
    case 0:
        input = lf->log;
        break;
    case AFTER_PARENT:
        input = lf->log_after_parent;
        break;
    case AFTER_PREMATCH:
        input = lf->log_after_prematch;
        break;
    default:
        merror("At JSON Decoder: invalid offset value.");
        input = NULL;
    }

    if (!input) {
        mdebug1("JSON decoder: null input (offset = %hu)", lf->decoder_info->plugin_offset);
    }

    mdebug2("Decoding JSON: '%.32s'", input);

    logJSON = cJSON_Parse(input);
    if (!logJSON)
        mdebug2("Malformed JSON string '%s', near '%.20s'", input, cJSON_GetErrorPtr());
    else
    {
        readJSON (logJSON, NULL, lf);
        cJSON_Delete (logJSON);
    }
    return (NULL);
}
