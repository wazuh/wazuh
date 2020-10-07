/*
* Copyright (C) 2015-2020, Wazuh Inc.
* April 18, 2017.
*
* This program is free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

#include "../plugin_decoders.h"

#include "shared.h"
#include "eventinfo.h"
#include "../../config.h"
#include "../../external/cJSON/cJSON.h"

void fillData(Eventinfo *lf, const char *key, const char *value)
{

    if (!key)
        return;

    if (strcmp(key, "srcip") == 0){
        os_strdup(value, lf->srcip);
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
        os_strdup(value, lf->dstip);
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
        os_strdup(value, lf->dstport);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       dstport: '%s'", lf->dstport);
        }
#endif
        return;
    }

    if (strcmp(key, "srcport") == 0){
        os_strdup(value, lf->srcport);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       srcport: '%s'", lf->srcport);
        }
#endif
        return;
    }

    if (strcmp(key, "protocol") == 0){
        os_strdup(value, lf->protocol);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       protocol: '%s'", lf->protocol);
        }
#endif
        return;
    }

    if (strcmp(key, "action") == 0){
        os_strdup(value, lf->action);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       action: '%s'", lf->action);
        }
#endif
        return;
    }

    if (strcmp(key, "srcuser") == 0){
        os_strdup(value, lf->srcuser);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       srcuser: '%s'", lf->srcuser);
        }
#endif
        return;
    }

    if (strcmp(key, "dstuser") == 0){
        os_strdup(value, lf->dstuser);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       dstuser: '%s'", lf->dstuser);
        }
#endif
        return;
    }

    if (strcmp(key, "id") == 0){
        os_strdup(value, lf->id);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       id: '%s'", lf->id);
        }
#endif
        return;
    }

    if (strcmp(key, "status") == 0){
        os_strdup(value, lf->status);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       status: '%s'", lf->status);
        }
#endif
        return;
    }

    if (strcmp(key, "command") == 0){
        os_strdup(value, lf->command);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       command: '%s'", lf->command);
        }
#endif
        return;
    }

    if (strcmp(key, "url") == 0){
        os_strdup(value, lf->url);
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

    if (strcmp(key, "extra_data") == 0){
        os_strdup(value, lf->extra_data);
#ifdef TESTRULE
        if (!alert_only) {
            print_out("       extra_data: '%s'", lf->extra_data);
        }
#endif
        return;
    }

    if (strcmp(key, "systemname") == 0){
        os_strdup(value, lf->systemname);
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
    os_strdup(key, lf->fields[lf->nfields].key);
    os_strdup(value, lf->fields[lf->nfields].value);
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
                if (key = malloc(n + strlen(logJSON->string) + 2), key) {
                    strcpy(key, parent);
                    key[n++] = '.';
                    strcpy(key + n, logJSON->string);
                }
            }
            else {
                os_strdup(logJSON->string, key);
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
                if (lf->decoder_info->flags & CSV_STRING) {
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
                } else if (lf->decoder_info->flags & JSON_ARRAY) {
                    value = cJSON_Print(logJSON);
                }

                if (value && *value != '\0') {
                    fillData(lf, key, value);
                }

                os_free(value);
                break;

            case cJSON_NULL:
                if (lf->decoder_info->flags & EMPTY) {
                    fillData(lf, key, VALUE_EMPTY);
                } else if (lf->decoder_info->flags & SHOW_STRING) {
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
    else {
        mdebug2("Decoding JSON: '%.32s'", input);

        const char *jsonErrPtr;
        logJSON = cJSON_ParseWithOpts(input, &jsonErrPtr, 0);
        if (!logJSON)
            mdebug2("Malformed JSON string '%s'", input);
        else
        {
            readJSON (logJSON, NULL, lf);
            cJSON_Delete (logJSON);
        }
    }
    return (NULL);
}
