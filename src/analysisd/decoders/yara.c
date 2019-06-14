/*
* Copyright (C) 2015-2019, Wazuh Inc.
* June 05, 2019.
*
* This program is a free software; you can redistribute it
* and/or modify it under the terms of the GNU General Public
* License (version 2) as published by the FSF - Free Software
* Foundation.
*/

/* YARA decoder */

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

/* WDB RESPONSES */
#define WDB_OK              "ok"
#define WDB_ERR             "err"
#define WDB_OK_FOUND        "ok found"
#define WDB_OK_NOT_FOUND    "ok not found"

/* Set handling */
static void HandleSetDataEvent(Eventinfo *lf, int *socket, cJSON *event);
static int CheckSetDataJSON(cJSON *event, cJSON **name, cJSON **description);
static int FindSetDataEvent(Eventinfo *lf, char *name, int *socket);

/* Set rules handling */
static void HandleSetDataRuleEvent(Eventinfo *lf, int *socket, cJSON *event);
static int CheckSetDataRuleJSON(cJSON *event, cJSON **rules);
static int FindSetDataRuleEvent(Eventinfo *lf, char *event, int *socket);
static int DeleteSetDataRuleEvent(Eventinfo *lf, char *set_name, int *socket);

/* Rules handling */
static void HandleRuleEvent(Eventinfo *lf, int *socket, cJSON *event);
static int FindRuleMetadataEvent(Eventinfo *lf, char *rule_id, char *set_name, char *namespace, int *socket);
static int FindRuleStringsEvent(Eventinfo *lf, char *rule_id, char *set_name, char *namespace, int *socket);
static int FindRuleEvent(Eventinfo *lf, char *rule, char *namespace, int *socket);
static int CheckRuleJSON(cJSON *event, cJSON **strings, cJSON **metadata, cJSON **name, cJSON **namespace, cJSON **set_name);

/* Set removal handling */
static void HandleSetsEvent(Eventinfo *lf, int *socket, cJSON *event);
static int CheckSetsJSON(cJSON *event, cJSON **sets);
static int FindSetsEvent(Eventinfo *lf, int *socket, char *wdb_result);
static int DeleteSetEvent(Eventinfo *lf, char *set_name, int *socket);
static int DeleteRulesFromSet(Eventinfo *lf, int *socket, char *setname);
static int DeleteRulesMetadataFromSet(Eventinfo *lf, int *socket, char *setname);
static int DeleteRulesStringsFromSet(Eventinfo *lf, int *socket, char *setname);

/* Save event to DB */
static int SendQuery(Eventinfo *lf, char *query, char *param, char *positive, char *negative, char *wdb_result, int *socket);
static int SaveEvent(Eventinfo *lf, int *socket, char *query, cJSON *event);

static int pm_send_db(char *msg, char *response, int *sock);
static OSDecoderInfo *yara_json_dec = NULL;


void YARAInit() {
    os_calloc(1, sizeof(OSDecoderInfo), yara_json_dec);
    yara_json_dec->id = getDecoderfromlist(YARA_MOD);
    yara_json_dec->type = OSSEC_RL;
    yara_json_dec->name = YARA_MOD;
    yara_json_dec->fts = 0;

    signal(SIGPIPE, SIG_IGN);

    // Ignore SIGPIPE signal to prevent the process from crashing
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &act, NULL);
    
    mdebug1("YARAInit completed.");
}

int DecodeYARA(Eventinfo *lf, int *socket) {
    int ret_val = 1;
    cJSON *json_event = NULL;
   
    lf->decoder_info = yara_json_dec;

    if (json_event = cJSON_Parse(lf->log), !json_event) {
        merror("Malformed configuration assessment JSON event");
        return ret_val;
    }

    cJSON *type = cJSON_GetObjectItem(json_event, "type");

    if (type) {
        if (strcmp(type->valuestring,"set-data") == 0) {
            HandleSetDataEvent(lf, socket, json_event);
            HandleSetDataRuleEvent(lf, socket, json_event);
            lf->decoder_info = yara_json_dec;
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"sets-enabled") == 0) {
            HandleSetsEvent(lf, socket, json_event);
            lf->decoder_info = yara_json_dec;
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"rule-info") == 0) {
            HandleRuleEvent(lf, socket, json_event);
            lf->decoder_info = yara_json_dec;
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

static void HandleSetDataEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);
    
    cJSON *name = NULL;
    cJSON *description = NULL;

    if (!CheckSetDataJSON(event, &name, &description)) {
       
        int result_event = 0;
        int result_db = FindSetDataEvent(lf, name->valuestring, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying yara database for agent %s", lf->agent_id);
                break;
            case 0: // It exists, update
                result_event = SaveEvent(lf, socket, "update_set_data", event);
               
                if (result_event < 0) {
                    merror("Error updating yara database for agent %s", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveEvent(lf, socket, "insert_set_data", event);

                if (result_event < 0) {
                    merror("Error storing yara information for agent %s", lf->agent_id);
                }
                break;
            default:
                break;
        }
    }
}

static int CheckSetDataJSON(cJSON *event, cJSON **name, cJSON **description) {
    assert(event);
    int retval = 1;
    cJSON *obj;

    if ( *name = cJSON_GetObjectItem(event, "name"), !*name) {
        merror("Malformed JSON: field 'name' not found");
        return retval;
    }

    obj = *name;
    if ( !obj->valuestring ) {
        merror("Malformed JSON: field 'name' must be a string");
        return retval;
    }

    if ( *description = cJSON_GetObjectItem(event, "description"), !*name) {
        merror("Malformed JSON: field 'description' not found");
        return retval;
    }

    obj = *description;
    if ( !obj->valuestring ) {
        merror("Malformed JSON: field 'description' must be a string");
        return retval;
    }

    retval = 0;
    return retval;
}

static void HandleSetsEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);
    cJSON *sets = NULL;
    
    if (!CheckSetsJSON(event, &sets)) {
        char *wdb_result = NULL;
        os_calloc(OS_MAXSTR,sizeof(char),wdb_result);
        int result_db = FindSetsEvent(lf, socket, wdb_result);

        if (result_db == -1) {
            merror("Error querying yara database for agent %s", lf->agent_id);
            os_free(wdb_result);
            return;
        }

        char *saveptr = wdb_result; 
        char *set_name;

        while ((set_name = strtok_r(saveptr, ",", &saveptr))) {
            int exists = 0;

            cJSON *set;
            cJSON_ArrayForEach(set,sets) {
                if (set->valuestring) {
                    if (strcmp(set->valuestring, set_name) == 0) {
                        exists = 1;
                        break;
                    }
                }
            }

            if (!exists) {
                int result_delete =  DeleteSetEvent(lf, set_name, socket);

                switch (result_delete)
                {
                    /* Delete data set rules */
                    case 0:
                        DeleteSetDataRuleEvent(lf, set_name, socket);
                        break;

                    default:
                        merror("Unable to purge DB content for set '%s'", set_name);
                        break;
                }
            }
        }

        os_free(wdb_result);
    }
}

static int CheckSetsJSON(cJSON *event, cJSON **sets) {
    assert(event);
    int retval = 1;

    if (*sets = cJSON_GetObjectItem(event, "sets"), !*sets) {
        merror("Malformed JSON: field 'sets' not found");
        return retval;
    }

    retval = 0;
    return retval;
}

static int DeleteSetEvent(Eventinfo *lf, char *set_name, int *socket) {
    assert(lf);
    assert(set_name);
    return SendQuery(lf, "delete_set", set_name, WDB_OK, WDB_ERR, NULL, socket);
}

static void HandleRuleEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);

    cJSON *strings = NULL;
    cJSON *metadata = NULL;
    cJSON *name = NULL;
    cJSON *namespace = NULL;
    cJSON *set_name = NULL;

    if (!CheckRuleJSON(event, &strings, &metadata, &name, &namespace, &set_name)) {
        char *wdb_result = NULL;
        os_calloc(OS_MAXSTR,sizeof(char),wdb_result);
        int result_event = 0;
        int result_db = FindRuleEvent(lf, name->valuestring, namespace->valuestring, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying yara database for agent %s", lf->agent_id);
                break;
            case 1: 
                result_event = SaveEvent(lf, socket, "insert_rule", event);
                // It not exists, insert
                if (result_event < 0) {
                    merror("Error storing yara information for agent %s", lf->agent_id);
                }
                break;
            default:
                break;
        }

        result_db = FindRuleMetadataEvent(lf, name->valuestring, set_name->valuestring, namespace->valuestring, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying yara database for agent %s", lf->agent_id);
                break;
            case 1: 
                result_event = SaveEvent(lf, socket, "insert_rule_metadata", event);
                // It not exists, insert
                if (result_event < 0) {
                    merror("Error storing yara information for agent %s", lf->agent_id);
                }
                break;
            default:
                break;
        }

        result_db = FindRuleStringsEvent(lf, name->valuestring, set_name->valuestring, namespace->valuestring, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying yara database for agent %s", lf->agent_id);
                break;
            case 1: 
                result_event = SaveEvent(lf, socket, "insert_rule_strings", event);
                // It not exists, insert
                if (result_event < 0) {
                    merror("Error storing yara information for agent %s", lf->agent_id);
                }
                break;
            default:
                break;
        }

        os_free(wdb_result);
    }
}

static int FindRuleEvent(Eventinfo *lf, char *rule, char *namespace, int *socket) {
    assert(lf);
    assert(rule);
    assert(namespace);

    char data[OS_MAXSTR] = {0};
    snprintf(data, OS_MAXSTR, "%s|%s", rule, namespace);
    return SendQuery(lf, "query_rule", data, WDB_OK_FOUND, WDB_OK_NOT_FOUND, NULL, socket);
}

static int CheckRuleJSON(cJSON *event, cJSON **strings, cJSON **metadata, cJSON **name, cJSON **namespace, cJSON **set_name) {
    assert(event);
    int retval = 1;
    cJSON *data;
    cJSON *obj;

    if ( data = cJSON_GetObjectItem(event, "data"), !data) {
        merror("Malformed JSON: field 'data' not found");
        return retval;
    }

    if ( *set_name = cJSON_GetObjectItem(event, "set"), !set_name) {
        merror("Malformed JSON: field 'set' not found");
        return retval;
    }

    obj = *set_name;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'set' must be a string");
        return retval;
    }

    if ( *strings = cJSON_GetObjectItem(data, "strings"), !strings) {
        merror("Malformed JSON: field 'strings' not found");
        return retval;
    }

    if ( *metadata = cJSON_GetObjectItem(data, "meta"), !metadata) {
        merror("Malformed JSON: field 'strings' not found");
        return retval;
    }

    if ( *name = cJSON_GetObjectItem(data, "name"), !name) {
        merror("Malformed JSON: field 'name' not found");
        return retval;
    }

    obj = *name;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'name' must be a string");
        return retval;
    }

    if ( *namespace = cJSON_GetObjectItem(data, "namespace"), !namespace) {
        merror("Malformed JSON: field 'namespace' not found");
        return retval;
    }

    obj = *namespace;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'namespace' must be a string");
        return retval;
    }

    retval = 0;
    return retval;
}

static int FindRuleMetadataEvent(Eventinfo *lf, char *rule_id, char *set_name, char *namespace, int *socket) {
    assert(lf);
    assert(rule_id);
    assert(set_name);
    assert(namespace);

    char data[OS_MAXSTR] = {0};
    snprintf(data, OS_MAXSTR, "%s|%s|%s", rule_id, set_name, namespace);
    return SendQuery(lf, "query_rule_metadata", data, WDB_OK_FOUND, WDB_OK_NOT_FOUND, NULL, socket);
}

static int FindRuleStringsEvent(Eventinfo *lf, char *rule_id, char *set_name, char *namespace, int *socket) {
    assert(lf);
    assert(rule_id);
    assert(set_name);
    assert(namespace);

    char data[OS_MAXSTR] = {0};
    snprintf(data, OS_MAXSTR, "%s|%s|%s", rule_id, set_name, namespace);
    return SendQuery(lf, "query_rule_strings", data, WDB_OK_FOUND, WDB_OK_NOT_FOUND, NULL, socket);
}

static int FindSetDataEvent(Eventinfo *lf, char *name, int *socket) {
    assert(lf);
    assert(name);
    return SendQuery(lf, "query", name, WDB_OK_FOUND, WDB_OK_NOT_FOUND, NULL, socket);
}

static int SaveEvent(Eventinfo *lf, int *socket, char *query, cJSON *event) {
    assert(lf);
    assert(event);

    int retval = -1;
    char *json_event = cJSON_PrintUnformatted(event);

    retval = SendQuery(lf, query, json_event, WDB_OK, WDB_ERR, NULL, socket);
    os_free(json_event);

    return retval;
}

static void HandleSetDataRuleEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);
    
    cJSON *rules = NULL;
    cJSON *set_name = NULL;

    set_name = cJSON_GetObjectItem(event, "name");

    if (!CheckSetDataRuleJSON(event, &rules)) {
       
        cJSON *rule = NULL;
        cJSON_ArrayForEach(rule, rules){
            cJSON_AddStringToObject(rule, "set_name", set_name->valuestring);

            /* Delete set rule */
            DeleteSetDataRuleEvent(lf, set_name->valuestring, socket);

            char *rule_event = cJSON_PrintUnformatted(rule);
            int result_event = 0;

            result_event = SaveEvent(lf, socket, "insert_set_data_rule", rule);
            os_free(rule_event);
             
            if (result_event < 0) {
                merror("Error updating yara database for agent %s", lf->agent_id);
            }
        }
    }
}

static int CheckSetDataRuleJSON(cJSON *event, cJSON **rules) {
    assert(event);
    int retval = 1;
    
    if ( *rules = cJSON_GetObjectItem(event, "rules"), !*rules) {
        merror("Malformed JSON: rules 'name' not found");
        return retval;
    }

    cJSON *rule = NULL;
    cJSON_ArrayForEach(rule,*rules) {

        cJSON *path = NULL;
        if (path = cJSON_GetObjectItem(rule, "path"), !path) {
            merror("Malformed JSON: rule 'path' not found");
            return retval;
        }

        if (!path->valuestring) {
            merror("Malformed JSON: field 'path' must be a string");
            return retval;
        }
    }
    
    retval = 0;
    return retval;
}

static int FindSetDataRuleEvent(Eventinfo *lf, char *event, int *socket) {
    assert(lf);
    assert(event);
    return SendQuery(lf, "query_set_get_rule", event, WDB_OK_FOUND, WDB_OK_NOT_FOUND, NULL, socket);
}

static int DeleteSetDataRuleEvent(Eventinfo *lf, char *set_name, int *socket) {
    assert(lf);
    assert(set_name);
    return SendQuery(lf, "delete_set_data_rule", set_name, WDB_OK, WDB_ERR, NULL, socket);
}

static int DeleteRulesFromSet(Eventinfo *lf, int *socket, char *set_name) {
    assert(lf);
    assert(set_name);
    return SendQuery(lf, "delete_rules_from_set", set_name, WDB_OK, WDB_ERR, NULL, socket);
}

static int DeleteRulesMetadataFromSet(Eventinfo *lf, int *socket, char *set_name) {
    assert(lf);
    assert(set_name);
    return SendQuery(lf, "delete_rules_metadata_from_set", set_name, WDB_OK, WDB_ERR, NULL, socket);
}

static int DeleteRulesStringsFromSet(Eventinfo *lf, int *socket, char *set_name) {
    assert(lf);
    assert(set_name);
    return SendQuery(lf, "delete_rules_strings_from_set", set_name, WDB_OK, WDB_ERR, NULL, socket);
}

static int FindSetsEvent(Eventinfo *lf, int *socket, char *wdb_result) {
    assert(lf);
    return SendQuery(lf, "query_sets", "", WDB_OK_FOUND, WDB_OK_NOT_FOUND, wdb_result, socket);
}

static int SendQuery(Eventinfo *lf, char *query, char *param, char *positive, char *negative, char *wdb_result, int *socket) {
    assert(lf);
    assert(query);
    assert(param);
    assert(positive);
    assert(negative);

    char *msg = NULL;
    char *response = NULL;
    int retval = -1;

    os_calloc(OS_MAXSTR, sizeof(char), msg);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    snprintf(msg, OS_MAXSTR - 1, "agent %s yara %s %s", lf->agent_id, query, param);

    if (pm_send_db(msg, response, socket) == 0) {
        int positive_len = strlen(positive);
        int negative_len = strlen(negative);
        if (!strncmp(response, positive, positive_len)) {
            if (wdb_result) {
                char *result = response + positive_len + 1;
                snprintf(wdb_result,OS_MAXSTR,"%s",result);
            }
            retval = 0;
        } else if (!strncmp(response, negative, negative_len)) {
            retval = 1;
        } else {
            retval = -1;
        }
    }

    os_free(response);
    return retval;
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
            mterror(ARGV0, "at pm_send_db(): Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            goto end;
        }
    }

    // Send msg to Wazuh DB
    if (OS_SendSecureTCP(*sock, size + 1, msg) != 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            merror("at pm_send_db(): database socket is full");
        }
        else if (errno == EPIPE)
        {
            // Retry to connect
            merror("at pm_send_db(): Connection with wazuh-db lost. Reconnecting.");
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
    length = OS_RecvSecureTCP(*sock, response, OS_SIZE_6144);
    switch (length)
    {
    case OS_SOCKTERR:
        merror("OS_RecvSecureTCP(): response size is bigger than expected");
        break;
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
