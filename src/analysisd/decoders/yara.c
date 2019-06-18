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

/* Integrity handling */
static void HandleIntegrityEvent(Eventinfo *lf, int *socket, cJSON *event);
static int CheckIntegrityJSON(cJSON *event, cJSON **block_name_l0, cJSON **block_name_l1, cJSON **block_name_l2, cJSON **l0_checksum, cJSON **l1_checksum, cJSON **l2_checksum);

/* Files handling */
static void HandleFileEvent(Eventinfo *lf, int *socket, cJSON *event);
static int FindFileEvent(Eventinfo *lf, char *file, int *socket);
static int CheckFileJSON(cJSON *event, cJSON **file, cJSON **rules_matched, cJSON **level0, cJSON **level1, cJSON **level2, cJSON **checksum_l0, cJSON **checksum_l1, cJSON **checksum_l2);
static void FillFileInfo(Eventinfo *lf, cJSON *file, cJSON *rules_matched);

/* Save event to DB */
static int SendQuery(Eventinfo *lf, char *query, char *param, char *positive, char *negative, char *wdb_result, int *socket);
static int SaveEvent(Eventinfo *lf, int *socket, char *query, cJSON *event);

/* DB request thread */
static void *RequestDB();

static int pm_send_db(char *msg, char *response, int *sock);
static OSDecoderInfo *yara_json_dec = NULL;

/* Communication socket */
static int ConnectToYARASocket();
static int ConnectToYARASocketRemoted();
static int yara_socket;
static int yarar_socket;
static w_queue_t * request_queue;

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

    request_queue = queue_init(1024);

    w_create_thread(RequestDB, NULL);
    
    mdebug1("YARAInit completed.");
}

static void *RequestDB() {

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
                goto end;
            }

            if(strcmp(agent_id,"000") == 0) {
                if(ConnectToYARASocket() == 0){
                    if ((rc = OS_SendUnix(yara_socket, dump_db_msg, 0)) < 0) {
                        /* Error on the socket */
                        if (rc == OS_SOCKTERR) {
                            merror("socketerr (not available).");
                            close(yara_socket);
                        }
                        /* Unable to send. Socket busy */
                        mdebug2("Socket busy, discarding message.");
                    } else {
                        close(yara_socket);
                    }
                }
            } else {
               
                /* Send to agent */
                if(!ConnectToYARASocketRemoted()) {
                    *dump_db_msg_original = ':';

                    if ((rc = OS_SendUnix(yarar_socket, msg, 0)) < 0) {
                        /* Error on the socket */
                        if (rc == OS_SOCKTERR) {
                            merror("socketerr (not available).");
                            close(yarar_socket);
                        }
                        /* Unable to send. Socket busy */
                        mdebug2("Socket busy, discarding message.");
                    } else {
                        close(yarar_socket);
                    }
                }
            }
end:
            os_free(msg);
        }
    }

    return NULL;
}

static int ConnectToYARASocket() {

    if ((yara_socket = StartMQ(YARAQUEUE, WRITE)) < 0) {
        merror(QUEUE_ERROR, YARAQUEUE, strerror(errno));
        return -1;
    }

    return 0;
}

static int ConnectToYARASocketRemoted() {

    if ((yarar_socket = StartMQ(YARARQUEUE, WRITE)) < 0) {
        merror(QUEUE_ERROR, YARARQUEUE, strerror(errno));
        return -1;
    }

    return 0;
}

int DecodeYARA(Eventinfo *lf, int *socket) {
    int ret_val = 1;
    cJSON *json_event = NULL;
   
    lf->decoder_info = yara_json_dec;

    if (json_event = cJSON_Parse(lf->log), !json_event) {
        merror("Malformed YARA JSON event");
        return ret_val;
    }

    cJSON *type = cJSON_GetObjectItem(json_event, "type");

    if (type) {
        if (strcmp(type->valuestring,"set-data") == 0) {
            HandleSetDataEvent(lf, socket, json_event);
            HandleSetDataRuleEvent(lf, socket, json_event);
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"sets-enabled") == 0) {
            HandleSetsEvent(lf, socket, json_event);
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"rule-info") == 0) {
            HandleRuleEvent(lf, socket, json_event);
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"files-integrity") == 0) {
            HandleIntegrityEvent(lf, socket, json_event);
            cJSON_Delete(json_event);
            ret_val = 1;
            return ret_val;
        } else if (strcmp(type->valuestring,"file") == 0) {
            HandleFileEvent(lf, socket, json_event);
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

static void HandleIntegrityEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);

    cJSON *block_name_l0 = NULL;
    cJSON *block_name_l1 = NULL;
    cJSON *block_name_l2 = NULL;
    cJSON *l0_checksum = NULL;
    cJSON *l1_checksum = NULL;
    cJSON *l2_checksum = NULL;

    if (!CheckIntegrityJSON(event, &block_name_l0, &block_name_l1, &block_name_l2, &l0_checksum, &l1_checksum, &l2_checksum)) {
        /* TODO: check if the integrity blocks match the DB integrity */
        /* If not, send a request for DB dump with the required block */
    }
}

static int CheckIntegrityJSON(cJSON *event, cJSON **block_name_l0, cJSON **block_name_l1, cJSON **block_name_l2, cJSON **l0_checksum, cJSON **l1_checksum, cJSON **l2_checksum) {
    assert(event);
    int retval = 1;
    cJSON *obj;

    if ( *block_name_l0 = cJSON_GetObjectItem(event, "block-name-l0"), !block_name_l0) {
        merror("Malformed JSON: field 'block-name-l0' not found");
        return retval;
    }

    obj = *block_name_l0;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'block-name-l0' must be a string");
        return retval;
    }

    if ( *block_name_l1 = cJSON_GetObjectItem(event, "block-name-l1"), !block_name_l1) {
        merror("Malformed JSON: field 'block-name-l1' not found");
        return retval;
    }
    
    obj = *block_name_l1;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'block-name-1' must be a string");
        return retval;
    }

    if ( *block_name_l2 = cJSON_GetObjectItem(event, "block-name-l2"), !block_name_l2) {
        merror("Malformed JSON: field 'block-name-l2' not found");
        return retval;
    }
    
    obj = *block_name_l2;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'block-name-2' must be a string");
        return retval;
    }


    if ( *l0_checksum = cJSON_GetObjectItem(event, "block-checksum-l0"), !l0_checksum) {
        merror("Malformed JSON: field 'block-checksum-l0' not found");
        return retval;
    }

    obj = *l0_checksum;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'block-checksum-l0' must be a string");
        return retval;
    }

    if ( *l1_checksum = cJSON_GetObjectItem(event, "block-checksum-l1"), !l1_checksum) {
        merror("Malformed JSON: field 'block-checksum-l1' not found");
        return retval;
    }

    obj = *l1_checksum;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'block-checksum-l1' must be a string");
        return retval;
    }

    if ( *l2_checksum = cJSON_GetObjectItem(event, "block-checksum-l2"), !l2_checksum) {
        merror("Malformed JSON: field 'block-checksum-l2' not found");
        return retval;
    }

    obj = *l2_checksum;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'block-checksum-l2' must be a string");
        return retval;
    }

    retval = 0;
    return retval;
}

static void HandleFileEvent(Eventinfo *lf, int *socket, cJSON *event) {
    assert(lf);
    assert(event);

    cJSON *file = NULL;
    cJSON *rules_matched = NULL;
    cJSON *block_name_l0 = NULL;
    cJSON *block_name_l1 = NULL;
    cJSON *block_name_l2 = NULL;
    cJSON *l0_checksum = NULL;
    cJSON *l1_checksum = NULL;
    cJSON *l2_checksum = NULL;


    if (!CheckFileJSON(event, &file, &rules_matched, &block_name_l0, &block_name_l1, &block_name_l2, &l0_checksum, &l1_checksum, &l2_checksum)) {
        int result_event = 0;
        int result_db = FindFileEvent(lf, file->valuestring, socket);

        switch (result_db)
        {
            case -1:
                merror("Error querying yara database for agent %s", lf->agent_id);
                break;
            case 0: // It exists, update
                result_event = SaveEvent(lf, socket, "update_file", event);
               
                if (result_event < 0) {
                    merror("Error updating yara database for agent %s", lf->agent_id);
                }
                break;
            case 1: // It not exists, insert
                result_event = SaveEvent(lf, socket, "insert_file", event);

                if (result_event < 0) {
                    merror("Error storing yara information for agent %s", lf->agent_id);
                }
                break;
            default:
                break;
        }

        FillFileInfo(lf, file, rules_matched);
    }
}

static int CheckFileJSON(cJSON *event, cJSON **file, cJSON **rules_matched, cJSON **level0, cJSON **level1, cJSON **level2, cJSON **checksum_l0, cJSON **checksum_l1, cJSON **checksum_l2) {
    assert(event);
    int retval = 1;
    cJSON *obj;

    if ( *file = cJSON_GetObjectItem(event, "file-name"), !file) {
        merror("Malformed JSON: field 'block-name-l0' not found");
        return retval;
    }

    obj = *file;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'file-name' must be a string");
        return retval;
    }

    if ( *rules_matched = cJSON_GetObjectItem(event, "rules-matched"), !rules_matched) {
        merror("Malformed JSON: field 'rules-matched' not found");
        return retval;
    }

    obj = *file;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'rules-matched' must be a string");
        return retval;
    }

    if ( *level0 = cJSON_GetObjectItem(event, "level0"), !level0) {
        merror("Malformed JSON: field 'level0' not found");
        return retval;
    }

    obj = *level0;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'level0' must be a string");
        return retval;
    }

    if ( *level1 = cJSON_GetObjectItem(event, "level1"), !level1) {
        merror("Malformed JSON: field 'level1' not found");
        return retval;
    }

    obj = *level1;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'level1' must be a string");
        return retval;
    }

    if ( *level2 = cJSON_GetObjectItem(event, "level2"), !level2) {
        merror("Malformed JSON: field 'level2' not found");
        return retval;
    }

    obj = *level2;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'level2' must be a string");
        return retval;
    }

    if ( *checksum_l0 = cJSON_GetObjectItem(event, "checksum-l0"), !checksum_l0) {
        merror("Malformed JSON: field 'checksum-l0' not found");
        return retval;
    }

    obj = *checksum_l0;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'checksum-l0' must be a string");
        return retval;
    }

    if ( *checksum_l1 = cJSON_GetObjectItem(event, "checksum-l1"), !checksum_l1) {
        merror("Malformed JSON: field 'checksum-l1' not found");
        return retval;
    }

    obj = *checksum_l1;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'checksum-l1' must be a string");
        return retval;
    }

    if ( *checksum_l2 = cJSON_GetObjectItem(event, "checksum-l2"), !checksum_l2) {
        merror("Malformed JSON: field 'checksum-l2' not found");
        return retval;
    }

    obj = *checksum_l2;
    if (!obj->valuestring) {
        merror("Malformed JSON: field 'checksum-l2' must be a string");
        return retval;
    }

    retval = 0;
    return retval;
}

static int FindFileEvent(Eventinfo *lf, char *file, int *socket) {
    assert(lf);
    assert(file);
    return SendQuery(lf, "query_file", file, WDB_OK_FOUND, WDB_OK_NOT_FOUND, NULL, socket);
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

static void FillFileInfo(Eventinfo *lf, cJSON *file, cJSON *rules_matched) {
    assert(lf);
    assert(file);
    assert(rules_matched);

    fillData(lf, "yara.type", "file");

    if (file && file->valuestring) {
        fillData(lf, "yara.file", file->valuestring);
    }

    if (rules_matched && rules_matched->valuestring) {
        char *rules_matched_formated = NULL;
        rules_matched_formated = wstr_replace(rules_matched->valuestring,":",",");
        fillData(lf, "yara.rules_matched", rules_matched_formated);
        os_free(rules_matched_formated);
    }
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
