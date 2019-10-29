/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

#include "mitre.h"

static OSHash *mitre_table;

int mitre_load(char * mode){
    int result = 0;
    int hashcheck;
    int i;
    int j;
    int size_ids;
    int size_tactics;
    char path_db[PATH_MAX + 1];
    char *wazuhdb_query = NULL;
    char *response = NULL;
    char *ext_id = NULL;
    cJSON *root;
    cJSON *ids;
    cJSON *id;
    cJSON *tactics_array;
    cJSON *tactics_json;
    cJSON *tactics;
    cJSON *tactic;

    snprintf(path_db, sizeof(path_db), "%s/%s.db", WDB_DIR, WDB_MITRE_NAME);

    /* Create hash table */
    mitre_table = OSHash_Create();
    
    /* Get Mitre IDs from Mitre's database */
    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    snprintf(wazuhdb_query, OS_SIZE_6144, "mitre sql SELECT id from attack;");
    if (result = wdb_send_query(wazuhdb_query, &response), result == -2) {
        mdebug1("Mitre info loading failed. Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
        merror("Mitre matrix information could not be loaded.");
        goto end;
    }

    if (result == -1) {
        mdebug1("Mitre info loading failed. No response or bad response from wazuh-db: %s", response);
        merror("Mitre matrix information could not be loaded.");
        os_free(response);
        goto end;
    }

    /* Parse IDs string */
    if (root = cJSON_Parse(response+3), !root) {
        mdebug1("Mitre info loading failed. Query response cannot be parsered: %s", response);
        merror("Mitre matrix information could not be loaded.");
        os_free(response);
        cJSON_Delete(root);
        result = -1;
        goto end;
    }

    /* Response parameter has to be freed before continuing */
    os_free(response);

    /* Getting array size */
    if (size_ids = cJSON_GetArraySize(root), size_ids == 0) {
        mdebug1("Mitre info loading failed. Query response has 0 elements.");
        merror("Mitre matrix information could not be loaded.");
        cJSON_Delete(root);
        result = -1;
        goto end;
    }
    
    for (i = 0; i < size_ids; i++){
        /* Getting Mitre attack ID from Mitre's database in Wazuh-DB  */
        ids = cJSON_GetArrayItem(root, i);
        if (id = cJSON_GetObjectItem(ids,"id"), id == NULL) {
            mdebug1("Mitre info loading failed. It was not possible to get cJSON item from IDs array.");
            merror("Mitre matrix information could not be loaded.");
            cJSON_Delete(root);
            result = -1;
            goto end; 
        }
        ext_id = id->valuestring;

        /* Consulting Mitre's database to get Tactics */
        snprintf(wazuhdb_query, OS_SIZE_6144, "mitre sql SELECT phase_name FROM has_phase WHERE attack_id = '%s';", ext_id);
        if (result = wdb_send_query(wazuhdb_query, &response), result == -2) {
            mdebug1("Mitre info loading failed. Unable to connect to socket '%s'.", WDB_LOCAL_SOCK);
            merror("Mitre matrix information could not be loaded.");
            cJSON_Delete(root);
            goto end;
        }

        if (result == -1) {
            mdebug1("Mitre info loading failed. No response or bad response from wazuh-db: %s", response);
            merror("Mitre matrix information could not be loaded.");
            cJSON_Delete(root);
            os_free(response);
            goto end;
        }

        /* Getting tactics from Mitre's database in Wazuh-DB */
        tactics_array = cJSON_CreateArray();
        if (tactics_json = cJSON_Parse(response+3), !tactics_json) {
            mdebug1("Mitre info loading failed. Query response cannot be parsered: %s", response);
            merror("Mitre matrix information could not be loaded.");
            cJSON_Delete(tactics_json);
            cJSON_Delete(root);
            cJSON_Delete(tactics_array);
            os_free(response);
            result = -1;
            goto end;
        }
        if (size_tactics = cJSON_GetArraySize(tactics_json), size_tactics == 0) {
            mdebug1("Mitre info loading failed. Query response has 0 elements. Response: %s", response);
            merror("Mitre matrix information could not be loaded.");
            cJSON_Delete(tactics_json);
            cJSON_Delete(root);
            cJSON_Delete(tactics_array);
            os_free(response);
            result = -1;
            goto end;
        }
        for (j = 0; j < size_tactics; j++) {
            tactics = cJSON_GetArrayItem(tactics_json, j);
            if (tactic = cJSON_GetObjectItem(tactics,"phase_name"), tactic == NULL) {
                mdebug1("Mitre info loading failed. It was not possible to get cJSON item from tactics array.");
                merror("Mitre matrix information could not be loaded.");
                cJSON_Delete(tactics_json);
                cJSON_Delete(root);
                cJSON_Delete(tactics_array);
                os_free(response);
                result = -1;
                goto end;
            }
            cJSON_AddItemToArray(tactics_array, cJSON_Duplicate(tactic,1));
        }

        /* Filling Hash table with Mitre's information */
        if (hashcheck = OSHash_Add(mitre_table, ext_id, tactics_array), hashcheck == 0) {
            mdebug1("Mitre Hash table adding failed. Mitre information cannot be stored. Response: %s", response);
            merror("Mitre matrix information could not be loaded.");
            cJSON_Delete(tactics_json);
            cJSON_Delete(root);
            cJSON_Delete(tactics_array);
            os_free(response);
            result = -1;
            goto end;
        }
        if (mode != NULL && !strcmp(mode,"test")) {
            cJSON_Delete(tactics_array);
        }
        cJSON_Delete(tactics_json);
        os_free(response);
    }
    cJSON_Delete(root);

end:
    if (mode != NULL && !strcmp(mode,"test")) {
        OSHash_Free(mitre_table);
    }
    os_free(wazuhdb_query);
    return result;
}

cJSON * mitre_get_attack(const char * mitre_id) {
    return OSHash_Get(mitre_table, mitre_id);
}
