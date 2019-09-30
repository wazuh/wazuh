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

int mitre_load(){
    int result = 0;
    int hashcheck;
    int i;
    int j;
    int size_ids;
    int size_tactics;
    char path_db[PATH_MAX + 1]= "/var/db/mitre.db" ;
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


    /* Create hash table */
    mitre_table = OSHash_Create();
    
    /* Get Mitre IDs from Mitre's database */
    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    snprintf(wazuhdb_query, OS_SIZE_6144, "mitre get_ids");
    result = wdb_send_query(wazuhdb_query, &response);
    if (!response) {
        mdebug1("Mitre info loading failed. Mitre's database query failed. Database: %s", path_db);
        merror("Mitre matrix information could not be loaded.");
        result = -1;
        goto end;
    }

    if (response[0] != 'o' || response[1] != 'k' || response[2] != ' ') {
        mdebug1("Mitre info loading failed. Mitre's database gave error response. Response: %s", response);
        merror("Mitre matrix information could not be loaded.");
        os_free(response);
        result = -1;
        goto end;
    }

    /* Parse IDs string */
    if(root = cJSON_Parse(response+3), !root) {
        mdebug1("Mitre info loading failed. Mitre's database response cannot be parsered. Response: %s", response);
        merror("Mitre matrix information could not be loaded.");
        os_free(response);
        cJSON_Delete(root);
        result = -1;
        goto end;
    }

    /* Response parameter has to be freed before continuing*/
    os_free(response);

    /* Getting array size */
    if(size_ids = cJSON_GetArraySize(root), size_ids == 0) {
        mdebug1("Mitre info loading failed. Mitre's database response has 0 elements.");
        merror("Mitre matrix information could not be loaded.");
        cJSON_Delete(root);
        result = -1;
        goto end;
    }
    
    for (i=0; i<size_ids; i++){
        /* Getting Mitre attack ID  */
        ids = cJSON_GetArrayItem(root, i);
        id = cJSON_GetObjectItem(ids,"id");
        ext_id = id->valuestring;

        /* Consulting mitredatabase to get Tactics */
        snprintf(wazuhdb_query, OS_SIZE_6144, "mitre get_tactics %s", ext_id);
        result = wdb_send_query(wazuhdb_query, &response);

        if (response) {
            if (response[0] == 'o' && response[1] == 'k' && response[2] == ' ') {
                /* Getting tactics and filling the Mitre Hash table */
                tactics_array = cJSON_CreateArray();
                tactics_json = cJSON_Parse(response+3);
                if(size_tactics = cJSON_GetArraySize(tactics_json), size_tactics == 0) {
                    mdebug1("Mitre info loading failed. Mitre's database response has 0 elements. Response: %s", response);
                    merror("Mitre matrix information could not be loaded.");
                    cJSON_Delete(tactics_json);
                    cJSON_Delete(root);
                    os_free(response);
                    result = -1;
                    goto end;    
                }
                for(j=0; j<size_tactics; j++) {
                    tactics = cJSON_GetArrayItem(tactics_json, j);
                    tactic = cJSON_GetObjectItem(tactics,"phase_name");
                    cJSON_AddItemToArray(tactics_array, cJSON_Duplicate(tactic,1));
                }
                if(hashcheck = OSHash_Add(mitre_table, ext_id, tactics_array), hashcheck == 0) {
                    mdebug1("Mitre Hash table adding failed. Mitre information cannot be stored. Response: %s", response);
                    merror("Mitre matrix information could not be loaded.");
                    cJSON_Delete(tactics_json);
                    cJSON_Delete(root);
                    os_free(response);
                    result = -1;
                    goto end;
                }    
                cJSON_Delete(tactics_json);
                os_free(response);    
            } else {
                mdebug1("Mitre info loading failed. Mitre's database gave error response. Response: %s", response);
                merror("Mitre matrix information could not be loaded.");
                cJSON_Delete(tactics_json);
                cJSON_Delete(root);
                os_free(response);
                result = -1;
                goto end;
            }
        }
    }
    cJSON_Delete(root);

end:
    os_free(wazuhdb_query);
    return result;
}

cJSON * mitre_get_attack(const char * mitre_id){
    return OSHash_Get(mitre_table, mitre_id);
}
