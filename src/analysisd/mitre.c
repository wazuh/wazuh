/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 */

#include "mitre.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define static
#endif

#define SQL_GET_ALL_TECHNIQUES "mitre sql SELECT technique.id, technique.name, reference.external_id FROM technique LEFT JOIN reference ON technique.id = reference.id WHERE technique.revoked_by IS NULL AND NOT technique.deprecated AND reference.source = 'mitre-attack' LIMIT %i OFFSET %i;"
#define SQL_GET_ALL_TECHNIQUE_PHASES "mitre sql SELECT tactic_id FROM phase WHERE tech_id = '%s';"
#define SQL_GET_TACTIC_INFORMATION "mitre sql SELECT tactic.name, reference.external_id FROM tactic LEFT JOIN reference ON tactic.id = reference.id WHERE reference.source = 'mitre-attack' AND tactic.id = '%s';"

#define MAX_TECHNIQUES_REQUEST 100

static void free_technique_data(void *data);

static void free_tactic_list_data(OSList *tactics_list);

static OSHash *techniques_table;

int mitre_load() {
    int result = 0;
    int i;
    int j;
    int offset = 0;
    int size_ids;
    int size_phases;
    int sock = -1;
    char *wazuhdb_query = NULL;
    char *response = NULL;
    char *tech_id = NULL;
    char *tech_name = NULL;
    char *tech_ext_id = NULL;
    char *tactic_id = NULL;
    char *tactic_name = NULL;
    char *tactic_ext_id = NULL;
    cJSON *techniques_json = NULL;
    cJSON *techniques = NULL;
    cJSON *tech_id_json = NULL;
    cJSON *tech_name_json = NULL;
    cJSON *tech_ext_id_json = NULL;
    cJSON *phases_json = NULL;
    cJSON *phases = NULL;
    cJSON *tactic_json = NULL;
    cJSON *tactic = NULL;
    cJSON *tactic_id_json = NULL;
    cJSON *tactic_name_json = NULL;
    cJSON *tactic_ext_id_json = NULL;
    technique_data* data_technique = NULL;
    OSList* tactics_list = NULL;
    tactic_data* data_tactic = NULL;

    os_calloc(OS_SIZE_6144 + 1, sizeof(char), wazuhdb_query);
    os_calloc(OS_MAXSTR, sizeof(char), response);

    /* Connect to wdb */
    sock = wdbc_connect_with_attempts(5);
    if (sock < 0) {
        merror("Unable to connect to Wazuh-DB for Mitre matrix information.");
        result = -1;
        goto end;
    }

    /* Getting technique ID and name from Mitre's database in Wazuh-DB  */
    snprintf(wazuhdb_query, OS_SIZE_6144, SQL_GET_ALL_TECHNIQUES, MAX_TECHNIQUES_REQUEST, offset);
    techniques_json = wdbc_query_parse_json(&sock, wazuhdb_query, response, OS_MAXSTR);

    if (!techniques_json) {
        merror("Response from the Mitre database cannot be parsed.");
        result = -1;
        goto end;
    }

    if (size_ids = cJSON_GetArraySize(techniques_json), size_ids == 0) {
        merror("Response from the Mitre database has 0 elements.");
        result = -1;
        goto end;
    }

    /* Create techniques hash table */
    techniques_table = OSHash_Create();

    /* Set Free Data Pointer */
    OSHash_SetFreeDataPointer(techniques_table, (void (*)(void *))free_technique_data);

    do {
        for (i = 0; i < size_ids; i++) {
            techniques = cJSON_GetArrayItem(techniques_json, i);

            if (tech_id_json = cJSON_GetObjectItem(techniques, "id"), tech_id_json == NULL) {
                merror("It was not possible to get Mitre technique ID.");
                result = -1;
                goto end;
            }
            tech_id = tech_id_json->valuestring;

            if (tech_name_json = cJSON_GetObjectItem(techniques, "name"), tech_name_json == NULL) {
                merror("It was not possible to get Mitre technique name.");
                result = -1;
                goto end;
            }
            tech_name = tech_name_json->valuestring;

            if (tech_ext_id_json = cJSON_GetObjectItem(techniques, "external_id"), tech_ext_id_json == NULL) {
                merror("It was not possible to get Mitre technique external ID.");
                result = -1;
                goto end;
            }
            tech_ext_id = tech_ext_id_json->valuestring;

            /* Create tactics list */
            tactics_list = OSList_Create();

            /* Getting tactics from Mitre's database in Wazuh-DB */
            snprintf(wazuhdb_query, OS_SIZE_6144, SQL_GET_ALL_TECHNIQUE_PHASES, tech_id);
            phases_json = wdbc_query_parse_json(&sock, wazuhdb_query, response, OS_MAXSTR);

            if (!phases_json) {
                merror("Response from the Mitre database cannot be parsed.");
                result = -1;
                goto end;
            }

            if (size_phases = cJSON_GetArraySize(phases_json), size_phases == 0) {
                merror("Response from the Mitre database has 0 elements.");
                result = -1;
                goto end;
            }

            for (j = 0; j < size_phases; j++) {
                phases = cJSON_GetArrayItem(phases_json, j);

                if (tactic_id_json = cJSON_GetObjectItem(phases, "tactic_id"), tactic_id_json == NULL) {
                    merror("It was not possible to get MITRE tactic ID.");
                    result = -1;
                    goto end;
                }
                tactic_id = tactic_id_json->valuestring;

                /* Getting tactic ID and name from Mitre's database in Wazuh-DB  */
                snprintf(wazuhdb_query, OS_SIZE_6144, SQL_GET_TACTIC_INFORMATION, tactic_id);
                tactic_json = wdbc_query_parse_json(&sock, wazuhdb_query, response, OS_MAXSTR);

                if (!tactic_json) {
                    merror("Response from the Mitre database cannot be parsed.");
                    result = -1;
                    goto end;
                }

                tactic = cJSON_GetArrayItem(tactic_json, 0);

                if (tactic_name_json = cJSON_GetObjectItem(tactic, "name"), tactic_name_json == NULL) {
                    merror("It was not possible to get Mitre tactic name.");
                    result = -1;
                    goto end;
                }
                tactic_name = tactic_name_json->valuestring;

                if (tactic_ext_id_json = cJSON_GetObjectItem(tactic, "external_id"), tactic_ext_id_json == NULL) {
                    merror("It was not possible to get Mitre tactic external ID.");
                    result = -1;
                    goto end;
                }
                tactic_ext_id = tactic_ext_id_json->valuestring;

                data_tactic = NULL;
                os_malloc(sizeof(tactic_data), data_tactic);
                os_strdup(tactic_ext_id, data_tactic->tactic_id);
                os_strdup(tactic_name, data_tactic->tactic_name);

                /* Filling tactics list with Mitre's information */
                if (!OSList_AddData(tactics_list, (void *)data_tactic)) {
                    merror("Mitre tactics list adding failed. Mitre Tactic ID '%s' cannot be stored.", tactic_ext_id);
                    os_free(data_tactic->tactic_name);
                    os_free(data_tactic->tactic_id);
                    os_free(data_tactic);
                    result = -1;
                    goto end;
                }

                if (tactic_json != NULL) {
                    cJSON_Delete(tactic_json);
                    tactic_json = NULL;
                }
            }

            os_malloc(sizeof(technique_data), data_technique);
            os_strdup(tech_ext_id, data_technique->technique_id);
            os_strdup(tech_name, data_technique->technique_name);
            data_technique->tactics_list = tactics_list;

            /* Filling techniques hash table with Mitre's information */
            if (!OSHash_Add(techniques_table, tech_ext_id, data_technique)) {
                merror("Mitre techniques hash table adding failed. Mitre Technique ID '%s' cannot be stored.", tech_ext_id);
                os_free(data_technique->technique_name);
                os_free(data_technique->technique_id);
                os_free(data_technique);
                result = -1;
                goto end;
            }

            if (phases_json != NULL) {
                cJSON_Delete(phases_json);
                phases_json = NULL;
            }
        }

        if (techniques_json != NULL) {
            cJSON_Delete(techniques_json);
        }

        offset += MAX_TECHNIQUES_REQUEST;

        /* Getting technique ID and name from Mitre's database in Wazuh-DB  */
        snprintf(wazuhdb_query, OS_SIZE_6144, SQL_GET_ALL_TECHNIQUES, MAX_TECHNIQUES_REQUEST, offset);
        techniques_json = wdbc_query_parse_json(&sock, wazuhdb_query, response, OS_MAXSTR);

    } while (size_ids = cJSON_GetArraySize(techniques_json), size_ids > 0);

end:
    os_free(wazuhdb_query);
    os_free(response);

    if (tactic_json != NULL) {
        cJSON_Delete(tactic_json);
    }
    if (phases_json != NULL) {
        cJSON_Delete(phases_json);
    }
    if (techniques_json != NULL) {
        cJSON_Delete(techniques_json);
    }
    if (tactics_list != NULL && result != 0) {
    	free_tactic_list_data(tactics_list);
    }

    if (result != 0) {
         merror("Mitre matrix information could not be loaded.");
    }

    return result;
}

technique_data* mitre_get_attack(const char *mitre_id) {

    if (techniques_table == NULL) {
        return NULL;
    }

    return OSHash_Get(techniques_table, mitre_id);
}

int mitre_free_techniques(void) {

    if (techniques_table != NULL) {
        if(OSHash_Free(techniques_table)) {
            return -1;
        }
    }
    return 0;
}

static void free_technique_data(void *data) {

    technique_data * tech = (technique_data *)data;

    if (tech == NULL) {
        return;
    }
    if (tech->technique_id) {
        os_free(tech->technique_id);
    }
    if (tech->technique_name) {
        os_free(tech->technique_name);
    }
    if (tech->tactics_list) {
        free_tactic_list_data(tech->tactics_list);
    }
    os_free(tech);
}

static void free_tactic_list_data(OSList* tactics_list) {

    OSListNode* tactic_node = NULL;
    tactic_data* data_tactic = NULL;

    tactic_node = OSList_GetFirstNode(tactics_list);
    while (tactic_node) {
        data_tactic = (tactic_data *)tactic_node->data;
        os_free(data_tactic->tactic_name);
        os_free(data_tactic->tactic_id);
        os_free(data_tactic);
        OSList_DeleteCurrentlyNode(tactics_list);
        tactic_node = OSList_GetCurrentlyNode(tactics_list);
    }
    os_free(tactics_list);
}
