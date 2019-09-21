/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "mitre.h"

static OSHash *mitre_table;

void mitre_load(){
    int hashcheck;
    size_t read;
    long size;
    char * buffer = NULL;
    char path_file[PATH_MAX + 1];
    FILE *fp;
    cJSON *root;
    cJSON *type = NULL;
    cJSON *source_name = NULL;
    cJSON *ext_id = NULL;
    cJSON *object = NULL;
    cJSON *objects = NULL;
    cJSON *reference = NULL;
    cJSON *references = NULL;
    cJSON *kill_chain_phases = NULL;
    cJSON *kill_chain_phase = NULL;
    cJSON *chain_phase = NULL;
    cJSON *arrayphases = NULL;

    /* Create hash table */
    mitre_table = OSHash_Create();

    /* Load Json File */
    /* Reading enterprise-attack json file */
    snprintf(path_file, sizeof(path_file), "%s/%s", MITRE_JSON_FILE_DIR, MITRE_JSON_FILE_NAME);
    if(fp = fopen(path_file, "r"), !fp) {
        mdebug1("Mitre file info loading failed. File %s parsing error.", path_file);
        merror("Mitre matrix information could not be loaded.");
        goto end;
    }

    /* Size of the json file */
    if (size = get_fp_size(fp), size < 0) {
        mdebug1("Mitre file info loading failed. It was not possible to get file size. File %s", path_file);
        merror("Mitre matrix information could not be loaded.");
        goto end;
    }

    /* Check file size limit */
    if (size > JSON_MAX_FSIZE) {
        mdebug1("Mitre file info loading failed. It exceeds size. File %s", path_file);
        merror("Mitre matrix information could not be loaded.");
        goto end;
    }

    /* Allocate memory */
    os_malloc(size+1,buffer);
    
    // Get file and parse into JSON
    if (read = fread(buffer, 1, size, fp), read != (size_t)size && !feof(fp)) {
        mdebug1("Mitre file info loading failed. JSON file cannot be readed. File %s", path_file);
        merror("Mitre matrix information could not be loaded.");
        goto end;
    }
    
    /* Adding \0 */
    buffer[size] = '\0';

    /* First, parse the whole thing */
    if(root = cJSON_Parse(buffer), !root) {
        mdebug1("Mitre file info loading failed. JSON file cannot be parsered. File %s", path_file);
        merror("Mitre matrix information could not be loaded.");
        cJSON_Delete(root);
        goto end;
    } else {
        objects = cJSON_GetObjectItem(root, "objects");
        cJSON_ArrayForEach(object, objects){
            if(type = cJSON_GetObjectItem(object, "type"), type) {
                if (strcmp(type->valuestring,"attack-pattern") == 0){
                    references = cJSON_GetObjectItem(object, "external_references");
                    cJSON_ArrayForEach(reference, references){
                        if(source_name = cJSON_GetObjectItem(reference, "source_name"), source_name) {
                            if (strcmp(source_name->valuestring, "mitre-attack") == 0){
                                /* All the conditions have been met */
                                /* Storing the item 'external_id' */
                                ext_id = cJSON_GetObjectItem(reference, "external_id");

                                /* Storing the item 'phase_name' of 'kill_chain_phases' */
                                arrayphases = cJSON_CreateArray();
                                kill_chain_phases = cJSON_GetObjectItem(object, "kill_chain_phases");
                                cJSON_ArrayForEach(kill_chain_phase, kill_chain_phases){
                                    cJSON_ArrayForEach(chain_phase, kill_chain_phase){
                                        if(strcmp(chain_phase->string,"phase_name") == 0){
                                            cJSON_AddItemToArray(arrayphases, cJSON_Duplicate(chain_phase,1));
                                        }
                                    }  
                                }

                                /* Creating and filling the Mitre Hash table */
                                if(hashcheck = OSHash_Add(mitre_table, ext_id->valuestring, arrayphases), hashcheck == 0) {
                                    mdebug1("Mitre Hash table adding failed. JSON file cannot be stored. File %s", path_file);
                                    merror("Mitre matrix information could not be loaded.");
                                    cJSON_Delete(root);
                                    goto end;
                                }
                            }
                        }    
                    }
                }
            }
        }
    }
    cJSON_Delete(root);
    minfo("Mitre Hash table completed");
    goto end;

end:
    fclose(fp);
    os_free(buffer);
}

cJSON * mitre_get_attack(const char * mitre_id){
    return OSHash_Get(mitre_table, mitre_id);
}
