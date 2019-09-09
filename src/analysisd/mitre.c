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
    int phases_size;
    int platforms_size;
    int hashcheck;
    int i = 0;
    size_t n;
    size_t size;
    char * buffer = NULL;
    char ** phases_string;
    FILE *fp;
    cJSON *type = NULL;
    cJSON *source_name = NULL;
    cJSON *name = NULL;
    cJSON *ext_id = NULL;
    cJSON *object_out = NULL;
    cJSON *object = NULL;
    cJSON *objects = NULL;
    cJSON *reference = NULL;
    cJSON *references = NULL;
    cJSON *kill_chain_phases = NULL;
    cJSON *kill_chain_phase = NULL;
    cJSON *chain_phase = NULL;
    cJSON *platforms = NULL;
    cJSON *arrayphases = NULL;

    /* Create hash table */
    mitre_table = OSHash_Create();

    /* Load Json File */
    /* Reading enterprise-attack json file */
    fp = fopen("../ruleset/mitre/enterprise-attack.json", "r");
  
    if(!fp)
    {
        merror("Error at mitre_load() function. Mitre Json File not found");
        exit(1);
    }

    /* Size of the json file */
    size = get_fp_size(fp); 
    if (size > JSON_MAX_FSIZE){
        merror("Cannot load Mitre JSON file, it exceeds the size");
        exit(1);
    }

    /* Allocate memory */
    os_malloc(size+1,buffer);
    
    /* String JSON */
    n = fread(buffer, 1, size, fp);
    fclose(fp);
    
    /* Added \0 */
    if (n == size)
        buffer[size] = '\0';

    /* First, parse the whole thing */
    cJSON *root = cJSON_Parse(buffer);
    free(buffer);

    if(root == NULL){
        minfo("Mitre JSON file is empty.");
    } else {
        object_out = cJSON_CreateObject();
        objects = cJSON_GetObjectItem(root, "objects");
        cJSON_ArrayForEach(object, objects){
            type = cJSON_GetObjectItem(object, "type");
            if (strcmp(type->valuestring,"attack-pattern") == 0){
                references = cJSON_GetObjectItem(object, "external_references");
                cJSON_ArrayForEach(reference, references){
                    if (cJSON_GetObjectItem(reference, "source_name") && cJSON_GetObjectItem(reference, "external_id")){
                        source_name = cJSON_GetObjectItem(reference, "source_name");
                        if (strcmp(source_name->valuestring, "mitre-attack") == 0){
                            phases_size = 0;
                            platforms_size = 0;
                            /* All the conditions have been met */
                            /* Storing the item 'external_id' */
                            ext_id = cJSON_GetObjectItem(reference, "external_id");

                            /* Storing the item 'name' */
                            name = cJSON_GetObjectItem(object, "name");

                            /* Storing the item 'phase_name' of 'kill_chain_phases' */
                            kill_chain_phases = cJSON_GetObjectItem(object, "kill_chain_phases");
                            cJSON_ArrayForEach(kill_chain_phase, kill_chain_phases){
                                cJSON_ArrayForEach(chain_phase, kill_chain_phase){
                                    if(strcmp(chain_phase->string,"phase_name") == 0){
                                        os_realloc(phases_string, (phases_size + 2) * sizeof(char *), phases_string);
                                        os_strdup(chain_phase->valuestring, phases_string[phases_size]);
                                        phases_string[phases_size + 1] = NULL;
                                        phases_size++;
                                    }
                                }  
                            }
                            arrayphases = cJSON_CreateStringArray(phases_string, phases_size);

                            /* Storing the item 'x_mitre_platforms' */
                            platforms = cJSON_GetObjectItem(object, "x_mitre_platforms");
                            
                            /* A new object with the items we want to add */
                            cJSON_AddStringToObject(object_out, "id", ext_id->valuestring);
                            cJSON_AddStringToObject(object_out, "name", name->valuestring);
                            cJSON_AddItemToObject(object_out, "phases", arrayphases);
                            cJSON_AddItemToObject(object_out, "platforms", cJSON_Duplicate(platforms,1));

                            /* Creating and filling the Mitre Hash table */
                            hashcheck = OSHash_Add(mitre_table, ext_id->valuestring, cJSON_Duplicate(object_out,1));
                            if(hashcheck == 0){
                                merror("Error: Check the OSHash Mitre configuration. Exiting.");
                                exit(1);
                            }
                            else if (hashcheck == 1){
                                minfo("Warning: the value wasn't added to mitre hash table because duplicated key.");
                            }

                            /* Deleting items from the object. Replacing items is another option */
                            cJSON_DeleteItemFromObject(object_out, "id");
                            cJSON_DeleteItemFromObject(object_out, "name");
                            cJSON_DeleteItemFromObject(object_out, "phases");
                            cJSON_DeleteItemFromObject(object_out, "platforms");

                            /* Free memory */
                            for (i=0; phases_string[i] != NULL; i++){
                                os_free (phases_string[i]);                            
                            }
                            os_free(phases_string);
                        }
                    }    
                }
            }
        }
    }
    cJSON_Delete(root);
    cJSON_Delete(object_out);
}

cJSON * mitre_get_attack(const char * mitre_id){
    return OSHash_Get(mitre_table, mitre_id);
}
