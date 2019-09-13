/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_db/wdb.h"

int main(){
    size_t n;
    size_t size;
    char * buffer = NULL;
    char * output;
    FILE *fp;
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
    cJSON *platforms = NULL;
    cJSON *platform = NULL;
    
    if (wdb_mitre = wdb_open_mitre(), !wdb_mitre) {
            merror("Couldn't open DB mitre");
            snprintf(output, OS_MAXSTR + 1, "err Couldn't open DB mitre");
            return -1;
    }

    /* Load Json File */
    /* Reading enterprise-attack json file */
    fp = fopen("../ruleset/mitre/enterprise-attack.json", "r");

    if(!fp)
    {
        merror("Error at wdb_mitre_load() function. Mitre Json File not found");
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
        objects = cJSON_GetObjectItem(root, "objects");
        cJSON_ArrayForEach(object, objects){
            type = cJSON_GetObjectItem(object, "type");
            if (strcmp(type->valuestring,"attack-pattern") == 0){
                references = cJSON_GetObjectItem(object, "external_references");
                cJSON_ArrayForEach(reference, references){
                    if (cJSON_GetObjectItem(reference, "source_name") && cJSON_GetObjectItem(reference, "external_id")){
                        source_name = cJSON_GetObjectItem(reference, "source_name");
                        if (strcmp(source_name->valuestring, "mitre-attack") == 0){
                            /* All the conditions have been met */
                            /* Storing the item 'external_id' */
                            ext_id = cJSON_GetObjectItem(reference, "external_id");

                            // /* Insert functions */
                            if(wdb_mitre_attack_insert(wdb_mitre, ext_id->valuestring, cJSON_Print(object)) < 0){
                                merror("SQLite - Mitre: object was not inserted in attack table");
                                goto end;
                            }

                            /* Storing the item 'phase_name' of 'kill_chain_phases' */
                            kill_chain_phases = cJSON_GetObjectItem(object, "kill_chain_phases");
                            cJSON_ArrayForEach(kill_chain_phase, kill_chain_phases){
                                cJSON_ArrayForEach(chain_phase, kill_chain_phase){
                                    if(strcmp(chain_phase->string,"phase_name") == 0){
                                        /* Insert mitre phases */
                                        if(wdb_mitre_phase_insert(wdb_mitre, ext_id->valuestring, chain_phase->valuestring) < 0){
                                            merror("SQLite - Mitre: phase was not inserted in phases table");
                                            goto end;
                                        }
                                    }
                                }  
                            }

                            /* Storing the item 'x_mitre_platforms' */
                            platforms = cJSON_GetObjectItem(object, "x_mitre_platforms");
                            cJSON_ArrayForEach(platform, platforms){
                                /* Insert mitre platforms */
                                if(wdb_mitre_platform_insert(wdb_mitre, ext_id->valuestring, platform->valuestring) < 0){
                                    merror("SQLite - Mitre: platform was not inserted in platforms table");
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
end:
    return -1;
}