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
    size_t n;
    size_t size;
    char * buffer = NULL;
    FILE *fp;
    cJSON *object = NULL;
    cJSON *objects = NULL;
    cJSON *reference = NULL;
    cJSON *references = NULL;
    cJSON *type = NULL;
    cJSON *name = NULL;
    cJSON *ext_id = NULL;

    /* Create hash table */
    mitre_table = OSHash_Create();

    /* Load Json File */
    /* Reading enterprise-attack json file */
    fp = fopen("../ruleset/mitre/enterprise-attack.json", "r");
    //fp = fopen("../../etc/mitre/enterprise-attack.json", "r"); 
    if(!fp)
    {
        merror("Error at mitre_load() function. Mitre Json File not found");
        exit(-1);
    }

    /* Size of the json file */
    size = get_fp_size(fp); 
    if (size > JSON_MAX_FSIZE){
        merror("Cannot load Mitre JSON file, it exceeds the size");
        exit(-1);
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
        /* Building the mitre_table */
        objects = cJSON_GetObjectItem(root, "objects");
        cJSON_ArrayForEach(object, objects){
            type = cJSON_GetObjectItem(object, "type");
            if (strcmp(type->valuestring,"attack-pattern") == 0){
                references = cJSON_GetObjectItem(object, "external_references");
                cJSON_ArrayForEach(reference, references){
                    if (cJSON_GetObjectItem(reference, "source_name") && cJSON_GetObjectItem(reference, "external_id")){
                        name = cJSON_GetObjectItem(reference, "source_name");
                        ext_id = cJSON_GetObjectItem(reference, "external_id");
                        if (strcmp(name->valuestring, "mitre-attack") == 0){
                            hashcheck = OSHash_Add(mitre_table, ext_id->valuestring, cJSON_Duplicate(object, 1));
                            if(hashcheck == 0){
                                merror("Error: Check the OSHash Mitre configuration. Exiting.");
                                exit(-1);
                            }
                            else if (hashcheck == 1){
                                minfo("Warning: the value wasn't added to mitre hash table because duplicated key.");
                            }
                        }
                    }    
                }
            }
        }
    }
    cJSON_Delete(root);
}

cJSON * mitre_get_attack(const char * mitre_id){
    return OSHash_Get(mitre_table, mitre_id);
}
