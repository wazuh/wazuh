/*
 * Wazuh Indexer Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * August 31, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT
#ifndef WIN32

#include "shared.h"
#include "external/cJSON/cJSON.h"

/* Global variables */
static const char * special_array_keys[] = {
    "indexer.hosts",
    "indexer.ssl.certificate_authorities",
    NULL
};

cJSON * indexer_config = NULL;

bool indexer_config_is_special_array_key(const char * keypath)
{
    const char ** psearch = special_array_keys;
    while(*psearch)
    {
        if(strcmp(keypath, *psearch) == 0)
        {
            return true;
        }
        psearch++;
    }
    return false;
}

void indexer_config_special_array_subnode_read(XML_NODE node, cJSON *output_json)
{
    if (!node)
        return;

    // Iterate over elements
    for (int i = 0; node[i]; i++) {
        cJSON_AddItemToArray(output_json, cJSON_CreateString(node[i]->content));
    }
}

int indexer_config_subnode_read(const OS_XML *xml, XML_NODE node, cJSON *output_json, char * current_keypath)
{
    int i;
    xml_node **children;
    cJSON * subnode;
    cJSON * existing_item;
    char * subnode_keypath;
    size_t subnode_keypath_len;

    if (!node)
        return OS_SUCCESS

    // Iterate over elements
    for (i = 0; node[i]; i++) {
        subnode_keypath_len = strlen(current_keypath) + strlen(node[i]->element) + 2;
        os_calloc(1, subnode_keypath_len, subnode_keypath);
        snprintf(subnode_keypath, subnode_keypath_len, "%s.%s", current_keypath, node[i]->element);

        if(indexer_config_is_special_array_key(subnode_keypath))
        {
            if(cJSON_GetObjectItem(output_json, node[i]->element))
            {
                // Delete the existing element.
                cJSON_Delete(cJSON_DetachItemFromObject(output_json, node[i]->element));
            }

            subnode = cJSON_CreateArray();
            if((children = OS_GetElementsbyNode(xml, node[i])))
            {
                indexer_config_special_array_subnode_read(children, subnode);
                OS_ClearNode(children);
            }

            if(cJSON_GetArraySize(subnode) <= 0){
                merror("%s is empty in module 'indexer'. Check configuration", subnode_keypath);
                os_free(subnode_keypath);
                return OS_MISVALUE;
            }

            cJSON_AddItemToObject(output_json, node[i]->element, subnode);
        }
        else
        {
            if((children = OS_GetElementsbyNode(xml, node[i])))
            {
                if(cJSON_GetObjectItem(output_json, node[i]->element))
                {
                    // Delete the existing element.
                    cJSON_Delete(cJSON_DetachItemFromObject(output_json, node[i]->element));
                }

                subnode = cJSON_CreateObject();
                indexer_config_subnode_read(xml, children, subnode, subnode_keypath);
                cJSON_AddItemToObject(output_json, node[i]->element, subnode);
                OS_ClearNode(children);
            }
            else
            {
                if((existing_item = cJSON_GetObjectItem(output_json, node[i]->element)))
                {
                    // Already exists a key in JSON with this same name at this level
                    if(cJSON_IsArray(existing_item))
                    {
                        // Item already is an array. Just add the new item to array
                        cJSON_AddItemToArray(existing_item, cJSON_CreateString(node[i]->content));
                    }
                    else
                    {
                        // Overwrite the existing element.
                        cJSON_Delete(cJSON_DetachItemFromObject(output_json, node[i]->element));
                        cJSON_AddStringToObject(output_json, node[i]->element, node[i]->content);
                    }
                }
                else
                {
                    cJSON_AddStringToObject(output_json, node[i]->element, node[i]->content);
                }
            }
        }
        os_free(subnode_keypath);
    }

    return OS_SUCCESS;
}

int Read_Indexer(const OS_XML *xml, XML_NODE nodes)
{
    if(indexer_config) {
        cJSON_Delete(indexer_config);
    }
    indexer_config = cJSON_CreateObject();

    if (!nodes) {
        mdebug1("Empty configuration for module 'indexer'");
        return OS_SUCCESS;
    }

    return indexer_config_subnode_read(xml, nodes, indexer_config, "indexer");
}

#endif
#endif
