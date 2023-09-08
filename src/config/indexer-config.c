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

int indexer_config_special_array_subnode_read(XML_NODE node, cJSON *output_json)
{
    int i;

    if (!node)
        return 0;

    // Iterate over elements
    for (i = 0; node[i]; i++) {
        cJSON_AddItemToArray(output_json, cJSON_CreateString(node[i]->content));
    }
    return 0;
}

int indexer_config_subnode_read(const OS_XML *xml, XML_NODE node, cJSON *output_json, char * current_keypath)
{
    int i;
    xml_node **children;
    cJSON * subnode;
    cJSON * existing_item;
    cJSON * array_item;
    char * subnode_keypath;
    size_t subnode_keypath_len;

    if (!node)
        return 0;

    // Iterate over elements
    for (i = 0; node[i]; i++) {
        subnode_keypath_len = strlen(current_keypath) + strlen(node[i]->element) + 2;
        os_calloc(1, subnode_keypath_len, subnode_keypath);
        snprintf(subnode_keypath, subnode_keypath_len, "%s.%s", current_keypath, node[i]->element);

        if(indexer_config_is_special_array_key(subnode_keypath))
        {
            subnode = cJSON_CreateArray();
            if((children = OS_GetElementsbyNode(xml, node[i])))
            {
                indexer_config_special_array_subnode_read(children, subnode);
                OS_ClearNode(children);
            }
            cJSON_AddItemToObject(output_json, node[i]->element, subnode);
        }
        else
        {
            if((children = OS_GetElementsbyNode(xml, node[i])))
            {
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
                        // Item is not an array. Convert existing item to array and then add the new item to it
                        existing_item = cJSON_DetachItemFromObject(output_json, node[i]->element);
                        array_item = cJSON_AddArrayToObject(output_json, node[i]->element);
                        cJSON_AddItemToArray(array_item, cJSON_CreateString(cJSON_GetStringValue(existing_item)));
                        cJSON_AddItemToArray(array_item, cJSON_CreateString(node[i]->content));
                        cJSON_Delete(existing_item);
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

    return 0;
}

int Read_Indexer(const OS_XML *xml, XML_NODE nodes)
{
    indexer_config = cJSON_CreateObject();

    if (!nodes) {
        mdebug1("Empty configuration for module 'indexer'");
        return 0;
    }

    if (indexer_config_subnode_read(xml, nodes, indexer_config, "indexer") < 0) {
        return OS_INVALID;
    }

    return 0;
}

#endif
#endif
