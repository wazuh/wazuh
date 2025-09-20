#include "engine_external.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>
#include <os_xml/os_xml.h>
#include <shared.h>

// Configuration constants
static const char* const XML_TAG_OSSEC_CONFIG = "ossec_config";
static const char* const XML_TAG_INDEXER = "indexer";
static const char* const INDEXER_ROOT_PATH = "indexer";

/**
 * Configuration keys that should be treated as arrays of strings
 * These keys will have their child elements converted to JSON arrays
 */
static const char* const SPECIAL_ARRAY_KEYS[] = {"indexer.hosts", "indexer.ssl.certificate_authorities", NULL};

/**
 * Valid configuration paths for indexer settings
 * Any path not in this list will generate a warning and be ignored
 */
static const char* const VALID_CONFIG_PATHS[] = {"indexer.enabled",
                                                 "indexer.hosts",
                                                 "indexer.ssl",
                                                 "indexer.ssl.certificate_authorities",
                                                 "indexer.ssl.certificate",
                                                 "indexer.ssl.key",
                                                 NULL};

// Forward declarations
static int parse_indexer_subnodes(const OS_XML* xml, XML_NODE nodes, cJSON* output_json, const char* current_path);
static void populate_array_from_xml_nodes(XML_NODE nodes, cJSON* json_array);
static void cleanup_xml_resources(OS_XML* xml, XML_NODE* nodes_to_clear, int node_count);
static char* build_keypath(const char* parent_path, const char* element_name);
static cJSON* replace_existing_json_item(cJSON* parent, const char* key, cJSON* new_item);
static bool is_key_in_array(const char* keypath, const char** search_array);

bool is_key_in_array(const char* keypath, const char** search_array)
{
    if (!keypath || !search_array)
    {
        return false;
    }

    for (const char** current = search_array; *current != NULL; current++)
    {
        if (strcmp(keypath, *current) == 0)
        {
            return true;
        }
    }

    return false;
}

/**
 * @brief Populate a JSON array with string values from XML nodes
 *
 * @param nodes Array of XML nodes to process
 * @param json_array JSON array to populate with string values
 */
static void populate_array_from_xml_nodes(XML_NODE nodes, cJSON* json_array)
{
    if (!nodes || !json_array)
    {
        return;
    }

    for (int i = 0; nodes[i] != NULL; i++)
    {
        if (nodes[i]->content)
        {
            cJSON* string_item = cJSON_CreateString(nodes[i]->content);
            if (string_item)
            {
                cJSON_AddItemToArray(json_array, string_item);
            }
        }
    }
}

/**
 * @brief Build a dot-separated configuration key path
 *
 * @param parent_path Parent path (e.g., "indexer")
 * @param element_name Element name to append (e.g., "hosts")
 * @return Dynamically allocated string with combined path (e.g., "indexer.hosts")
 *         Caller must free the returned string
 */
static char* build_keypath(const char* parent_path, const char* element_name)
{
    if (!parent_path || !element_name)
    {
        return NULL;
    }

    size_t path_length = strlen(parent_path) + strlen(element_name) + 2; // +2 for '.' and '\0'
    char* keypath = NULL;

    os_calloc(1, path_length, keypath);
    snprintf(keypath, path_length, "%s.%s", parent_path, element_name);

    return keypath;
}

/**
 * @brief Replace an existing JSON object item or add a new one
 *
 * @param parent Parent JSON object
 * @param key Key name for the item
 * @param new_item New JSON item to add
 * @return The new item that was added
 */
static cJSON* replace_existing_json_item(cJSON* parent, const char* key, cJSON* new_item)
{
    if (!parent || !key || !new_item)
    {
        return NULL;
    }

    cJSON* existing_item = cJSON_GetObjectItem(parent, key);
    if (existing_item)
    {
        cJSON_Delete(cJSON_DetachItemFromObject(parent, key));
    }

    cJSON_AddItemToObject(parent, key, new_item);
    return new_item;
}

/**
 * @brief Process XML nodes and convert them to JSON format
 *
 * This function recursively processes XML nodes under the indexer configuration,
 * handling special array cases and nested objects appropriately.
 *
 * @param xml Parsed XML document
 * @param nodes Array of XML nodes to process
 * @param output_json JSON object to populate with configuration data
 * @param current_path Current configuration path for validation
 * @return 0 on success, 1 on error
 */
static int parse_indexer_subnodes(const OS_XML* xml, XML_NODE nodes, cJSON* output_json, const char* current_path)
{
    if (!nodes || !output_json || !current_path)
    {
        return 0;
    }

    for (int i = 0; nodes[i] != NULL; i++)
    {
        xml_node* current_node = nodes[i];

        if (!current_node->element)
        {
            continue;
        }

        char* node_keypath = build_keypath(current_path, current_node->element);
        if (!node_keypath)
        {
            continue;
        }

        // Validate configuration path
        if (!is_key_in_array(node_keypath, VALID_CONFIG_PATHS))
        {
            mwarn("Invalid element in the configuration: '%s'", node_keypath);
            os_free(node_keypath);
            continue;
        }

        // Handle special array keys (e.g., hosts, certificate_authorities)
        if (is_key_in_array(node_keypath, SPECIAL_ARRAY_KEYS))
        {
            cJSON* array_node = cJSON_CreateArray();
            if (!array_node)
            {
                merror("Failed to create JSON array for '%s'", node_keypath);
                os_free(node_keypath);
                return 1;
            }

            XML_NODE children = OS_GetElementsbyNode(xml, current_node);
            if (children)
            {
                populate_array_from_xml_nodes(children, array_node);
                OS_ClearNode(children);
            }

            if (cJSON_GetArraySize(array_node) == 0)
            {
                mwarn("Configuration array '%s' is empty in module 'indexer'. Check configuration", node_keypath);
            }

            replace_existing_json_item(output_json, current_node->element, array_node);
        }
        // Handle nested objects
        else
        {
            XML_NODE children = OS_GetElementsbyNode(xml, current_node);
            if (children)
            {
                cJSON* object_node = cJSON_CreateObject();
                if (!object_node)
                {
                    merror("Failed to create JSON object for '%s'", node_keypath);
                    os_free(node_keypath);
                    OS_ClearNode(children);
                    return 1;
                }

                int result = parse_indexer_subnodes(xml, children, object_node, node_keypath);
                if (result != 0)
                {
                    cJSON_Delete(object_node);
                    os_free(node_keypath);
                    OS_ClearNode(children);
                    return result;
                }

                replace_existing_json_item(output_json, current_node->element, object_node);
                OS_ClearNode(children);
            }
            // Handle simple string values
            else if (current_node->content)
            {
                cJSON* existing_item = cJSON_GetObjectItem(output_json, current_node->element);

                if (existing_item && cJSON_IsArray(existing_item))
                {
                    // Add to existing array
                    cJSON_AddItemToArray(existing_item, cJSON_CreateString(current_node->content));
                }
                else
                {
                    // Replace or add new string value
                    if (existing_item)
                    {
                        cJSON_Delete(cJSON_DetachItemFromObject(output_json, current_node->element));
                    }
                    cJSON_AddStringToObject(output_json, current_node->element, current_node->content);
                }
            }
        }

        os_free(node_keypath);
    }

    return 0;
}

/**
 * @brief Clean up XML resources safely
 *
 * @param xml XML document to clear
 * @param nodes_to_clear Array of node arrays to clear
 * @param node_count Number of node arrays in the array
 */
static void cleanup_xml_resources(OS_XML* xml, XML_NODE* nodes_to_clear, int node_count)
{
    if (nodes_to_clear)
    {
        for (int i = 0; i < node_count; i++)
        {
            if (nodes_to_clear[i])
            {
                OS_ClearNode(nodes_to_clear[i]);
            }
        }
    }

    if (xml)
    {
        OS_ClearXML(xml);
    }
}

char* get_indexer_cnf(const char* cnf_file, char* err_buf, size_t err_buf_size)
{
    if (!cnf_file || !err_buf || err_buf_size == 0)
    {
        if (err_buf && err_buf_size > 0)
        {
            snprintf(err_buf, err_buf_size, "Invalid parameters provided");
        }
        return NULL;
    }

    OS_XML xml = {0};
    XML_NODE root_nodes = NULL;
    char* indexer_config_json = NULL;

    // Parse XML file
    if (OS_ReadXML(cnf_file, &xml) < 0)
    {
        snprintf(err_buf,
                 err_buf_size,
                 "Could not read configuration file %s: %s at line %u",
                 cnf_file,
                 xml.err,
                 xml.err_line);
        return NULL;
    }

    // Get root elements
    root_nodes = OS_GetElementsbyNode(&xml, NULL);
    if (!root_nodes)
    {
        snprintf(err_buf, err_buf_size, "Could not parse configuration file %s", cnf_file);
        cleanup_xml_resources(&xml, NULL, 0);
        return NULL;
    }

    // Search for ossec_config element
    for (int i = 0; root_nodes[i] != NULL; i++)
    {
        xml_node* current_root = root_nodes[i];

        if (!current_root->element)
        {
            snprintf(
                err_buf, err_buf_size, "Element without name at position %d in configuration file %s", i, cnf_file);
            XML_NODE nodes_to_clear[] = {root_nodes};
            cleanup_xml_resources(&xml, nodes_to_clear, 1);
            return NULL;
        }

        // Skip non-ossec_config elements
        if (strcmp(current_root->element, XML_TAG_OSSEC_CONFIG) != 0)
        {
            continue;
        }

        XML_NODE ossec_children = OS_GetElementsbyNode(&xml, current_root);
        if (!ossec_children)
        {
            continue;
        }

        // Search for indexer element within ossec_config
        for (int j = 0; ossec_children[j] != NULL; j++)
        {
            xml_node* current_child = ossec_children[j];

            if (!current_child->element || strcmp(current_child->element, XML_TAG_INDEXER) != 0)
            {
                continue;
            }

            // Found indexer configuration - parse it
            cJSON* config_json = cJSON_CreateObject();
            if (!config_json)
            {
                merror("Failed to create JSON object for indexer configuration");
                XML_NODE nodes_to_clear[] = {root_nodes, ossec_children};
                cleanup_xml_resources(&xml, nodes_to_clear, 2);
                return NULL;
            }

            XML_NODE indexer_children = OS_GetElementsbyNode(&xml, current_child);
            int parse_result = parse_indexer_subnodes(&xml, indexer_children, config_json, INDEXER_ROOT_PATH);

            if (parse_result != 0)
            {
                snprintf(err_buf, err_buf_size, "Could not parse <indexer> element in configuration file %s", cnf_file);
                cJSON_Delete(config_json);
                XML_NODE nodes_to_clear[] = {root_nodes, ossec_children, indexer_children};
                cleanup_xml_resources(&xml, nodes_to_clear, 3);
                return NULL;
            }

            // Convert JSON to string
            indexer_config_json = cJSON_PrintUnformatted(config_json);
            cJSON_Delete(config_json);

            XML_NODE nodes_to_clear[] = {root_nodes, ossec_children, indexer_children};
            cleanup_xml_resources(&xml, nodes_to_clear, 3);
            return indexer_config_json;
        }

        OS_ClearNode(ossec_children);
        snprintf(err_buf, err_buf_size, "Could not find <indexer> element in configuration file %s", cnf_file);
        XML_NODE nodes_to_clear[] = {root_nodes};
        cleanup_xml_resources(&xml, nodes_to_clear, 1);
        return NULL;
    }

    snprintf(err_buf, err_buf_size, "Could not find <ossec_config> element in configuration file %s", cnf_file);
    XML_NODE nodes_to_clear[] = {root_nodes};
    cleanup_xml_resources(&xml, nodes_to_clear, 1);
    return NULL;
}
