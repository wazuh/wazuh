#include "engine_external.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <cJSON.h>
#include <os_xml.h>
#include <shared.h>

// Configuration constants
static const char* const XML_TAG_WAZUH_CONFIG = "wazuh_config";
static const char* const XML_TAG_INDEXER = "indexer";
static const char* const INDEXER_ROOT_PATH = "indexer";
static const char* const XML_TAG_HOST = "host";
static const char* const XML_TAG_CA = "ca";
static const char* const XML_TAG_CERT = "certificate";
static const char* const XML_TAG_KEY = "key";

/**
 * Configuration keys that should be treated as arrays of strings
 * These keys will have their child elements converted to JSON arrays
 */
static const char* const SPECIAL_ARRAY_KEYS[] = {"indexer.hosts", "indexer.ssl.certificate_authorities", NULL};

/**
 * Valid configuration paths for indexer settings
 * Any path not in this list will generate a warning and be ignored
 */
static const char* const VALID_CONFIG_PATHS[] = {"indexer.hosts",
                                                 "indexer.ssl",
                                                 "indexer.ssl.certificate_authorities",
                                                 "indexer.ssl.certificate",
                                                 "indexer.ssl.key",
                                                 NULL};

// Forward declarations
static int parse_indexer_subnodes(const OS_XML* xml, XML_NODE nodes, cJSON* output_json, const char* current_path, char* err_buf, size_t err_buf_size);
static int populate_array_from_xml_nodes(XML_NODE nodes, cJSON* json_array, char* err_buf, size_t err_buf_size);
static void cleanup_xml_resources(OS_XML* xml, XML_NODE* nodes_to_clear, int node_count);
static char* build_keypath(const char* parent_path, const char* element_name);
static cJSON* replace_existing_json_item(cJSON* parent, const char* key, cJSON* new_item);
static bool is_key_in_array(const char* keypath, const char** search_array);
static int validate_host(const char* host);
static int validate_certificate_path(const char* path);

/**
 * @brief Check if a given key path exists in a list of keys
 *
 * @param keypath The dot-separated key path to check
 * @param search_array NULL-terminated array of valid key paths
 * @return true if the key path is found, false otherwise
 */
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
 * @brief Validate host string
 *
 * @param host Host string to validate (e.g., "http://hostname:port")
 * @return OS_SUCCESS if the host is valid, OS_INVALID otherwise
 */
static int validate_host(const char* host)
{
    // Fail if host not defined or empty
    if (!host || strlen(host) == 0) {
        return OS_INVALID;
    }

    // Verify protocol
    if (strncmp(host, "http://", 7) != 0 && strncmp(host, "https://", 8) != 0) {
        return OS_INVALID;
    }

    // Parse hostname and port
    const char* hostname_port = strchr(host, '/') + 2;
    const char* port_separator = strchr(hostname_port, ':');

    // Port missing
    if (!port_separator) {
        return OS_INVALID;
    }

    // Get hostname and port separately
    const char* port = port_separator + 1;
    char * hostname = NULL;
    w_strdup(hostname_port, hostname);
    hostname[strlen(hostname_port) - strlen(port) - 1] = '\0';

    // Validate hostname
    if (OS_IsValidIP(hostname, NULL) == 0) {
        // Invalid if contains slashes
        if (strlen(hostname) == 0 || strchr(hostname, '/') != NULL) {
            os_free(hostname);
            return OS_INVALID;
        }
    }

    os_free(hostname);

    // Validate port
    if (strlen(port) == 0) {
        return OS_INVALID;
    }

    for (int i = 0; port[i] != '\0'; ++i)
    {
        if (port[i] < '0' || port[i] > '9')
        {
            return OS_INVALID;
        }
    }

    return OS_SUCCESS;
}

/**
 * @brief Validate certificate path
 *
 * @param path Path to the certificate file
 * @return OS_SUCCESS if the path is valid, OS_INVALID otherwise
 */
static int validate_certificate_path(const char* path)
{
    int ret = OS_INVALID;
    // Verify that the variable is set and contains a non-empty path
    if (path && strlen(path) > 0)
    {
        struct stat info;
        if (stat(path, &info) == 0)
        {
            ret = OS_SUCCESS;
        }
    }

    return ret;
}

/**
 * @brief Populate a JSON array with string values from XML nodes
 *
 * @param nodes Array of XML nodes to process
 * @param json_array JSON array to populate with string values
 * @param err_buf Buffer to store error messages
 * @param err_buf_size Size of the error buffer
 *
 * @return OS_SUCCESS on success, OS_INVALID on error
 */
static int populate_array_from_xml_nodes(XML_NODE nodes, cJSON* json_array, char* err_buf, size_t err_buf_size)
{
    if (!nodes || !json_array)
    {
        return OS_INVALID;
    }

    for (int i = 0; nodes[i] != NULL; i++)
    {
        if (nodes[i]->element) {
            if (strcmp(nodes[i]->element, XML_TAG_HOST) == 0){
                if (validate_host(nodes[i]->content) != OS_SUCCESS) {
                    snprintf(err_buf, err_buf_size, "Invalid host '%s' in configuration array 'indexer.hosts' in module 'indexer'. Check configuration", nodes[i]->content);
                    return OS_INVALID;
                }
            }
            if (strcmp(nodes[i]->element, XML_TAG_CA) == 0) {
                if (validate_certificate_path(nodes[i]->content) != OS_SUCCESS) {
                    snprintf(err_buf, err_buf_size, "File '%s' not found for 'indexer.ssl.certificate_authorities' in module 'indexer'. Check configuration", nodes[i]->content);
                    return OS_INVALID;
                }
            }
        }

        if (nodes[i]->content)
        {
            cJSON* string_item = cJSON_CreateString(nodes[i]->content);
            if (string_item)
            {
                cJSON_AddItemToArray(json_array, string_item);
            }
        }
    }

    return OS_SUCCESS;
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
 * @param err_buf Buffer to store error messages
 * @param err_buf_size Size of the error buffer
 * @return OS_SUCCESS on success, OS_INVALID on error
 */
static int parse_indexer_subnodes(const OS_XML* xml, XML_NODE nodes, cJSON* output_json, const char* current_path, char* err_buf, size_t err_buf_size)
{
    if (!nodes || !output_json || !current_path)
    {
        return OS_INVALID;
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

        if (!is_key_in_array(node_keypath, VALID_CONFIG_PATHS))
        {
            snprintf(err_buf, err_buf_size, "Invalid element in the configuration: '%s'", node_keypath);
            os_free(node_keypath);
            return OS_INVALID;
        }

        // Handle special array keys (e.g., hosts, certificate_authorities)
        if (is_key_in_array(node_keypath, SPECIAL_ARRAY_KEYS))
        {
            cJSON* array_node = cJSON_CreateArray();
            if (!array_node)
            {
                snprintf(err_buf, err_buf_size, "Failed to create JSON array for '%s'", node_keypath);
                os_free(node_keypath);
                return OS_INVALID;
            }

            XML_NODE children = OS_GetElementsbyNode(xml, current_node);
            if (children)
            {
                int ret = populate_array_from_xml_nodes(children, array_node, err_buf, err_buf_size);
                OS_ClearNode(children);
                if (ret != OS_SUCCESS)
                {
                    cJSON_Delete(array_node);
                    os_free(node_keypath);
                    return ret;
                }
            }

            if (cJSON_GetArraySize(array_node) == 0)
            {
                snprintf(err_buf, err_buf_size, "Configuration array '%s' is empty in module 'indexer'. Check configuration", node_keypath);
                cJSON_Delete(array_node);
                os_free(node_keypath);
                return OS_INVALID;
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
                    snprintf(err_buf, err_buf_size, "Failed to create JSON object for '%s'", node_keypath);
                    os_free(node_keypath);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                int result = parse_indexer_subnodes(xml, children, object_node, node_keypath, err_buf, err_buf_size);
                if (result != OS_SUCCESS)
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
                // Display warning message for empty string values
                if (strlen(current_node->content) == 0)
                {
                    snprintf(err_buf, err_buf_size, "Configuration field '%s' has an empty value in module 'indexer'. Check configuration", node_keypath);
                    os_free(node_keypath);
                    return OS_INVALID;
                }

                // Validate certificate and key paths
                if (strcmp(current_node->element, XML_TAG_CERT) == 0) {
                    if (validate_certificate_path(current_node->content) != OS_SUCCESS) {
                        snprintf(err_buf, err_buf_size, "File '%s' not found for 'indexer.ssl.certificate' in module 'indexer'. Check configuration", current_node->content);
                        os_free(node_keypath);
                        return OS_INVALID;
                    }
                }
                if (strcmp(current_node->element, XML_TAG_KEY) == 0) {
                    if (validate_certificate_path(current_node->content) != OS_SUCCESS) {
                        snprintf(err_buf, err_buf_size, "File '%s' not found for 'indexer.ssl.key' in module 'indexer'. Check configuration", current_node->content);
                        os_free(node_keypath);
                        return OS_INVALID;
                    }
                }

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

    return OS_SUCCESS;
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

/**
 * @brief Retrieve and parse the indexer configuration from an XML file
 *
 * @param cnf_file Path to the configuration XML file
 * @param err_buf Buffer to store error messages
 * @param err_buf_size Size of the error buffer
 *
 * @return Dynamically allocated JSON string with indexer configuration on success,
 *         NULL on error (error message stored in err_buf)
 */
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

    // Search for wazuh_config element
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

        // Skip non-wazuh_config elements
        if (strcmp(current_root->element, XML_TAG_WAZUH_CONFIG) != 0)
        {
            continue;
        }

        XML_NODE ossec_children = OS_GetElementsbyNode(&xml, current_root);
        if (!ossec_children)
        {
            continue;
        }

        // Search for indexer element within wazuh_config
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
                snprintf(err_buf, err_buf_size, "Failed to create JSON object for indexer configuration");
                XML_NODE nodes_to_clear[] = {root_nodes, ossec_children};
                cleanup_xml_resources(&xml, nodes_to_clear, 2);
                return NULL;
            }

            XML_NODE indexer_children = OS_GetElementsbyNode(&xml, current_child);

            // Check if indexer configuration is empty
            if (!indexer_children || indexer_children[0] == NULL)
            {
                snprintf(err_buf, err_buf_size, "Empty configuration for module 'indexer'");
                cJSON_Delete(config_json);
                XML_NODE nodes_to_clear[] = {root_nodes, ossec_children, indexer_children};
                cleanup_xml_resources(&xml, nodes_to_clear, 3);
                return NULL;
            }

            int parse_result = parse_indexer_subnodes(&xml, indexer_children, config_json, INDEXER_ROOT_PATH, err_buf, err_buf_size);

            if (parse_result != OS_SUCCESS)
            {
                cJSON_Delete(config_json);
                XML_NODE nodes_to_clear[] = {root_nodes, ossec_children, indexer_children};
                cleanup_xml_resources(&xml, nodes_to_clear, 3);
                return NULL;
            }

            // Validate required fields
            if (!cJSON_GetObjectItem(config_json, "hosts") || !cJSON_GetObjectItem(config_json, "ssl"))
            {
                snprintf(err_buf, err_buf_size, "Missing required configuration in module 'indexer'. Check configuration");
                cJSON_Delete(config_json);
                XML_NODE nodes_to_clear[] = {root_nodes, ossec_children, indexer_children};
                cleanup_xml_resources(&xml, nodes_to_clear, 3);
                return NULL;
            }

            if (indexer_config_json)
            {
                cJSON_free(indexer_config_json);
            }

            // Convert JSON to string
            indexer_config_json = cJSON_PrintUnformatted(config_json);
            cJSON_Delete(config_json);
            // Clear for possible new block
            OS_ClearNode(indexer_children);
        }

        if (indexer_config_json)
        {
            // indexer_children already freed
            XML_NODE nodes_to_clear[] = {root_nodes, ossec_children};
            cleanup_xml_resources(&xml, nodes_to_clear, 2);
            return indexer_config_json;
        }

        OS_ClearNode(ossec_children);
        snprintf(err_buf, err_buf_size, "Could not find <indexer> element in configuration file %s", cnf_file);
        XML_NODE nodes_to_clear[] = {root_nodes};
        cleanup_xml_resources(&xml, nodes_to_clear, 1);
        return NULL;
    }

    snprintf(err_buf, err_buf_size, "Could not find <wazuh_config> element in configuration file %s", cnf_file);
    XML_NODE nodes_to_clear[] = {root_nodes};
    cleanup_xml_resources(&xml, nodes_to_clear, 1);
    return NULL;
}
