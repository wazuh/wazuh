#ifndef CLIENT
#ifndef WIN32

#ifndef ENGINE_EXTERNAL_H
#define ENGINE_EXTERNAL_H

#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Parse and extract indexer configuration from XML configuration file
 *
 * This function reads a Wazuh XML configuration file, locates the <indexer>
 * section within <ossec_config>, validates the configuration parameters,
 * and converts them to a JSON string format.
 *
 * Supported configuration paths:
 * - indexer.enabled: Enable/disable indexer functionality
 * - indexer.hosts: Array of indexer host addresses
 * - indexer.ssl: SSL/TLS configuration section
 * - indexer.ssl.certificate_authorities: Array of CA certificates
 * - indexer.ssl.certificate: Client certificate path
 * - indexer.ssl.key: Client private key path
 *
 * @param cnf_file Path to the XML configuration file to parse
 * @param err_buf Buffer to store error messages if parsing fails
 * @param err_buf_size Size of the error buffer
 *
 * @return Dynamically allocated JSON string containing indexer configuration,
 *         or NULL if parsing fails. The caller is responsible for freeing
 *         the returned string using free().
 *
 * @note The returned string is allocated using cJSON_PrintUnformatted()
 *       and must be freed by the caller.
 * @note Invalid configuration paths will generate warnings but won't stop parsing
 * @note Empty arrays for required fields will cause parsing to fail
 */
char* get_indexer_cnf(const char* cnf_file, char* err_buf, size_t err_buf_size);



#endif // ENGINE_EXTERNAL_H
#endif // WIN32
#endif // CLIENT
