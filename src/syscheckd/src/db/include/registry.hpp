/**
 * @file registry.hpp
 * @brief Definition of FIM database library.
 * @date 2019-08-28
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#include "syscheck-config.h"

#ifndef _REGISTRY_HPP_
#define _REGISTRY_HPP_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32

// Registry functions.

/**
 * @brief Get registry data using its key_id and name.
 *
 * @param key_id ID of the registry.
 * @param name Name of the registry value.
 *
 * @return FIM registry data struct on success, NULL on error.
 */
fim_registry_value_data* fim_db_get_registry_data(unsigned int key_id, const char* name);

/**
 * @brief Get a registry key using its path.
 *
 * @param arch An integer specifying the bit count of the register element, must be ARCH_32BIT or ARCH_64BIT.
 * @param path Path to registry key.
 * @param arch Architecture of the registry
 *
 * @return FIM registry key struct on success, NULL on error.
*/
fim_registry_key* fim_db_get_registry_key(const char* path, unsigned int arch);


/**
 * @brief Insert or update registry data.
 *
 * @param fim_sql FIM database struct.
 * @param data Registry data to be inserted.
 * @param key_id Registry key ID.
 * @param replace_entry 0 if a new registry_data entry is being inserted.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_data(fim_registry_value_data* data);

/**
 * @brief Insert or update registry key.
 *
 * @param entry Registry key to be inserted.
 * @param rowid Row id of the registry.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_insert_registry_key(fim_registry_key* entry);

/**
 * @brief Get count of all entries in registry data table.
 *
 * @return Number of entries in registry data table.
 */
int fim_db_get_count_registry_data();

/**
 * @brief Get count of all entries in registry key table.
 *
 * @return Number of entries in registry data table.
 */
int fim_db_get_count_registry_key();

/**
 * @brief Delete registry using registry entry.
 *
 * @param entry Registry entry.
 */
int fim_db_remove_registry_key(fim_registry_key* entry);

/**
 * @brief Delete registry data using fim_registry_value_data entry.
 *
 * @param entry fim_registry_value_data entry.
 *
 * @return FIMDB_OK on success, FIMDB_ERR otherwise.
 */
int fim_db_remove_registry_value_data(fim_registry_value_data* entry);

/**
 * @brief Get a registry using it's id.
 *
 * @param key_id Id of the registry key
 *
 * @return fim_registry_key structure.
 */
fim_registry_key* fim_db_get_registry_key_using_id(unsigned int key_id);

#endif /* WIN32 */
#ifdef __cplusplus
}
#endif // _cplusplus
#endif // _REGISTRY_HPP_
