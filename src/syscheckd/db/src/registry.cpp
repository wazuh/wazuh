/**
 * @file fim_db_registries.c
 * @brief Definition of FIM database for registries library.
 * @date 2020-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include "db.h"

extern const char* SQL_STMT[];

const char* registry_arch[] =
{
    [ARCH_32BIT] = "[x32]",
    [ARCH_64BIT] = "[x64]"
};

int fim_db_remove_registry_key(fim_entry* entry)
{
    /* TODO: Add c++ code to delete a registry from key_id
    */
    return FIMDB_OK;
}

int fim_db_remove_registry_value_data(fim_registry_value_data* entry)
{
    /* TODO: Add c++ code to delete a registry from fim_registry_value_data
    */

    return FIMDB_OK;
}

// Registry functions
int fim_db_get_registry_key_rowid(const char* path, unsigned int arch, unsigned int* rowid)
{
    /* TODO: Add c++ code to get a registry key from path, arch and rowid
    */

    return FIMDB_OK;
}

fim_registry_value_data* fim_db_get_registry_data(unsigned int key_id, const char* name)
{
    fim_registry_value_data* value = NULL;
    /* TODO: Add c++ code to get a registry data from key_id and name
    */

    return value;
}

fim_registry_key* fim_db_get_registry_key(const char* path, unsigned int arch)
{
    fim_registry_key* reg_key = NULL;
    /* TODO: Add c++ code to get a registry key from path and arch
    */

    return reg_key;
}

fim_registry_key* fim_db_get_registry_key_using_id(unsigned int id)
{
    fim_registry_key* reg_key = NULL;
    /* TODO: Add c++ code to get a registry key from id
    */

    return reg_key;
}

int fim_db_get_count_registry_key()
{
    int res = 0;
    /* TODO: Add c++ code to count registry keys
    */

    return res;
}

int fim_db_get_count_registry_data()
{
    int res = 0;
    /* TODO: Add c++ code to get a registry key from path and arch
    */

    return res;
}

int fim_db_insert_registry_data(fim_registry_value_data* data,
                                unsigned int key_id,
                                unsigned int replace_entry)
{
    int res = 0;
    /* TODO: Add c++ code to insert or update a registry data
    */

    return FIMDB_OK;
}

int fim_db_insert_registry_key(fim_registry_key* entry, unsigned int rowid)
{
    int res = 0;
    /* TODO: Add c++ code to insert or update a registry key
    */

    return FIMDB_OK;
}

#ifdef __cplusplus
}
#endif
