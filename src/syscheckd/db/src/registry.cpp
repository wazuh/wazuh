/**
 * @file fim_db_registries.c
 * @brief Definition of FIM database for registries library.
 * @date 2020-09-9
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#include <iostream>
#include <string.h>

#ifdef WAZUH_UNIT_TESTING
    #include "fimDBHelpersUTInterface.hpp"
#else
    #include "fimDBHelper.hpp"
    #include "fimDB.hpp"
#endif

#include "dbRegistryValue.hpp"
#include "dbRegistryKey.hpp"
#include "fimCommonDefs.h"
#include "registry.hpp"

#ifdef __cplusplus
extern "C" {
#endif

extern const char* SQL_STMT[];

const char* registry_arch[] =
{
    [ARCH_32BIT] = "[x32]",
    [ARCH_64BIT] = "[x64]"
};

int fim_db_remove_registry_key(fim_registry_key* key_entry)
{

    std::string filter = "WHERE id = " + std::to_string(key_entry->id) + " AND arch = " +
                         std::to_string(key_entry->arch);

    try
    {
        FIMDBHelper::removeFromDB<FIMDB>(std::string(FIMDB_REGISTRY_KEY_TABLENAME), filter);
        return FIMDB_OK;
    } catch(std::exception& ex)
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return FIMDB_ERR;
    }
}

int fim_db_remove_registry_value_data(fim_registry_value_data* value_entry)
{

    std::string filter = "WHERE key_id = " + std::to_string(value_entry->id) + " AND name = " +
                         std::to_string(*value_entry->name);

    try
    {
        FIMDBHelper::removeFromDB<FIMDB>(std::string(FIMDB_REGISTRY_VALUE_TABLENAME), filter);
        return FIMDB_OK;
    } catch(std::exception& ex)
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return FIMDB_ERR;
    }
}

fim_registry_value_data* fim_db_get_registry_data(unsigned int key_id, const char* name)
{

    nlohmann::json dbItem;
    std::string strName(name);

    std::string rawFilter = "WHERE name = " + strName + " AND key_id = " + std::to_string(key_id);
    nlohmann::json columnList;
    columnList["column_list"] = "[*]";

    nlohmann::json query = FIMDBHelper::dbQuery(std::string(FIMDB_REGISTRY_VALUE_TABLENAME), columnList, rawFilter, "");

    try
    {
        FIMDBHelper::getDBItem<FIMDB>(dbItem, query);
    }catch(std::exception& ex)
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return 0;
    }

    RegistryValue reg_value(dbItem);
    return (reg_value.toFimEntry())->registry_entry.value;
}

fim_registry_key* fim_db_get_registry_key(const char* path, unsigned int arch)
{
    nlohmann::json dbItem;
    std::string strPath(path);

    std::string rawFilter = "WHERE path = " + strPath + " AND arch = " + std::to_string(arch);
    nlohmann::json columnList;
    columnList["column_list"] = "[*]";

    nlohmann::json query = FIMDBHelper::dbQuery(std::string(FIMDB_REGISTRY_KEY_TABLENAME), columnList, rawFilter, "");
    try
    {
        FIMDBHelper::getDBItem<FIMDB>(dbItem, query);
    }catch(std::exception& ex)
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return 0;
    }

    RegistryKey reg_key(dbItem);
    return reg_key.toFimEntry()->registry_entry.key;

}

fim_registry_key* fim_db_get_registry_key_using_id(unsigned int key_id)
{
    nlohmann::json dbItem;

    std::string rawFilter = "WHERE item_id = " + std::to_string(key_id);
    nlohmann::json columnList;
    columnList["column_list"] = "[*]";

    nlohmann::json query = FIMDBHelper::dbQuery(std::string(FIMDB_REGISTRY_KEY_TABLENAME), columnList, rawFilter, "");

    try
    {
        FIMDBHelper::getDBItem<FIMDB>(dbItem, query);
    }catch(std::exception& ex)
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return 0;
    }

    RegistryKey reg_key(dbItem);
    return reg_key.toFimEntry()->registry_entry.key;
}

int fim_db_get_count_registry_key()
{
    int res = 0;

    try
    {
        FIMDBHelper::getCount<FIMDB>(std::string(FIMDB_REGISTRY_KEY_TABLENAME), res);
    } catch(std::exception& ex) // EMPTY_TABLE_METADATA
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return FIMDB_ERR;
    }

    return res;
}

int fim_db_get_count_registry_data()
{
    int res = 0;
    try
    {
        FIMDBHelper::getCount<FIMDB>(std::string(FIMDB_REGISTRY_VALUE_TABLENAME), res);
    } catch(std::exception& ex) // EMPTY_TABLE_METADATA
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return FIMDB_ERR;
    }

    return res;
}

int fim_db_insert_registry_data(fim_registry_value_data* data)
{
    fim_entry regValueEntry;
    regValueEntry.registry_entry.value = data;
    RegistryValue regValue(&regValueEntry);

    try
    {
        FIMDBHelper::updateItem<FIMDB>(std::string(FIMDB_REGISTRY_VALUE_TABLENAME), *regValue.toJSON());
    }
    catch(const std::exception& ex)
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

int fim_db_insert_registry_key(fim_registry_key* entry)
{

    fim_entry regEntryKey;
    regEntryKey.registry_entry.key = entry;
    RegistryKey regKey(&regEntryKey);

    try
    {
        FIMDBHelper::updateItem<FIMDB>(std::to_string(*FIMDB_REGISTRY_KEY_TABLENAME), *regKey.toJSON());
    }
    catch(const std::exception& ex)
    {
        FIMDB::getInstance().loggingFunction(LOG_ERROR, ex.what());
        return FIMDB_ERR;
    }

    return FIMDB_OK;
}

}
