/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 9, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <string.h>

#ifdef WAZUH_UNIT_TESTING
#include "fimDBHelpersUTInterface.hpp"
#else
#include "fimDB.hpp"
#endif

#include "db.h"
#include "db.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#include "fimCommonDefs.h"
#include "syscheck-config.h"

#ifdef __cplusplus
extern "C"
{
#endif

int fim_db_get_count_registry_key()
{
    auto count {0};

    try
    {
        count = DB::instance().countEntries(FIMDB_REGISTRY_KEY_TABLENAME, COUNT_SELECT_TYPE::COUNT_ALL);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

    return count;
}

int fim_db_get_count_registry_data()
{
    auto count {0};

    try
    {
        count = DB::instance().countEntries(FIMDB_REGISTRY_VALUE_TABLENAME, COUNT_SELECT_TYPE::COUNT_ALL);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

    return count;
}

int fim_db_get_max_version_registry()
{
    auto maxVersionKey {0};
    auto maxVersionValue {0};

    try
    {
        maxVersionKey = DB::instance().maxVersion(FIMDB_REGISTRY_KEY_TABLENAME);
        maxVersionValue = DB::instance().maxVersion(FIMDB_REGISTRY_VALUE_TABLENAME);
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP

    return maxVersionKey > maxVersionValue ? maxVersionKey : maxVersionValue;
}

int fim_db_set_version_registry(int version)
{
    auto retval {-1};

    try
    {
        int result_key = DB::instance().updateVersion(FIMDB_REGISTRY_KEY_TABLENAME, version);
        int result_value = DB::instance().updateVersion(FIMDB_REGISTRY_VALUE_TABLENAME, version);

        if (result_key != 0 || result_value != 0)
        {
            retval = -1;
        }
        else
        {
            retval = 0;
        }
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
        retval = -1;
    }

    // LCOV_EXCL_STOP

    return retval;
}

void fim_db_clean_registry_tables()
{
    try
    {
        // Delete all registry values first (foreign key constraint with registry_key)
        auto deleteValuesQuery
        {
            DeleteQuery::builder()
            .table(FIMDB_REGISTRY_VALUE_TABLENAME)
            .rowFilter("1=1")
            .build()
        };
        FIMDB::instance().removeItem(deleteValuesQuery.query());

        // Delete all registry keys
        auto deleteKeysQuery
        {
            DeleteQuery::builder()
            .table(FIMDB_REGISTRY_KEY_TABLENAME)
            .rowFilter("1=1")
            .build()
        };
        FIMDB::instance().removeItem(deleteKeysQuery.query());

        FIMDB::instance().logFunction(LOG_DEBUG, "Registry tables cleaned successfully");
    }
    // LCOV_EXCL_START
    catch (const std::exception& err)
    {
        FIMDB::instance().logFunction(LOG_ERROR, err.what());
    }

    // LCOV_EXCL_STOP
}

FIMDBErrorCode fim_db_registry_key_delete(const char* path, int arch)
{
    auto retVal {FIMDB_ERR};

    if (!path)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            std::string arch_str = (arch == ARCH_32BIT) ? "[x32]" : "[x64]";
            auto deleteQuery
            {
                DeleteQuery::builder()
                .table(FIMDB_REGISTRY_KEY_TABLENAME)
                .data({{"path", path}, {"architecture", arch_str}})
                .rowFilter("")
                .build()
            };
            FIMDB::instance().removeItem(deleteQuery.query());
            retVal = FIMDB_OK;
        }
        catch (const std::exception& err)
        {
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }
    }

    return retVal;
}

FIMDBErrorCode fim_db_registry_value_delete(const char* path, const char* value, int arch)
{
    auto retVal {FIMDB_ERR};

    if (!path || !value)
    {
        FIMDB::instance().logFunction(LOG_ERROR, "Invalid parameters");
    }
    else
    {
        try
        {
            std::string arch_str = (arch == ARCH_32BIT) ? "[x32]" : "[x64]";
            auto deleteQuery
            {
                DeleteQuery::builder()
                .table(FIMDB_REGISTRY_VALUE_TABLENAME)
                .data({{"path", path}, {"value", value}, {"architecture", arch_str}})
                .rowFilter("")
                .build()
            };
            FIMDB::instance().removeItem(deleteQuery.query());
            retVal = FIMDB_OK;
        }
        catch (const std::exception& err)
        {
            FIMDB::instance().logFunction(LOG_ERROR, err.what());
        }
    }

    return retVal;
}

#ifdef __cplusplus
}
#endif
