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

#ifdef __cplusplus
}
#endif
