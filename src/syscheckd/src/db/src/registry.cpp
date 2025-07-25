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

#ifdef __cplusplus
}
#endif
