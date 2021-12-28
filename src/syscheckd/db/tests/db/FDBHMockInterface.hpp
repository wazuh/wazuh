#include "fimDB.hpp"
#include "FDBHMockClass.hpp"

#ifndef _FIMDB_HELPERS_MOCK_INTERFACE_
#define _FIMDB_HELPERS_MOCK_INTERFACE_

namespace FIMDBHelpersUTInterface
{


    void initDB(const unsigned int syncInterval,
                fim_sync_callback_t syncCallback,
                logging_callback_t logCallback,
                std::shared_ptr<DBSync>handlerDBSync,
                std::shared_ptr<RemoteSync>handlerRSync,
                const unsigned int fileLimit,
                const unsigned int registryLimit = 0,
                const bool isWindows = false)
    {
        FIMDBHelpersMock::getInstance().initDB(syncInterval,
                                               syncCallback,
                                               logCallback,
                                               handlerDBSync,
                                               handlerRSync,
                                               fileLimit,
                                               registryLimit,
                                               isWindows);
    }

    void removeFromDB(const std::string& tableName, const nlohmann::json& filter)
    {
        FIMDBHelpersMock::getInstance().removeFromDB(tableName, filter);
    }

    void getCount(const std::string& tableName, int& count)
    {
        FIMDBHelpersMock::getInstance().getCount(tableName, count);
    }

    void updateItem(const std::string& tableName, const nlohmann::json& item)
    {

        FIMDBHelpersMock::getInstance().updateItem(tableName, item);
    }

    void getDBItem(nlohmann::json& item, const nlohmann::json& query)
    {
        FIMDBHelpersMock::getInstance().executeQuery(item, query);
    }
}

#endif
