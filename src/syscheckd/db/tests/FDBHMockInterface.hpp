#include "fimDB.hpp"
#include "FDBHMockClass.hpp"

#ifndef _FIMDB_HELPERS_MOCK_INTERFACE_
#define _FIMDB_HELPERS_MOCK_INTERFACE_

namespace FIMDBHelpersUTInterface {

#ifndef WIN32

    void initDB(unsigned int sync_interval, unsigned int file_limit,
                            fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                            std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        FIMDBHelpersMock::getInstance().initDB(sync_interval, file_limit, sync_callback, logCallback, handler_DBSync, handler_RSync);
    }
#else

    void initDB(unsigned int sync_interval, unsigned int file_limit, unsigned int registry_limit,
                             fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                             std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        FIMDBHelpersMock::getInstance().initDB(sync_interval, file_limit, registry_limit, sync_callback, logCallback, handler_DBSync,
                              handler_RSync);
    }
#endif


    void removeFromDB(const std::string& tableName, const nlohmann::json& filter)
    {
        FIMDBHelpersMock::getInstance().removeFromDB(tableName, filter);
    }

    void getCount(const std::string & tableName, int & count)
    {
        FIMDBHelpersMock::getInstance().getCount(tableName, count);
    }

    void insertItem(const std::string & tableName, const nlohmann::json & item)
    {
        FIMDBHelpersMock::getInstance().insertItem(tableName, item);
    }

    void updateItem(const std::string & tableName, const nlohmann::json & item)
    {

        FIMDBHelpersMock::getInstance().updateItem(tableName, item);
    }

    void getDBItem(nlohmann::json & item, const nlohmann::json & query)
    {
        FIMDBHelpersMock::getInstance().executeQuery(item, query);
    }
}

#endif
