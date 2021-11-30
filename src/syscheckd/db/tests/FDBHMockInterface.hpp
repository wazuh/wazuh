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
        FIMDBHelpersMock::getInstance().initDBMock(sync_interval, file_limit, sync_callback, logCallback, handler_DBSync, handler_RSync);
    }
#else

    void initDB(unsigned int sync_interval, unsigned int file_limit, unsigned int registry_limit,
                             fim_sync_callback_t sync_callback, logging_callback_t logCallback,
                             std::shared_ptr<DBSync>handler_DBSync, std::shared_ptr<RemoteSync>handler_RSync)
    {
        FIMDBHelpersMock::getInstance().initDBMock(sync_interval, file_limit, registry_limit, sync_callback, logCallback, handler_DBSync,
                              handler_RSync);
    }
#endif


    int removeFromDB(const std::string& tableName, const nlohmann::json& filter)
    {
        return FIMDBHelpersMock::getInstance().removeFromDBMock(tableName, filter);
    }

    int getCount(const std::string & tableName, int & count)
    {
        return FIMDBHelpersMock::getInstance().getCountMock(tableName, count);
    }

    int insertItem(const std::string & tableName, const nlohmann::json & item)
    {
        return FIMDBHelpersMock::getInstance().insertItemMock(tableName, item);
    }

    int updateItem(const std::string & tableName, const nlohmann::json & item)
    {

        return FIMDBHelpersMock::getInstance().updateItemMock(tableName, item);
    }

    int getDBItem(nlohmann::json & item, const nlohmann::json & query)
    {
        return FIMDBHelpersMock::getInstance().executeQueryMock(item, query);
    }
}

#endif
