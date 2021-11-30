#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "fimDB.hpp"

#ifndef _FIM_DB_HELPERS_MOCK_CLASS_
#define _FIM_DB_HELPERS_MOCK_CLASS_

class FIMDBHelpersMock {
    public:
        static FIMDBHelpersMock& getInstance(){
            static FIMDBHelpersMock mock;
            return mock;
        }

        MOCK_METHOD(void, initDBMock, (unsigned int, unsigned int,
                                fim_sync_callback_t, logging_callback_t,
                                std::shared_ptr<DBSync>, std::shared_ptr<RemoteSync>), ());
        MOCK_METHOD(void, initDBMock, (unsigned int, unsigned int, unsigned int, fim_sync_callback_t, logging_callback_t,
                                std::shared_ptr<DBSync>, std::shared_ptr<RemoteSync>), ());
        MOCK_METHOD(int, removeFromDBMock, (const std::string&, const nlohmann::json&), ());
        MOCK_METHOD(int, getCountMock, (const std::string&, int&), ());
        MOCK_METHOD(int, insertItemMock, (const std::string&, const nlohmann::json&), ());
        MOCK_METHOD(int, updateItemMock, (const std::string&, const nlohmann::json&), ());
        MOCK_METHOD(int, getDBItemMock, (nlohmann::json&, const nlohmann::json&), ());
        MOCK_METHOD(int, removeItemMock, (const std::string&, const nlohmann::json&), ());
        MOCK_METHOD(int, executeQueryMock, (nlohmann::json&, const nlohmann::json&), ());
};

#endif
