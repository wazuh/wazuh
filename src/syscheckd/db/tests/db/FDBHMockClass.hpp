#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "fimDB.hpp"

#ifndef _FIM_DB_HELPERS_MOCK_CLASS_
#define _FIM_DB_HELPERS_MOCK_CLASS_

class FIMDBHelpersMock
{
    public:
        static FIMDBHelpersMock& getInstance()
        {
            static FIMDBHelpersMock mock;
            return mock;
        }

        MOCK_METHOD(void, initDB, (unsigned int, unsigned int,
                                   fim_sync_callback_t, logging_callback_t,
                                   std::shared_ptr<DBSync>, std::shared_ptr<RemoteSync>), ());
        MOCK_METHOD(void, initDB, (unsigned int, unsigned int, unsigned int, fim_sync_callback_t, logging_callback_t,
                                   std::shared_ptr<DBSync>, std::shared_ptr<RemoteSync>), ());
        MOCK_METHOD(void, removeFromDB, (const std::string&, const nlohmann::json&), ());
        MOCK_METHOD(void, getCount, (const std::string&, int&), ());
        MOCK_METHOD(void, updateItem, (const std::string&, const nlohmann::json&), ());
        MOCK_METHOD(void, getDBItem, (nlohmann::json&, const nlohmann::json&), ());
        MOCK_METHOD(void, removeItem, (const std::string&, const nlohmann::json&), ());
        MOCK_METHOD(void, executeQuery, (nlohmann::json&, const nlohmann::json&), ());
};

#endif
