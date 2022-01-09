/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 24, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMDB_UTILS_TEST_H
#define _FIMDB_UTILS_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "fimCommonDefs.h"
#include "dbsync.hpp"
#include "rsync.hpp"

class FIMDBMOCK final
{

    public:
        static FIMDBMOCK& getInstance()
        {
            static FIMDBMOCK s_instance;
            return s_instance;
        };

        MOCK_METHOD(void, init, (unsigned int,
                                 fim_sync_callback_t,
                                 logging_callback_t,
                                 std::shared_ptr<DBSync>,
                                 std::shared_ptr<RemoteSync>,
                                 unsigned int,
                                 unsigned int,
                                 bool), ());
        MOCK_METHOD(void, removeItem, (const nlohmann::json&), ());
        MOCK_METHOD(void, updateItem, (const nlohmann::json&, ResultCallbackData), ());
        MOCK_METHOD(void, executeQuery, (const nlohmann::json&, ResultCallbackData), ());
        MOCK_METHOD(void, logFunction, (const modules_log_level_t logLevel, const std::string& msg), ());

    private:
        FIMDBMOCK() = default;
        ~FIMDBMOCK() = default;

};


class FIMWrapperTest : public testing::Test {
    protected:
        FIMWrapperTest() = default;
        virtual ~FIMWrapperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

class FIMDBUtilsTest : public testing::Test {
    protected:
        FIMDBUtilsTest() = default;
        virtual ~FIMDBUtilsTest() = default;

        void SetUp() override;
        void TearDown() override;
};

class CallbackMock
{
    public:
        CallbackMock() = default;
        ~CallbackMock() = default;
        MOCK_METHOD(void, callbackMock, (ReturnTypeCallback type, nlohmann::json&), ());
};

#endif //_FIMDB_UTILS_TEST_H
