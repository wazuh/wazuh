/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 5, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FIMHELPER_TEST_H
#define _FIMHELPER_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class FIMDBMOCK final
{

    public:
        static FIMDBMOCK& getInstance()
        {
            static FIMDBMOCK s_instance;
            return s_instance;
        };
        MOCK_METHOD(int, insertItem, (const nlohmann::json&), ());
        MOCK_METHOD(int, removeItem, (const nlohmann::json&), ());
        MOCK_METHOD(int, updateItem, (const nlohmann::json&, ResultCallbackData), ());
        MOCK_METHOD(int, executeQuery, (const nlohmann::json&, ResultCallbackData), ());

    private:
        FIMDBMOCK() = default;
        ~FIMDBMOCK() = default;

};

class FIMHelperTest : public testing::Test {
    protected:
        FIMHelperTest() = default;
        virtual ~FIMHelperTest() = default;

        void SetUp() override;
        void TearDown() override;
};

#endif //_FIMHELPER_TEST_H
