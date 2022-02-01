/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2022, Wazuh Inc.
 * January 11, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DB_TEST_H
#define _DB_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "dbFileItem.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#include "db.h"
#include "fimDBTests/fimDBImpTests.hpp"


typedef struct txn_context_test_s {
    event_data_t *evt_data;
} txn_context_test;
MockLoggingCall* mockLog;
MockSyncMsg* mockSync;

void mockLoggingFunction(const modules_log_level_t logLevel, const char* tag)
{
    mockLog->loggingFunction(logLevel, tag);
}

void mockSyncMessage(const char* log, const char* tag)
{
    mockSync->syncMsg(log, tag);
}

class DBTestFixture : public testing::Test {
    protected:
        DBTestFixture() = default;
        virtual ~DBTestFixture() = default;

        txn_context_test txn_ctx;
        event_data_t evt_data;

        void SetUp() override
        {
            mockLog = new MockLoggingCall();
            mockSync = new MockSyncMsg();

            fim_db_init(FIM_DB_MEMORY,
                        300,
                        mockSyncMessage,
                        mockLoggingFunction,
                        MAX_FILE_LIMIT,
                        0,
                        false);

            evt_data = {};
            evt_data.report_event = true;
            evt_data.mode = FIM_SCHEDULED;
            evt_data.w_evt = NULL;
            txn_ctx = { .evt_data = &evt_data };
        }
        void TearDown() override
        {
            fim_db_teardown();
            delete mockLog;
            delete mockSync;
        }
};

class DBTestWinFixture : public ::testing::Test
{
    protected:
        DBTestWinFixture() = default;
        virtual ~DBTestWinFixture() = default;

        txn_context_test txn_ctx;
        event_data_t evt_data;

        void SetUp() override
        {
            fim_db_init(FIM_DB_MEMORY,
                        300,
                        nullptr,
                        nullptr,
                        MAX_FILE_LIMIT,
                        100000,
                        true);
            evt_data = {};
            evt_data.report_event = true;
            evt_data.mode = FIM_SCHEDULED;
            evt_data.w_evt = NULL;
            txn_ctx = { .evt_data = &evt_data };
        }

        void TearDown() override
        {
            fim_db_teardown();
        };
};
#endif //_DB_TEST_H
