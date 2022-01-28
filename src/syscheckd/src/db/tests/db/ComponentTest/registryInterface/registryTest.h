/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * December 31, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRY_TEST_H
#define _REGISTRY_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "dbFileItem.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#include "db.h"
#include "fimDBTests/fimDBImpTests.hpp"

typedef struct fim_txn_context_s {
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

class RegistryTestWinFixture : public ::testing::Test
{
    protected:
        RegistryTestWinFixture() = default;
        virtual ~RegistryTestWinFixture() = default;

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
                        100000,
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
            delete mockLog;
            delete mockSync;
        };
};

#endif //_REGISTRY_TEST_H
