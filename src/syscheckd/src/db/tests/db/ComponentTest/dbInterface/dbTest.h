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


typedef struct fim_txn_context_s {
    event_data_t *evt_data;
} txn_context_test;

class DBTestFixture : public testing::Test {
    protected:
        DBTestFixture() = default;
        virtual ~DBTestFixture() = default;

        txn_context_test txn_ctx;
        event_data_t evt_data;

        void SetUp() override
        {
            fim_db_init(FIM_DB_MEMORY,
                        300,
                        nullptr,
                        nullptr,
                        MAX_FILE_LIMIT,
                        0,
                        false);
            evt_data = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
            txn_ctx = { .evt_data = &evt_data };
        }
        void TearDown() override
        {
            fim_db_teardown();
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
            evt_data = { .report_event = true, .mode = FIM_SCHEDULED, .w_evt = NULL };
            txn_ctx = { .evt_data = &evt_data };
        }

        void TearDown() override
        {
            fim_db_teardown();
        };
};
#endif //_DB_TEST_H
