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
#include "db.h"
#include "dbFileItem.hpp"
#include "dbRegistryKey.hpp"
#include "dbRegistryValue.hpp"
#include "fimDBTests/fimDBImpTests.hpp"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

typedef struct callback_ctx_test_s
{
    event_data_t* event;
    const directory_t* config;
    fim_entry* entry;
} callback_ctx_test;
typedef struct txn_context_test_s
{
    event_data_t* evt_data;
} txn_context_test;
MockLoggingCall* mockLog;
callback_context_t callback_data_added;
callback_context_t callback_data_modified;
callback_context_t callback_null;
event_data_t evt_data1;
event_data_t evt_data2;
directory_t configuration1;
directory_t configuration2;
callback_ctx_test ctx1;
callback_ctx_test ctx2;

void mockLoggingFunction(const modules_log_level_t logLevel, const char* tag)
{
    mockLog->loggingFunction(logLevel, tag);
}

static void callbackFileUpdateAdded(ReturnTypeCallback result_type, const cJSON* result_json, void* user_data)
{
    ASSERT_TRUE(result_type == ReturnTypeCallback::INSERTED);
    ASSERT_TRUE(result_json);
    ASSERT_TRUE(user_data);
}

static void callbackFileUpdateModified(ReturnTypeCallback result_type, const cJSON* result_json, void* user_data)
{
    ASSERT_TRUE(result_type == ReturnTypeCallback::MODIFIED);
    ASSERT_TRUE(result_json);
    ASSERT_TRUE(user_data);
}

class DBTestFixture : public testing::Test
{
protected:
    DBTestFixture() = default;
    virtual ~DBTestFixture() = default;

    txn_context_test txn_ctx;
    event_data_t evt_data;

    void SetUp() override
    {
        mockLog = new MockLoggingCall();

        fim_db_init(FIM_DB_MEMORY, mockLoggingFunction, MAX_FILE_LIMIT, 100000, nullptr);

        evt_data = {};
        evt_data.report_event = true;
        evt_data.mode = FIM_SCHEDULED;
        evt_data.w_evt = NULL;
        txn_ctx = {.evt_data = &evt_data};

        evt_data1 = {};
        evt_data1.report_event = true;
        evt_data1.mode = FIM_REALTIME;
        evt_data1.w_evt = NULL;
        configuration1 = {};
        configuration1.options = -1;

        evt_data2 = {};
        evt_data2.report_event = true;
        evt_data2.mode = FIM_REALTIME;
        evt_data2.w_evt = NULL;
        configuration2 = {};
        configuration2.options = -1;

        ctx1 = {};
        ctx1.event = &evt_data1;
        ctx1.config = &configuration1;

        ctx2 = {};
        ctx2.event = &evt_data2;
        ctx2.config = &configuration2;

        callback_data_added.callback_txn = callbackFileUpdateAdded;
        callback_data_added.context = &ctx1;
        callback_data_modified.callback_txn = callbackFileUpdateModified;
        callback_data_modified.context = &ctx2;
        callback_null.callback = NULL;
        callback_null.context = NULL;
    }
    void TearDown() override
    {
        fim_db_teardown();
        delete mockLog;
    }
};

#endif //_DB_TEST_H
