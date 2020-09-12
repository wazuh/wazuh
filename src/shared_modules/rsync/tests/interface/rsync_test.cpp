/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * August 28, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "rsync_test.h"
#include "rsync.h"


static void logFunction(const char* msg)
{
    if (msg)
    {
        std::cout << msg << std::endl;
    }
}

void RSyncTest::SetUp()
{
    rsync_initialize(&logFunction);
};

void RSyncTest::TearDown()
{
    EXPECT_NO_THROW(rsync_teardown());
};

TEST_F(RSyncTest, Initialization)
{
    const auto handle { rsync_create() };
    ASSERT_NE(nullptr, handle);
}

TEST_F(RSyncTest, startSync)
{
    const auto handle { rsync_create() };
    ASSERT_EQ(0, rsync_start_sync(handle));
}

TEST_F(RSyncTest, registerSyncId)
{
    const auto handle { rsync_create() };
    ASSERT_EQ(0, rsync_register_sync_id(handle, nullptr, nullptr, nullptr, {}));
}

TEST_F(RSyncTest, pushMessage)
{
    const std::string buffer{"test buffer"};
    const auto handle { rsync_create() };
    ASSERT_NE(0, rsync_push_message(handle, nullptr, 1000));
    ASSERT_NE(0, rsync_push_message(handle, reinterpret_cast<const void*>(0x1000), 0));
    ASSERT_EQ(0, rsync_push_message(handle, reinterpret_cast<const void*>(buffer.data()), buffer.size()));
}

TEST_F(RSyncTest, CloseWithoutInitialization)
{
    
    EXPECT_EQ(-1, rsync_close(nullptr));
}

TEST_F(RSyncTest, CloseCorrectInitialization)
{
    const auto handle { rsync_create() };
    ASSERT_NE(nullptr, handle);
    EXPECT_EQ(0, rsync_close(handle));
}