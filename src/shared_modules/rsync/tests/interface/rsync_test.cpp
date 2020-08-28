/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 11, 2020.
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