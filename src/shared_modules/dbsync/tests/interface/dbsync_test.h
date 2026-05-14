/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * June 11, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBYSNC_TEST_H
#define _DBYSNC_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "commonDefs.h"

class DBSyncTest : public ::testing::Test
{
    protected:

        DBSyncTest() = default;
        virtual ~DBSyncTest() = default;

        void SetUp() override;
        void TearDown() override;
};

struct DummyContext
{
    DBSYNC_HANDLE handle;
    TXN_HANDLE    txnContext;
};

#endif // _DBYSNC_TEST_H
