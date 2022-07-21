/*
 * Wazuh DBSYNC
 * Copyright (C) 2015, Wazuh Inc.
 * August 6, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _DBYSNC_FIM_INTEGRATION_TEST_H
#define _DBYSNC_FIM_INTEGRATION_TEST_H

#include "gtest/gtest.h"
#include "gmock/gmock.h"

class DBSyncFimIntegrationTest : public ::testing::Test
{
    protected:

        DBSyncFimIntegrationTest();
        virtual ~DBSyncFimIntegrationTest();

        void SetUp() override;
        void TearDown() override;
        const DBSYNC_HANDLE m_dbHandle;
};

#endif // _DBYSNC_FIM_INTEGRATION_TEST_H
