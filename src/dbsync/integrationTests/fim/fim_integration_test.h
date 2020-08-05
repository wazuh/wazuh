/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
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
    virtual ~DBSyncFimIntegrationTest() = default;

    void SetUp() override;
    void TearDown() override;
    DBSYNC_HANDLE m_dbHandle;
    const std::string m_fimSqlSchema;
};

#endif // _DBYSNC_FIM_INTEGRATION_TEST_H
