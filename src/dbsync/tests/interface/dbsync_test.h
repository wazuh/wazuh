#pragma once
#include "gtest/gtest.h"

class DBSyncTest : public ::testing::Test 
{
protected:

    DBSyncTest() = default;
    virtual ~DBSyncTest() = default;

    void SetUp() override;
    void TearDown() override;
};