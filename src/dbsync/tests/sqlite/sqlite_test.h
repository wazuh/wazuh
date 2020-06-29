#pragma once
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class SQLiteTest : public ::testing::Test {

protected:

    SQLiteTest() = default;
    virtual ~SQLiteTest() = default;

    void SetUp() override;
    void TearDown() override;
};