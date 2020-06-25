#pragma once
#include "gtest/gtest.h"

class StringHelperTest : public ::testing::Test {

protected:

    StringHelperTest() = default;
    virtual ~StringHelperTest() = default;

    void SetUp() override;
    void TearDown() override;
};