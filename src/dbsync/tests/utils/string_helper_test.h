#pragma once
#include "gtest/gtest.h"

class StringUtilsTest : public ::testing::Test {

protected:

    StringUtilsTest() = default;
    virtual ~StringUtilsTest() = default;

    void SetUp() override;
    void TearDown() override;
};