#pragma once
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class ThreadDispatcherTest : public ::testing::Test {

protected:

    ThreadDispatcherTest() = default;
    virtual ~ThreadDispatcherTest() = default;

    void SetUp() override;
    void TearDown() override;
};