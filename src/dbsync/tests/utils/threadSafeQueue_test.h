#pragma once
#include "gtest/gtest.h"

class ThreadSafeQueueTest : public ::testing::Test {

protected:

    ThreadSafeQueueTest() = default;
    virtual ~ThreadSafeQueueTest() = default;

    void SetUp() override;
    void TearDown() override;
};