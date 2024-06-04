/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "conditionSync_test.hpp"
#include "conditionSync.hpp"
#include "gtest/gtest.h"
#include <chrono>
#include <thread>

/**
 * @brief Tests initial value of the condition
 */
TEST_F(ConditionSyncTest, TestInitialValue)
{
    {
        ConditionSync conditionSync(false);
        EXPECT_FALSE(conditionSync.check());
    }

    {
        ConditionSync conditionSync(true);
        EXPECT_TRUE(conditionSync.check());
    }
}

/**
 * @brief Tests that the value of the condition changes
 */
TEST_F(ConditionSyncTest, TestChangingTheValue)
{
    {
        ConditionSync conditionSync(false);
        conditionSync.set(true);
        EXPECT_TRUE(conditionSync.check());
    }

    {
        ConditionSync conditionSync(true);
        conditionSync.set(false);
        EXPECT_FALSE(conditionSync.check());
    }
}

/**
 * @brief Tests waiting for the value to change within the wait period
 */
TEST_F(ConditionSyncTest, TestWaitingForValueChange)
{

    ConditionSync conditionSync(false);
    std::thread t1(
        [&conditionSync]()
        {
            const auto maxWaitTime {std::chrono::seconds(2)};
            auto start {std::chrono::high_resolution_clock::now()};

            // The condition must be true when the function returns
            EXPECT_TRUE(conditionSync.waitFor(maxWaitTime));
            auto end {std::chrono::high_resolution_clock::now()};

            // The waited time must be less than the max wait time
            EXPECT_TRUE(end - start < maxWaitTime);
        });

    // Wait for some time
    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    // Set condition to true
    conditionSync.set(true);

    t1.join();
}

/**
 * @brief Tests waiting for the value to change, exit on timeout
 */
TEST_F(ConditionSyncTest, TestWaitingForWithTimeout)
{

    ConditionSync conditionSync(false);
    std::thread t1(
        [&conditionSync]()
        {
            const auto maxWaitTime {std::chrono::milliseconds(100)};

            auto start {std::chrono::high_resolution_clock::now()};

            // The condition must be false when the function returns because it exits on timeout
            EXPECT_FALSE(conditionSync.waitFor(maxWaitTime));
            auto end {std::chrono::high_resolution_clock::now()};

            // The waited time must be greater than or equal to the max wait time
            EXPECT_TRUE(end - start >= maxWaitTime);
        });

    // The condition value does not change, waitFor will exit on timeout

    t1.join();
}

/**
 * @brief Tests waiting for the value to change within the wait period, two threads
 */
TEST_F(ConditionSyncTest, TestWaitingForTwoThreads)
{

    ConditionSync conditionSync(false);
    std::thread t1(
        [&conditionSync]()
        {
            const auto maxWaitTime {std::chrono::seconds(2)};
            auto start {std::chrono::high_resolution_clock::now()};

            // The condition must be true when the function returns
            EXPECT_TRUE(conditionSync.waitFor(maxWaitTime));
            auto end {std::chrono::high_resolution_clock::now()};

            // The waited time must be less than the max wait time
            EXPECT_TRUE(end - start < maxWaitTime);
        });
    std::thread t2(
        [&conditionSync]()
        {
            const auto maxWaitTime {std::chrono::seconds(1)};
            auto start {std::chrono::high_resolution_clock::now()};

            // The condition must be true when the function returns
            EXPECT_TRUE(conditionSync.waitFor(maxWaitTime));
            auto end {std::chrono::high_resolution_clock::now()};

            // The waited time must be less than the max wait time
            EXPECT_TRUE(end - start < maxWaitTime);
        });

    // Wait for some time
    std::this_thread::sleep_for(std::chrono::milliseconds(30));

    // Set condition to true
    conditionSync.set(true);

    t1.join();
    t2.join();
}

/**
 * @brief Tests waiting for the value to change, exit on timeout
 */
TEST_F(ConditionSyncTest, TestWaitingForWithTimeoutTwoThreads)
{

    ConditionSync conditionSync(false);

    std::thread t1(
        [&conditionSync]()
        {
            const auto maxWaitTime {std::chrono::milliseconds(50)};

            auto start {std::chrono::high_resolution_clock::now()};

            // The condition must be false when the function returns because it exits on timeout
            EXPECT_FALSE(conditionSync.waitFor(maxWaitTime));
            auto end {std::chrono::high_resolution_clock::now()};

            // The waited time must be greater than or equal to the max wait time
            EXPECT_TRUE(end - start >= maxWaitTime);
        });
    std::thread t2(
        [&conditionSync]()
        {
            const auto maxWaitTime {std::chrono::milliseconds(40)};

            auto start {std::chrono::high_resolution_clock::now()};

            // The condition must be false when the function returns because it exits on timeout
            EXPECT_FALSE(conditionSync.waitFor(maxWaitTime));
            auto end {std::chrono::high_resolution_clock::now()};

            // The waited time must be greater than or equal to the max wait time
            EXPECT_TRUE(end - start >= maxWaitTime);
        });

    // The condition value does not change, waitFor will exit on timeout.

    t1.join();
    t2.join();
}
