/*
 * Wazuh router - Subscriber tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "src/subscriber.hpp"
#include <functional>
#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

/**
 * @brief Runs unit tests for Subscriber class
 */
class SubscriberTest : public ::testing::Test
{
protected:
    SubscriberTest() = default;
    ~SubscriberTest() override = default;
};

/*
 * @brief Test the instantiation of the Subscriber class
 */
TEST_F(SubscriberTest, TestSubscriberInstantiation)
{
    constexpr auto OBSERVER_ID {"subscriber-id"};
    const std::function<void(const std::vector<char>&)> callback;

    // Check that the Subscriber class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Subscriber<const std::vector<char>&>>(callback, OBSERVER_ID));
}

/*
 * @brief Tests the Subscriber class with empty observer id.
 */
TEST_F(SubscriberTest, TestSubscriberWithEmptyObserverId)
{
    constexpr auto OBSERVER_ID {""};
    const std::function<void(const std::vector<char>&)> callback;

    // Check that the Subscriber class can be instantiated
    EXPECT_NO_THROW(std::make_shared<Subscriber<const std::vector<char>&>>(callback, OBSERVER_ID));
}

/*
 * @brief Tests the update method call of the Subscriber class.
 */
TEST_F(SubscriberTest, TestSubscriberUpdateMethod)
{
    constexpr auto OBSERVER_ID {"subscriber-id"};
    constexpr auto EXPECTED_CAPTURED_OUTPUT {"hello!\n"};

    const std::vector<char> data = {'h', 'e', 'l', 'l', 'o', '!'};
    const std::function<void(const std::vector<char>&)> callback = [](const std::vector<char>& data)
    {
        std::cout << std::string(data.begin(), data.end()) << "\n";
    };

    const auto subscriber {std::make_shared<Subscriber<const std::vector<char>&>>(callback, OBSERVER_ID)};

    testing::internal::CaptureStdout();

    EXPECT_NO_THROW(subscriber->update(data));

    const auto capturedOutput {testing::internal::GetCapturedStdout()};

    EXPECT_EQ(capturedOutput, EXPECTED_CAPTURED_OUTPUT);
}
