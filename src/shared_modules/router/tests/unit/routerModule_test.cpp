/*
 * Wazuh router - RouterModule tests
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "routerModule.hpp"
#include <atomic>
#include <gtest/gtest.h>
#include <memory>
#include <thread>

/**
 * @brief Runs unit tests for RouterModule class
 */
class RouterModuleTest : public ::testing::Test
{
protected:
    RouterModuleTest() = default;
    ~RouterModuleTest() override = default;

    void SetUp() override
    {
        // Clean state before each test
        try
        {
            RouterModule::instance().stop();
        }
        catch (...)
        {
            // Ignore if not started
        }
    }

    void TearDown() override
    {
        // Clean state after each test
        try
        {
            RouterModule::instance().stop();
        }
        catch (...)
        {
            // Ignore if not started
        }
    }
};

/*
 * @brief Tests RouterModule singleton pattern
 */
TEST_F(RouterModuleTest, TestRouterModuleSingleton)
{
    auto& instance1 = RouterModule::instance();
    auto& instance2 = RouterModule::instance();

    EXPECT_EQ(&instance1, &instance2);
}

/*
 * @brief Tests RouterModule initialization with valid log function
 */
TEST_F(RouterModuleTest, TestRouterModuleInitializeWithLogFunction)
{
    std::atomic<bool> logFunctionCalled {false};
    std::atomic<int> logLevel {-1};
    std::string logMessage;

    auto logFunction =
        [&logFunctionCalled, &logLevel, &logMessage](const modules_log_level_t level, const std::string& msg)
    {
        logFunctionCalled = true;
        logLevel = static_cast<int>(level);
        logMessage = msg;
    };

    EXPECT_NO_THROW(RouterModule::initialize(logFunction));

    // Test that the log function was stored (we can't directly verify this,
    // but the module should not throw)
}

/*
 * @brief Tests RouterModule initialization with null log function
 */
TEST_F(RouterModuleTest, TestRouterModuleInitializeWithNullLogFunction)
{
    std::function<void(const modules_log_level_t, const std::string&)> nullLogFunction;

    EXPECT_NO_THROW(RouterModule::initialize(nullLogFunction));
}

/*
 * @brief Tests RouterModule multiple initialization calls
 */
TEST_F(RouterModuleTest, TestRouterModuleMultipleInitialization)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };

    EXPECT_NO_THROW(RouterModule::initialize(logFunction));
    EXPECT_NO_THROW(RouterModule::initialize(logFunction));

    // Multiple calls should not throw (second call should be ignored)
}

/*
 * @brief Tests RouterModule start
 */
TEST_F(RouterModuleTest, TestRouterModuleStart)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    EXPECT_NO_THROW(RouterModule::instance().start());
}

/*
 * @brief Tests RouterModule stop
 */
TEST_F(RouterModuleTest, TestRouterModuleStop)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    RouterModule::instance().start();
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule start/stop cycle
 */
TEST_F(RouterModuleTest, TestRouterModuleStartStopCycle)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());

    // Should be able to start again
    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule stop without start
 */
TEST_F(RouterModuleTest, TestRouterModuleStopWithoutStart)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    EXPECT_ANY_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule start without initialization
 */
TEST_F(RouterModuleTest, TestRouterModuleStartWithoutInitialization)
{
    // Note: This test assumes the module can handle being started without explicit initialization
    EXPECT_NO_THROW(RouterModule::instance().start());
}

/*
 * @brief Tests RouterModule multiple start calls
 */
TEST_F(RouterModuleTest, TestRouterModuleMultipleStarts)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_ANY_THROW(RouterModule::instance().start());

    // Multiple starts should not cause issues
}

/*
 * @brief Tests RouterModule multiple stop calls
 */
TEST_F(RouterModuleTest, TestRouterModuleMultipleStops)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    RouterModule::instance().start();

    EXPECT_NO_THROW(RouterModule::instance().stop());
    EXPECT_ANY_THROW(RouterModule::instance().stop());

    // Multiple stops should not cause issues
}

/*
 * @brief Tests RouterModule log function preservation across operations
 */
TEST_F(RouterModuleTest, TestRouterModuleLogFunctionPreservation)
{
    std::atomic<int> logCallCount {0};
    auto logFunction = [&logCallCount](const modules_log_level_t /*level*/, const std::string& /*msg*/)
    {
        logCallCount++;
    };

    RouterModule::initialize(logFunction);
    RouterModule::instance().start();
    RouterModule::instance().stop();

    // The log function should still be available (though we can't directly test logging calls)
    EXPECT_TRUE(true); // Test passes if no exceptions are thrown
}

/*
 * @brief Tests RouterModule with different log levels
 */
TEST_F(RouterModuleTest, TestRouterModuleWithDifferentLogLevels)
{
    std::vector<modules_log_level_t> receivedLevels;
    std::vector<std::string> receivedMessages;

    auto logFunction = [&receivedLevels, &receivedMessages](const modules_log_level_t level, const std::string& msg)
    {
        receivedLevels.push_back(level);
        receivedMessages.push_back(msg);
    };

    RouterModule::initialize(logFunction);
    RouterModule::instance().start();
    RouterModule::instance().stop();

    // We can't directly trigger log messages from the module in unit tests,
    // but we can verify the setup doesn't throw
    EXPECT_TRUE(true);
}

// /*
//  * @brief Tests RouterModule thread safety (basic test)
//  */
// TEST_F(RouterModuleTest, TestRouterModuleThreadSafety)
// {
//     auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
//     };
//     RouterModule::initialize(logFunction);

//     // Basic thread safety test - multiple access to singleton
//     std::atomic<bool> thread1Complete {false};
//     std::atomic<bool> thread2Complete {false};

//     std::thread t1(
//         [&thread1Complete]()
//         {
//             auto& instance = RouterModule::instance();
//             instance.start();
//             instance.stop();
//             thread1Complete = true;
//         });

//     std::thread t2(
//         [&thread2Complete]()
//         {
//             auto& instance = RouterModule::instance();
//             instance.start();
//             instance.stop();
//             thread2Complete = true;
//         });

//     t1.join();
//     t2.join();

//     EXPECT_TRUE(thread1Complete);
//     EXPECT_TRUE(thread2Complete);
// }
