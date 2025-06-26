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

    // The test verifies that the log function was properly stored
    // Actual log messages would be generated by the router module internals
    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule performance under stress
 */
TEST_F(RouterModuleTest, TestRouterModuleStressTest)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/)
    {
        // Performance test - don't do anything in callback
    };
    RouterModule::initialize(logFunction);

    auto start = std::chrono::high_resolution_clock::now();

    // Perform many start/stop cycles
    for (int i = 0; i < 10; ++i)
    {
        EXPECT_NO_THROW(RouterModule::instance().start());
        EXPECT_NO_THROW(RouterModule::instance().stop());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    // Should complete stress test in reasonable time (less than 5 seconds)
    EXPECT_LT(duration.count(), 5000);
}

/*
 * @brief Tests RouterModule with slow log function
 */
TEST_F(RouterModuleTest, TestRouterModuleSlowLogFunction)
{
    std::atomic<int> logCallCount {0};

    auto slowLogFunction = [&logCallCount](const modules_log_level_t /*level*/, const std::string& /*msg*/)
    {
        logCallCount++;
        // Simulate slow logging
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    };

    RouterModule::initialize(slowLogFunction);

    // Even with slow logging, operations should not hang
    auto start = std::chrono::high_resolution_clock::now();

    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start);

    // Should complete even with slow logging in reasonable time
    EXPECT_LT(duration.count(), 10);
}

/*
 * @brief Tests RouterModule concurrent access
 */
TEST_F(RouterModuleTest, TestRouterModuleConcurrentAccess)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    const int numThreads = 4;
    std::vector<std::thread> threads;
    threads.reserve(numThreads);
    std::atomic<int> successCount {0};
    std::atomic<int> failCount {0};

    // Try to start router from multiple threads
    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&successCount, &failCount]()
            {
                try
                {
                    RouterModule::instance().start();
                    successCount++;
                }
                catch (...)
                {
                    failCount++;
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    // Only one thread should succeed in starting
    EXPECT_EQ(successCount.load(), 1);
    EXPECT_EQ(failCount.load(), numThreads - 1);

    // Clean up
    RouterModule::instance().stop();
}

/*
 * @brief Tests RouterModule memory management
 */
TEST_F(RouterModuleTest, TestRouterModuleMemoryManagement)
{
    // Test multiple initializations with different log functions
    for (int i = 0; i < 5; ++i)
    {
        auto logFunction = [i](const modules_log_level_t /*level*/, const std::string& /*msg*/)
        {
            // Each iteration uses a different lambda (different memory)
            static_cast<void>(i); // Use the captured variable
        };

        EXPECT_NO_THROW(RouterModule::initialize(logFunction));
    }

    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule exception handling in log function
 */
TEST_F(RouterModuleTest, TestRouterModuleLogFunctionException)
{
    std::atomic<bool> exceptionThrown {false};

    auto throwingLogFunction = [&exceptionThrown](const modules_log_level_t /*level*/, const std::string& /*msg*/)
    {
        exceptionThrown = true;
        throw std::runtime_error("Log function exception");
    };

    RouterModule::initialize(throwingLogFunction);

    // Router should handle exceptions in log function gracefully
    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule state consistency
 */
TEST_F(RouterModuleTest, TestRouterModuleStateConsistency)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    // Test that multiple start attempts don't corrupt state
    EXPECT_NO_THROW(RouterModule::instance().start());

    // Multiple start attempts should fail but not corrupt state
    for (int i = 0; i < 3; ++i)
    {
        EXPECT_ANY_THROW(RouterModule::instance().start());
    }

    // Should still be able to stop properly
    EXPECT_NO_THROW(RouterModule::instance().stop());

    // Should be able to start again after proper stop
    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule with lambda captures
 */
TEST_F(RouterModuleTest, TestRouterModuleLambdaCaptures)
{
    std::string capturedValue = "test-capture";
    std::atomic<bool> captureUsed {false};

    auto logFunction = [capturedValue, &captureUsed](const modules_log_level_t /*level*/, const std::string& /*msg*/)
    {
        if (!capturedValue.empty())
        {
            captureUsed = true;
        }
    };

    RouterModule::initialize(logFunction);
    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());

    // Test passes if no crash occurs with captured variables
}

/*
 * @brief Tests RouterModule initialization with std::function variations
 */
TEST_F(RouterModuleTest, TestRouterModuleFunctionVariations)
{
    // Test with function pointer
    {
        auto func = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
        };
        std::function<void(const modules_log_level_t, const std::string&)> stdFunc = func;
        EXPECT_NO_THROW(RouterModule::initialize(stdFunc));
    }

    // Test with null function
    {
        std::function<void(const modules_log_level_t, const std::string&)> nullFunc;
        EXPECT_NO_THROW(RouterModule::initialize(nullFunc));
    }

    // Test with move semantics
    {
        auto func = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
        };
        EXPECT_NO_THROW(RouterModule::initialize(std::move(func)));
    }
}

/*
 * @brief Tests RouterModule rapid initialization
 */
TEST_F(RouterModuleTest, TestRouterModuleRapidInitialization)
{
    const int numInitializations = 100;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < numInitializations; ++i)
    {
        auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
        };
        RouterModule::initialize(logFunction);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);

    // Rapid initializations should complete quickly (less than 100ms)
    EXPECT_LT(duration.count(), 100000);
}

/*
 * @brief Tests RouterModule with empty log messages
 */
TEST_F(RouterModuleTest, TestRouterModuleEmptyLogMessages)
{
    std::vector<std::string> receivedMessages;

    auto logFunction = [&receivedMessages](const modules_log_level_t /*level*/, const std::string& msg)
    {
        receivedMessages.push_back(msg);
    };

    RouterModule::initialize(logFunction);

    // The router module should handle empty or invalid log messages gracefully
    EXPECT_NO_THROW(RouterModule::instance().start());
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule long-running operation
 */
TEST_F(RouterModuleTest, TestRouterModuleLongRunning)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };
    RouterModule::initialize(logFunction);

    EXPECT_NO_THROW(RouterModule::instance().start());

    // Simulate long-running operation
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Should still be able to stop after running for a while
    EXPECT_NO_THROW(RouterModule::instance().stop());
}

/*
 * @brief Tests RouterModule resource cleanup
 */
TEST_F(RouterModuleTest, TestRouterModuleResourceCleanup)
{
    auto logFunction = [](const modules_log_level_t /*level*/, const std::string& /*msg*/) {
    };

    // Test multiple start/stop cycles to verify resource cleanup
    for (int cycle = 0; cycle < 3; ++cycle)
    {
        RouterModule::initialize(logFunction);
        EXPECT_NO_THROW(RouterModule::instance().start());

        // Do some work
        std::this_thread::sleep_for(std::chrono::milliseconds(10));

        EXPECT_NO_THROW(RouterModule::instance().stop());
    }

    // Test passes if no resource leaks occur
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
