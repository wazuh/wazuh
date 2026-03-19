/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "threadEventDispatcher_test.hpp"
#include "threadEventDispatcher.hpp"

void ThreadEventDispatcherTest::SetUp()
{
    // Remove folder.
    std::filesystem::remove_all("test.db");
};

void ThreadEventDispatcherTest::TearDown() {
    // Not implemented
};

constexpr auto BULK_SIZE {50};
TEST_F(ThreadEventDispatcherTest, Ctor)
{
    static const std::vector<size_t> MESSAGES_TO_SEND_LIST {120, 100};

    for (auto MESSAGES_TO_SEND : MESSAGES_TO_SEND_LIST)
    {
        std::atomic<size_t> counter {0};
        std::promise<void> promise;
        size_t index {0};

        ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
            [&counter, &index, &MESSAGES_TO_SEND, &promise](std::queue<std::string>& data)
            {
                counter += data.size();
                while (!data.empty())
                {
                    auto value = data.front();
                    data.pop();
                    EXPECT_EQ(std::to_string(index), value);
                    ++index;
                }

                if (counter == MESSAGES_TO_SEND)
                {
                    promise.set_value();
                }
            },
            "test.db",
            BULK_SIZE,
            UNLIMITED_QUEUE_SIZE,
            1,
            0);

        for (size_t i = 0; i < MESSAGES_TO_SEND; ++i)
        {
            dispatcher.push(std::to_string(i));
        }
        promise.get_future().wait_for(std::chrono::seconds(10));
        EXPECT_EQ(MESSAGES_TO_SEND, counter);
    }
}

TEST_F(ThreadEventDispatcherTest, CtorNoWorker)
{
    static const std::vector<size_t> MESSAGES_TO_SEND_LIST {120, 100};

    for (auto MESSAGES_TO_SEND : MESSAGES_TO_SEND_LIST)
    {
        std::atomic<size_t> counter {0};
        std::promise<void> promise;
        auto index {0};

        ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
            "test.db", BULK_SIZE, UNLIMITED_QUEUE_SIZE, 1, 0);

        for (size_t i = 0; i < MESSAGES_TO_SEND; ++i)
        {
            dispatcher.push(std::to_string(i));
        }

        dispatcher.startWorker(
            [&counter, &index, &MESSAGES_TO_SEND, &promise](std::queue<std::string>& data)
            {
                counter += data.size();
                while (!data.empty())
                {
                    auto value = data.front();
                    data.pop();
                    EXPECT_EQ(std::to_string(index), value);
                    ++index;
                }

                if (counter == MESSAGES_TO_SEND)
                {
                    promise.set_value();
                }
            });

        promise.get_future().wait_for(std::chrono::seconds(10));
        EXPECT_EQ(MESSAGES_TO_SEND, counter);
    }
}

TEST_F(ThreadEventDispatcherTest, CtorPopFeature)
{
    constexpr auto MESSAGES_TO_SEND {1000};

    std::atomic<size_t> counter {0};
    std::promise<void> promise;
    std::promise<void> pushPromise;
    bool firstIteration {true};
    auto index {0};

    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&firstIteration, &pushPromise, &counter, &index, &promise](std::queue<std::string>& data)
        {
            if (firstIteration)
            {
                pushPromise.get_future().wait_for(std::chrono::seconds(10));
                firstIteration = false;
                throw std::runtime_error("Test exception");
            }
            counter += data.size();
            while (!data.empty())
            {
                auto value = data.front();
                data.pop();
                EXPECT_EQ(std::to_string(index), value);
                ++index;
            }
            if (counter == MESSAGES_TO_SEND)
            {
                promise.set_value();
            }
        },
        "test.db",
        BULK_SIZE,
        UNLIMITED_QUEUE_SIZE,
        0,
        0);

    for (int i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push(std::to_string(i));
    }
    pushPromise.set_value();
    promise.get_future().wait_for(std::chrono::seconds(10));
    EXPECT_EQ(MESSAGES_TO_SEND, counter);
}

TEST_F(ThreadEventDispatcherTest, CaptureWarningMsg)
{
    std::promise<void> promise;
    std::atomic<bool> warningCaptured {false};
    // Custom function that will capture and compare the warning log message.
    Log::assignLogFunction(
        [&promise, &warningCaptured](const int logLevel,
                                     const char* tag,
                                     const char* file,
                                     const int line,
                                     const char* func,
                                     const char* message,
                                     va_list args)
        {
            // Receives the exception message from the dispatch method.
            if (logLevel == Log::LOGLEVEL_WARNING)
            {
                // Format the message.
                char buffer[4096];
                vsnprintf(buffer, sizeof(buffer), message, args);
                std::string formattedMsg(buffer);
                // Compare expected message.
                if (formattedMsg.find("ThreadEventDispatcher dispatch end.") == std::string::npos)
                {
                    EXPECT_EQ("Dispatch handler error, Test exception", formattedMsg);
                }
                warningCaptured = true;
                // Avoid multiple captures.
                try
                {
                    promise.set_value();
                }
                catch (...)
                {
                }
            }
        });

    std::string testMsg {"Test message"};
    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [testMsg](std::queue<std::string>& data)
        {
            // Pops and compare the dummy enqueued log message.
            while (!data.empty())
            {
                auto value = data.front();
                data.pop();
                EXPECT_EQ(testMsg.c_str(), value);
                throw std::runtime_error("Test exception");
            }
        },
        "test.db");

    // Force the dispatch method to throw an exception.
    dispatcher.push(testMsg);

    // Wait for the warning log to be captured.
    auto status = promise.get_future().wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready);

    EXPECT_EQ(warningCaptured.load(), true);

    // Teardown
    dispatcher.cancel();
    Log::deassignLogFunction();
}

TEST_F(ThreadEventDispatcherTest, QueueSizeLimitEnforced)
{
    constexpr auto MAX_QUEUE_SIZE {10};
    constexpr auto MESSAGES_TO_SEND {20};

    std::atomic<size_t> processedCounter {0};
    std::atomic<size_t> warningCount {0};
    std::promise<void> firstWarningPromise;
    std::atomic<bool> firstWarningReceived {false};

    // Custom log function to capture queue full warnings
    Log::assignLogFunction(
        [&firstWarningPromise, &warningCount, &firstWarningReceived](const int logLevel,
                                                                     const char* tag,
                                                                     const char* file,
                                                                     const int line,
                                                                     const char* func,
                                                                     const char* message,
                                                                     va_list args)
        {
            if (logLevel == Log::LOGLEVEL_WARNING)
            {
                char buffer[4096];
                vsnprintf(buffer, sizeof(buffer), message, args);
                std::string formattedMsg(buffer);

                // Check if it's a queue full warning
                if (formattedMsg.find("Queue is full") != std::string::npos ||
                    formattedMsg.find("Starting to discard events") != std::string::npos ||
                    formattedMsg.find("overflow continues") != std::string::npos)
                {
                    warningCount++;
                    if (!firstWarningReceived.exchange(true))
                    {
                        try
                        {
                            firstWarningPromise.set_value();
                        }
                        catch (...)
                        {
                        }
                    }
                }
            }
        });

    // Dispatcher that processes messages slowly to allow queue to fill up
    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&processedCounter](std::queue<std::string>& data)
        {
            // Process messages slowly
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            processedCounter += data.size();
            while (!data.empty())
            {
                data.pop();
            }
        },
        "test.db",
        BULK_SIZE,
        MAX_QUEUE_SIZE,
        1,
        0);

    // Push more messages than the queue can hold
    for (size_t i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push(std::to_string(i));
        // Small delay to allow some processing but still fill the queue
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Wait for first warning to be captured
    auto status = firstWarningPromise.get_future().wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Expected queue full warning to be logged";

    // Wait a bit more to see if we get the rate limiting (should NOT flood logs)
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // We should have received warnings, but NOT one per discarded event
    // With rate limiting, we expect far fewer warnings (1 initial + maybe 0-1 summary)
    const auto finalWarningCount = warningCount.load();
    EXPECT_GT(finalWarningCount, 0) << "Expected at least one warning to be logged";
    EXPECT_LT(finalWarningCount, MESSAGES_TO_SEND) << "Rate limiting should prevent one warning per event";

    // Verify queue size is respected
    EXPECT_LE(dispatcher.size(), MAX_QUEUE_SIZE) << "Queue size should not exceed maximum";

    // Verify that not all messages were processed (some were discarded)
    std::this_thread::sleep_for(std::chrono::seconds(2)); // Allow time for processing
    EXPECT_LT(processedCounter, MESSAGES_TO_SEND) << "Some messages should have been discarded";

    // Teardown
    dispatcher.cancel();
    Log::deassignLogFunction();
}

TEST_F(ThreadEventDispatcherTest, DiscardRateLimitingPreventsLogFlood)
{
    constexpr auto MAX_QUEUE_SIZE {5};
    constexpr auto MANY_MESSAGES {100};

    std::atomic<size_t> warningCount {0};
    std::atomic<size_t> infoCount {0};
    std::promise<void> firstWarningPromise;
    std::atomic<bool> firstWarningReceived {false};

    // Custom log function to count all log messages
    Log::assignLogFunction(
        [&firstWarningPromise, &warningCount, &infoCount, &firstWarningReceived](const int logLevel,
                                                                                 const char* tag,
                                                                                 const char* file,
                                                                                 const int line,
                                                                                 const char* func,
                                                                                 const char* message,
                                                                                 va_list args)
        {
            char buffer[4096];
            vsnprintf(buffer, sizeof(buffer), message, args);
            std::string formattedMsg(buffer);

            if (logLevel == Log::LOGLEVEL_WARNING && (formattedMsg.find("Starting to discard") != std::string::npos ||
                                                      formattedMsg.find("overflow continues") != std::string::npos))
            {
                warningCount++;
                if (!firstWarningReceived.exchange(true))
                {
                    try
                    {
                        firstWarningPromise.set_value();
                    }
                    catch (...)
                    {
                    }
                }
            }
            else if (logLevel == Log::LOGLEVEL_INFO &&
                     formattedMsg.find("Resuming event acceptance") != std::string::npos)
            {
                infoCount++;
            }
        });

    std::atomic<size_t> processedCounter {0};

    // Dispatcher that processes slowly
    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&processedCounter](std::queue<std::string>& data)
        {
            std::this_thread::sleep_for(std::chrono::seconds(2));
            processedCounter += data.size();
            while (!data.empty())
            {
                data.pop();
            }
        },
        "test.db",
        BULK_SIZE,
        MAX_QUEUE_SIZE,
        1,
        0);

    // Flood with many messages
    for (size_t i = 0; i < MANY_MESSAGES; ++i)
    {
        dispatcher.push(std::to_string(i));
    }

    // Wait for first warning
    auto status = firstWarningPromise.get_future().wait_for(std::chrono::seconds(3));
    EXPECT_EQ(status, std::future_status::ready) << "Expected first discard warning";

    // The key assertion: with 100 discarded messages, we should have MUCH fewer than 100 warnings
    // Expect: 1 initial warning only (no time for periodic summaries in this short test)
    EXPECT_GE(warningCount.load(), 1) << "Should have at least the initial warning";
    EXPECT_LE(warningCount.load(), 5) << "Rate limiting should prevent log flooding (expected ~1-2 warnings, not 100)";

    // Teardown
    dispatcher.cancel();
    Log::deassignLogFunction();
}

TEST_F(ThreadEventDispatcherTest, UnlimitedQueueSizeWorks)
{
    constexpr auto MESSAGES_TO_SEND {100};

    std::atomic<size_t> counter {0};
    std::promise<void> promise;

    // Dispatcher with unlimited queue size (default)
    ThreadEventDispatcher<std::string, std::function<void(std::queue<std::string>&)>> dispatcher(
        [&counter, &promise, MESSAGES_TO_SEND](std::queue<std::string>& data)
        {
            counter += data.size();
            while (!data.empty())
            {
                data.pop();
            }
            if (counter >= MESSAGES_TO_SEND)
            {
                promise.set_value();
            }
        },
        "test.db",
        BULK_SIZE,
        UNLIMITED_QUEUE_SIZE, // Explicitly set to unlimited
        1,
        0);

    // Push all messages
    for (size_t i = 0; i < MESSAGES_TO_SEND; ++i)
    {
        dispatcher.push(std::to_string(i));
    }

    // Wait for all messages to be processed
    auto status = promise.get_future().wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready);

    // All messages should be processed
    EXPECT_EQ(counter, MESSAGES_TO_SEND);
}
