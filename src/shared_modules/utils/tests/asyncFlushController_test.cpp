/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * April 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "asyncFlushController.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <stdexcept>
#include <thread>

#include <gtest/gtest.h>

class AsyncFlushControllerTest : public ::testing::Test
{
protected:
    static bool waitUntil(const std::function<bool()>& predicate,
                          const std::chrono::milliseconds timeout = std::chrono::milliseconds(1000))
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;

        while (std::chrono::steady_clock::now() < deadline)
        {
            if (predicate())
            {
                return true;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }

        return predicate();
    }
};

TEST_F(AsyncFlushControllerTest, IdleStatusIsCompletedSuccess)
{
    Utils::AsyncFlushController controller {"test", []() { return 0; }};

    const auto flushStatus = controller.getFlushStatus();
    EXPECT_FALSE(flushStatus.running);
    EXPECT_TRUE(flushStatus.successful);
}

TEST_F(AsyncFlushControllerTest, FirstRequestCompletesSuccessfully)
{
    std::atomic<int> callCount {0};
    Utils::AsyncFlushController controller {"test",
                                            [&callCount]()
                                            {
                                                ++callCount;
                                                return 0;
                                            }};

    EXPECT_TRUE(controller.startFlush());
    EXPECT_TRUE(waitUntil([&controller]() { return !controller.getFlushStatus().running; }));

    const auto flushStatus = controller.getFlushStatus();
    EXPECT_EQ(callCount.load(), 1);
    EXPECT_FALSE(flushStatus.running);
    EXPECT_TRUE(flushStatus.successful);
}

TEST_F(AsyncFlushControllerTest, DuplicateRequestWhileRunningIsIdempotent)
{
    std::promise<void> started;
    std::promise<void> release;
    std::shared_future<void> releaseFuture = release.get_future().share();
    std::atomic<int> callCount {0};
    std::atomic<bool> firstStartSignaled {false};

    Utils::AsyncFlushController controller {"test",
                                            [&]()
                                            {
                                                ++callCount;

                                                if (!firstStartSignaled.exchange(true))
                                                {
                                                    started.set_value();
                                                }

                                                releaseFuture.wait();
                                                return 0;
                                            }};

    EXPECT_TRUE(controller.startFlush());
    started.get_future().wait();

    const auto runningStatus = controller.getFlushStatus();
    EXPECT_TRUE(runningStatus.running);
    EXPECT_FALSE(runningStatus.successful);

    EXPECT_TRUE(controller.startFlush());
    EXPECT_EQ(callCount.load(), 1);

    release.set_value();

    EXPECT_TRUE(waitUntil([&controller]() { return !controller.getFlushStatus().running; }));
    EXPECT_TRUE(controller.getFlushStatus().successful);
}

TEST_F(AsyncFlushControllerTest, FailedFlushReturnsErrorStatus)
{
    Utils::AsyncFlushController controller {"test", []() { return -1; }};

    EXPECT_TRUE(controller.startFlush());
    EXPECT_TRUE(waitUntil([&controller]() { return !controller.getFlushStatus().running; }));

    const auto flushStatus = controller.getFlushStatus();
    EXPECT_FALSE(flushStatus.running);
    EXPECT_FALSE(flushStatus.successful);
}

TEST_F(AsyncFlushControllerTest, ExceptionMapsToErrorStatus)
{
    Utils::AsyncFlushController controller {"test", []() -> int { throw std::runtime_error("boom"); }};

    EXPECT_TRUE(controller.startFlush());
    EXPECT_TRUE(waitUntil([&controller]() { return !controller.getFlushStatus().running; }));

    const auto flushStatus = controller.getFlushStatus();
    EXPECT_FALSE(flushStatus.running);
    EXPECT_FALSE(flushStatus.successful);
}

TEST_F(AsyncFlushControllerTest, RepeatRequestAfterCompletionStartsNewWorker)
{
    std::atomic<int> callCount {0};
    Utils::AsyncFlushController controller {"test",
                                            [&callCount]()
                                            {
                                                ++callCount;
                                                return 0;
                                            }};

    EXPECT_TRUE(controller.startFlush());
    EXPECT_TRUE(waitUntil([&controller]() { return !controller.getFlushStatus().running; }));

    EXPECT_TRUE(controller.startFlush());
    EXPECT_TRUE(waitUntil([&controller]() { return !controller.getFlushStatus().running; }));

    EXPECT_EQ(callCount.load(), 2);
    EXPECT_TRUE(controller.getFlushStatus().successful);
}

TEST_F(AsyncFlushControllerTest, ShutdownWaitsForInFlightWorker)
{
    std::promise<void> started;
    std::promise<void> release;
    std::shared_future<void> releaseFuture = release.get_future().share();
    std::atomic<bool> firstStartSignaled {false};

    Utils::AsyncFlushController controller {"test",
                                            [&]()
                                            {
                                                if (!firstStartSignaled.exchange(true))
                                                {
                                                    started.set_value();
                                                }

                                                releaseFuture.wait();
                                                return 0;
                                            }};

    EXPECT_TRUE(controller.startFlush());
    started.get_future().wait();

    auto waitFuture = std::async(std::launch::async, [&controller]() { controller.waitForFlushToFinish(); });

    EXPECT_EQ(waitFuture.wait_for(std::chrono::milliseconds(100)), std::future_status::timeout);

    release.set_value();

    EXPECT_EQ(waitFuture.wait_for(std::chrono::seconds(1)), std::future_status::ready);
}
