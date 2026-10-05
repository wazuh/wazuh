/*
 * Wazuh container_instances — lifecycle notification transport (#37532 / #37203).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * Both halves of the channel together: the module's sender and the consumer's
 * receiver. They are tested as a pair because the properties that matter are
 * about the pair — that a change wakes a listener, and that the absence of a
 * listener costs the module nothing.
 *
 * The transport is deliberately unreliable, so what is pinned here is not
 * delivery. It is that nothing about it can take the module down: a consumer
 * that never binds, dies, or stops reading must all be non-events, because on a
 * real host they are the ordinary case rather than the exception.
 */

#include "ipc/lifecycle_notifier.hpp"

#include "container_instances_notify_socket.hpp"

#include <gtest/gtest.h>

#include <string>
#include <unistd.h>
#include <vector>

using namespace wazuh::container_instances;
using wazuh::container_instances_client::NotifySocket;

namespace
{

Logger SilentLogger()
{
    return [](LogLevel, const std::string&) {};
}

/// Unique per test so a leftover file from a crashed run cannot make one test
/// depend on another.
std::string ScratchPath(const std::string& name)
{
    return "/tmp/ci-notify-" + name + "-" + std::to_string(::getpid());
}

LifecycleCursor Cursor(std::uint64_t epoch, std::uint64_t seq)
{
    return LifecycleCursor {epoch, seq};
}

} // namespace

TEST(LifecycleNotifierTest, ADatagramWakesABoundConsumer)
{
    const auto path = ScratchPath("wake");

    NotifySocket socket;
    ASSERT_TRUE(socket.bind(path));
    ASSERT_GE(socket.fd(), 0);

    LifecycleNotifier notifier {{path}, SilentLogger()};
    notifier.notify(Cursor(42, 7));

    EXPECT_EQ(1, socket.drain());
}

TEST(LifecycleNotifierTest, ABurstCollapsesIntoOneWake)
{
    // A reconcile that adds ten containers is one change to react to, and the
    // consumer should pull once. drain() is what makes that true.
    const auto path = ScratchPath("burst");

    NotifySocket socket;
    ASSERT_TRUE(socket.bind(path));

    LifecycleNotifier notifier {{path}, SilentLogger()};
    for (int i = 0; i < 5; ++i)
    {
        notifier.notify(Cursor(42, static_cast<std::uint64_t>(i)));
    }

    EXPECT_EQ(5, socket.drain()) << "all of them are consumed by one drain";
    EXPECT_EQ(0, socket.drain()) << "and the queue is then empty";
}

TEST(LifecycleNotifierTest, NotifyingASocketNobodyBoundIsHarmless)
{
    // The ordinary case, not an error: that consumer is not running, or has the
    // feature switched off. It must not throw, block, or stop the other target
    // from being notified.
    const auto live = ScratchPath("mixed-live");

    NotifySocket socket;
    ASSERT_TRUE(socket.bind(live));

    LifecycleNotifier notifier {{ScratchPath("nobody-is-here"), live}, SilentLogger()};

    EXPECT_NO_THROW(notifier.notify(Cursor(1, 1)));
    EXPECT_EQ(1, socket.drain()) << "a dead target must not suppress a live one";
}

TEST(LifecycleNotifierTest, AConsumerThatDiesDoesNotAffectTheModule)
{
    const auto path = ScratchPath("dies");

    LifecycleNotifier notifier {{path}, SilentLogger()};

    {
        NotifySocket socket;
        ASSERT_TRUE(socket.bind(path));
        notifier.notify(Cursor(1, 1));
        ASSERT_EQ(1, socket.drain());
    } // unbinds and unlinks

    // Every later notification simply goes nowhere.
    for (int i = 0; i < 3; ++i)
    {
        EXPECT_NO_THROW(notifier.notify(Cursor(1, static_cast<std::uint64_t>(i + 2))));
    }
}

TEST(LifecycleNotifierTest, AConsumerThatStoppedReadingDoesNotBlockTheModule)
{
    // The datagram buffer is finite. If sending blocked when it filled, a
    // consumer stuck on a slow walk would stall the reconcile that is notifying
    // it — turning a latency optimisation into a liveness bug.
    const auto path = ScratchPath("deaf");

    NotifySocket socket;
    ASSERT_TRUE(socket.bind(path));

    LifecycleNotifier notifier {{path}, SilentLogger()};

    for (int i = 0; i < 20000; ++i)
    {
        notifier.notify(Cursor(1, static_cast<std::uint64_t>(i)));
    }

    SUCCEED() << "returned rather than blocking once the receive buffer filled";
}

TEST(LifecycleNotifierTest, RebindingReplacesAStaleSocketFile)
{
    // A socket file outlives the process that bound it, so a kill -9 leaves one
    // behind. Without the unlink in bind(), the daemon would never again be
    // able to receive notifications after an unclean stop.
    const auto path = ScratchPath("stale");

    {
        NotifySocket first;
        ASSERT_TRUE(first.bind(path));
        // Leak the file deliberately: this is what a crash leaves.
        ::close(first.fd());
    }

    NotifySocket second;
    EXPECT_TRUE(second.bind(path)) << "a leftover socket file must not lock the daemon out permanently";

    LifecycleNotifier notifier {{path}, SilentLogger()};
    notifier.notify(Cursor(9, 9));
    EXPECT_EQ(1, second.drain());
}

TEST(LifecycleNotifierTest, AnUnboundSocketYieldsAnFdPollIgnores)
{
    // -1 so a consumer needs no special case: poll() skips a negative fd, and
    // the loop keeps running on its timeout alone.
    NotifySocket socket;

    EXPECT_EQ(-1, socket.fd());
    EXPECT_EQ(0, socket.drain());
    EXPECT_FALSE(socket.bind("")) << "an empty path is 'not configured', not an error to report";
}
