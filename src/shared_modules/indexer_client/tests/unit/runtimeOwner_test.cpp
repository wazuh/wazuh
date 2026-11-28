/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <pthread.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include "indexer_client/runtime.hpp"

using namespace indexer_client;
using namespace std::chrono_literals;

namespace
{
    /// Test-owned configuration source (the KeyValueConfigSource belongs to another step).
    class MapSource final : public IConfigSource
    {
    public:
        explicit MapSource(std::map<std::string, std::string> values, Credentials credentials = {"user", "pass"})
            : m_values(std::move(values))
            , m_credentials(std::move(credentials))
        {
        }

        std::optional<std::string> raw(std::string_view key) const override
        {
            const auto it = m_values.find(std::string(key));
            if (it == m_values.end())
            {
                return std::nullopt;
            }
            return it->second;
        }

        std::vector<std::string> keysWithPrefix(std::string_view prefix) const override
        {
            std::vector<std::string> keys;
            for (const auto& [key, value] : m_values)
            {
                if (key.compare(0, prefix.size(), prefix) == 0)
                {
                    keys.push_back(key);
                }
            }
            return keys;
        }

        std::string indexerSectionJson() const override
        {
            return R"({"hosts":["http://127.0.0.1:1"]})";
        }

        indexer_client::Credentials credentials() const override
        {
            return m_credentials;
        }

    private:
        std::map<std::string, std::string> m_values;
        Credentials m_credentials;
    };

    MapSource sourceWith(std::uint32_t k, std::uint32_t m)
    {
        return MapSource({{"analysisd.indexer_client_network_threads", std::to_string(k)},
                          {"analysisd.indexer_client_cpu_threads", std::to_string(m)}});
    }

    std::set<std::string> tasks()
    {
        std::set<std::string> ids;
        for (const auto& entry : std::filesystem::directory_iterator("/proc/self/task"))
        {
            ids.insert(entry.path().filename().string());
        }
        return ids;
    }

    /// A joined thread can stay listed in /proc for a short while after pthread_join() returns (the kernel clears the
    /// tid before the task is released): read until two consecutive listings agree, so a dying task never counts.
    std::set<std::string> settledTasks()
    {
        auto previous = tasks();
        for (int i = 0; i < 400; ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            auto current = tasks();
            if (current == previous)
            {
                return current;
            }
            previous = std::move(current);
        }
        ADD_FAILURE() << "/proc/self/task never settled";
        return previous;
    }

    std::set<std::string> difference(const std::set<std::string>& after, const std::set<std::string>& before)
    {
        std::set<std::string> diff;
        for (const auto& id : after)
        {
            if (before.count(id) == 0)
            {
                diff.insert(id);
            }
        }
        return diff;
    }

    /// `SigBlk` of a task, as a 64-bit mask (bit n-1 = signal n).
    unsigned long long blockedMask(const std::string& tid)
    {
        std::ifstream status("/proc/self/task/" + tid + "/status");
        std::string line;
        while (std::getline(status, line))
        {
            if (line.rfind("SigBlk:", 0) == 0)
            {
                return std::stoull(line.substr(7), nullptr, 16);
            }
        }
        ADD_FAILURE() << "no SigBlk for task " << tid;
        return 0;
    }

    bool isBlocked(unsigned long long mask, int sig)
    {
        return (mask >> (sig - 1)) & 1ULL;
    }

    /// Converts a hang into a failure that does not freeze the suite: past the timeout it aborts the process.
    class Watchdog final
    {
    public:
        explicit Watchdog(std::chrono::milliseconds timeout, std::string what)
            : m_thread(
                  [this, timeout, what = std::move(what)]()
                  {
                      std::unique_lock<std::mutex> lock(m_mutex);
                      if (!m_cv.wait_for(lock, timeout, [this] { return m_disarmed; }))
                      {
                          std::fprintf(stderr, "WATCHDOG: '%s' still blocked after the timeout: FAIL\n", what.c_str());
                          std::abort();
                      }
                  })
        {
        }

        ~Watchdog()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_disarmed = true;
            }
            m_cv.notify_all();
            m_thread.join();
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_disarmed {false};
        std::thread m_thread;
    };

    enum class Where
    {
        Pool,
        IoLoop
    };

    bool postTo(Where where, std::function<void()> task)
    {
        return where == Where::Pool ? detail::testing::postToPool(std::move(task))
                                    : detail::testing::postToIoLoop(std::move(task));
    }

    std::string whereName(Where where)
    {
        return where == Where::Pool ? "Pool" : "IoLoop";
    }
} // namespace

class RuntimeOwnerTest : public ::testing::Test
{
protected:
    void TearDown() override
    {
        RuntimeOwner::shutdown();
        ASSERT_FALSE(RuntimeOwner::running());
    }
};

TEST_F(RuntimeOwnerTest, ThreadCountIsKPlusM)
{
    for (const std::uint32_t k : {1u, 3u})
    {
        for (const std::uint32_t m : {1u, 4u})
        {
            for (const std::uint32_t c : {1u, 5u})
            {
                SCOPED_TRACE("K=" + std::to_string(k) + " M=" + std::to_string(m) + " C=" + std::to_string(c));
                const auto before = settledTasks();

                auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(k, m));
                ASSERT_TRUE(ref.ok()) << toString(ref.cause) << ": " << ref.reason;

                std::vector<std::shared_ptr<Client>> clients;
                for (std::uint32_t i = 0; i < c; ++i)
                {
                    auto client = ref.value.client("consumer-" + std::to_string(i), {BucketSpec {"b"}});
                    ASSERT_TRUE(client.ok()) << client.reason;
                    clients.push_back(client.value);
                }

                EXPECT_EQ(settledTasks().size(), before.size() + k + m) << "clients must not create threads";
                const auto snapshot = ref.value.snapshot();
                EXPECT_EQ(snapshot.networkThreads, k);
                EXPECT_EQ(snapshot.cpuThreads, m);
                EXPECT_EQ(snapshot.clients, c);

                clients.clear();
                EXPECT_EQ(ref.value.snapshot().clients, 0u);
                ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
                EXPECT_EQ(settledTasks(), before) << "shutdown() must join every runtime thread";
            }
        }
    }
}

// shutdown() joins EVERY runtime thread, not just the one that happened to pick a task: one held task per runtime
// thread (M pool tasks that block until all M have started, so each lands on a distinct worker, plus one per IoLoop
// through `loopIndex`). Each round makes a different thread finish last (it sleeps after the release); a thread that
// shutdown() failed to join is caught in the round where it is the slow one, whichever thread it is.
TEST_F(RuntimeOwnerTest, ShutdownJoinsHeldTask)
{
    constexpr std::uint32_t K = 2;
    constexpr std::uint32_t M = 3;
    std::set<std::string> threadNames;
    for (std::uint32_t i = 0; i < K; ++i)
    {
        threadNames.insert("ic-io-" + std::to_string(i));
    }
    for (std::uint32_t i = 0; i < M; ++i)
    {
        threadNames.insert("ic-cpu-" + std::to_string(i));
    }

    // Shared by value with the tasks: a thread that shutdown() wrongly left running must not touch a dead frame.
    struct Held final
    {
        std::mutex mutex;
        std::condition_variable cv;
        std::uint32_t poolStarted {0};
        std::set<std::string> started;
        bool released {false};
        std::set<std::string> finished;
    };

    for (const auto& slow : threadNames)
    {
        SCOPED_TRACE("slow thread " + slow);
        ASSERT_TRUE(RuntimeOwner::start(ProcessId::Analysisd, sourceWith(K, M)).ok());
        auto held = std::make_shared<Held>();

        const auto task = [held, slow](bool onPool)
        {
            char buffer[16] = {};
            pthread_getname_np(pthread_self(), buffer, sizeof(buffer));
            const std::string name(buffer);
            std::unique_lock<std::mutex> lock(held->mutex);
            held->started.insert(name);
            if (onPool)
            {
                ++held->poolStarted;
            }
            held->cv.notify_all();
            if (onPool)
            {
                // Holding this worker until every pool task has started forces the M tasks onto M distinct workers.
                held->cv.wait(lock, [&] { return held->poolStarted == M; });
            }
            held->cv.wait(lock, [&] { return held->released; });
            lock.unlock();
            if (name == slow)
            {
                std::this_thread::sleep_for(300ms);
            }
            lock.lock();
            held->finished.insert(name);
        };

        for (std::uint32_t i = 0; i < M; ++i)
        {
            ASSERT_TRUE(detail::testing::postToPool([task]() { task(true); }));
        }
        for (std::uint32_t i = 0; i < K; ++i)
        {
            ASSERT_TRUE(detail::testing::postToIoLoop([task]() { task(false); }, i));
        }
        {
            std::unique_lock<std::mutex> lock(held->mutex);
            ASSERT_TRUE(held->cv.wait_for(lock, 10s, [&] { return held->started.size() == K + M; }))
                << "only " << held->started.size() << " of " << K + M << " held tasks started";
            ASSERT_EQ(held->started, threadNames) << "one held task per runtime thread";
        }

        std::thread releaser(
            [held]()
            {
                std::this_thread::sleep_for(100ms);
                {
                    std::lock_guard<std::mutex> lock(held->mutex);
                    held->released = true;
                }
                held->cv.notify_all();
            });

        {
            Watchdog watchdog(10s, "ShutdownJoinsHeldTask");
            EXPECT_EQ(RuntimeOwner::shutdown(), Cause::None);
            std::lock_guard<std::mutex> lock(held->mutex);
            EXPECT_TRUE(held->released) << "shutdown() returned before the held tasks were released";
            EXPECT_EQ(held->finished, threadNames) << "shutdown() returned before every held task finished";
        }
        releaser.join();
    }
}

TEST_F(RuntimeOwnerTest, ShutdownFromRuntimeThreadIsUsageError)
{
    for (const auto where : {Where::Pool, Where::IoLoop})
    {
        SCOPED_TRACE(whereName(where));
        ASSERT_TRUE(RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1)).ok());
        std::promise<std::tuple<Cause, Cause, Cause>> result;
        {
            Watchdog watchdog(10s, "ShutdownFromRuntimeThreadIsUsageError");
            ASSERT_TRUE(postTo(where,
                               [&result]()
                               {
                                   const auto shutdown = RuntimeOwner::shutdown();
                                   const auto begin = RuntimeOwner::beginShutdown(std::chrono::steady_clock::now());
                                   const auto start = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1)).cause;
                                   result.set_value({shutdown, begin, start});
                               }));
            const auto [shutdown, begin, start] = result.get_future().get();
            EXPECT_EQ(shutdown, Cause::UsageError);
            EXPECT_EQ(begin, Cause::UsageError);
            EXPECT_EQ(start, Cause::UsageError);
        }
        EXPECT_TRUE(RuntimeOwner::running());
        ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
    }
}

TEST_F(RuntimeOwnerTest, RestartAfterShutdown)
{
    const auto before = settledTasks();
    for (int round = 0; round < 3; ++round)
    {
        auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(2, 3));
        ASSERT_TRUE(ref.ok()) << "round " << round << ": " << ref.reason;
        EXPECT_TRUE(RuntimeOwner::running());
        auto client = ref.value.client("same-consumer", {BucketSpec {"b"}});
        ASSERT_TRUE(client.ok()) << client.reason;
        std::promise<void> ran;
        ASSERT_TRUE(detail::testing::postToPool([&ran]() { ran.set_value(); }));
        ran.get_future().wait();
        client.value.reset();
        ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
        EXPECT_FALSE(RuntimeOwner::running());
        EXPECT_EQ(settledTasks(), before) << "round " << round;
    }
}

TEST_F(RuntimeOwnerTest, RuntimeThreadsBlockSignals)
{
    sigset_t original;
    sigset_t empty;
    sigemptyset(&empty);
    ASSERT_EQ(pthread_sigmask(SIG_SETMASK, &empty, &original), 0);

    const auto before = settledTasks();
    auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(3, 4));
    ASSERT_TRUE(ref.ok()) << ref.reason;
    const auto runtimeTids = difference(settledTasks(), before);
    ASSERT_EQ(runtimeTids.size(), 7u);

    const std::set<int> synchronous {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGTRAP, SIGABRT};
    for (const auto& tid : runtimeTids)
    {
        const auto mask = blockedMask(tid);
        for (int sig = 1; sig < 32; ++sig)
        {
            if (sig == SIGKILL || sig == SIGSTOP)
            {
                continue; // The kernel never lets them be blocked.
            }
            if (synchronous.count(sig) != 0)
            {
                EXPECT_FALSE(isBlocked(mask, sig)) << "task " << tid << " blocks synchronous signal " << sig;
            }
            else
            {
                EXPECT_TRUE(isBlocked(mask, sig)) << "task " << tid << " does not block signal " << sig;
            }
        }
    }

    ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
    pthread_sigmask(SIG_SETMASK, &original, nullptr);
}

TEST_F(RuntimeOwnerTest, OwnerMaskRestored)
{
    sigset_t original;
    sigset_t empty;
    sigemptyset(&empty);
    ASSERT_EQ(pthread_sigmask(SIG_SETMASK, &empty, &original), 0);
    const auto self = std::to_string(gettid());
    ASSERT_EQ(blockedMask(self), 0ULL);

    auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 2));
    ASSERT_TRUE(ref.ok()) << ref.reason;
    EXPECT_EQ(blockedMask(self), 0ULL) << "the owner's mask must be restored after the threads exist";

    // A non-empty mask is restored exactly too.
    ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
    sigset_t onlyUsr2;
    sigemptyset(&onlyUsr2);
    sigaddset(&onlyUsr2, SIGUSR2);
    ASSERT_EQ(pthread_sigmask(SIG_SETMASK, &onlyUsr2, nullptr), 0);
    ASSERT_TRUE(RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1)).ok());
    EXPECT_EQ(blockedMask(self), 1ULL << (SIGUSR2 - 1));

    ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
    pthread_sigmask(SIG_SETMASK, &original, nullptr);
}

TEST_F(RuntimeOwnerTest, BeginShutdownIsIdempotent)
{
    auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
    ASSERT_TRUE(ref.ok());
    EXPECT_FALSE(ref.value.shutdownDeadline().has_value());

    const auto first = std::chrono::steady_clock::now() + 5s;
    EXPECT_EQ(RuntimeOwner::beginShutdown(first), Cause::None);
    EXPECT_EQ(RuntimeOwner::beginShutdown(first + 10s), Cause::None);
    EXPECT_EQ(RuntimeOwner::beginShutdown(first - 3s), Cause::None);
    ASSERT_TRUE(ref.value.shutdownDeadline().has_value());
    EXPECT_EQ(*ref.value.shutdownDeadline(), first) << "the first deadline wins";
}

TEST_F(RuntimeOwnerTest, OwnerApiBeforeStartIsTypedError)
{
    ASSERT_FALSE(RuntimeOwner::running());
    EXPECT_EQ(RuntimeOwner::beginShutdown(std::chrono::steady_clock::now()), Cause::InvalidState);
    EXPECT_EQ(RuntimeOwner::shutdown(), Cause::None) << "shutdown() without a runtime is a no-op";
    EXPECT_FALSE(detail::testing::postToPool([]() {}));
    EXPECT_FALSE(detail::testing::postToIoLoop([]() {}));

    RuntimeRef empty;
    EXPECT_FALSE(empty.valid());
    EXPECT_EQ(empty.client("consumer", {}).cause, Cause::InvalidState);
    EXPECT_FALSE(empty.shutdownDeadline().has_value());
    EXPECT_EQ(empty.snapshot().networkThreads, 0u);
}

TEST_F(RuntimeOwnerTest, DoubleStartKeepsRuntime)
{
    auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(2, 2));
    ASSERT_TRUE(ref.ok());
    auto client = ref.value.client("kept", {});
    ASSERT_TRUE(client.ok());
    const auto during = settledTasks();

    auto second = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
    EXPECT_EQ(second.cause, Cause::InvalidState);
    EXPECT_FALSE(second.value.valid());

    EXPECT_TRUE(RuntimeOwner::running());
    EXPECT_TRUE(ref.value.valid());
    EXPECT_EQ(settledTasks(), during);
    EXPECT_EQ(ref.value.snapshot().networkThreads, 2u);
    EXPECT_EQ(ref.value.snapshot().clients, 1u);
    std::promise<void> ran;
    ASSERT_TRUE(detail::testing::postToIoLoop([&ran]() { ran.set_value(); }, 1));
    ran.get_future().wait();
}

TEST_F(RuntimeOwnerTest, SnapshotEchoesRequestTimeout)
{
    auto ref =
        RuntimeOwner::start(ProcessId::Analysisd, MapSource({{"analysisd.indexer_client_request_timeout_ms", "1234"}}));
    ASSERT_TRUE(ref.ok()) << toString(ref.cause) << ": " << ref.reason;
    EXPECT_EQ(ref.value.snapshot().requestTimeout, Duration {1234});
    EXPECT_EQ(RuntimeRef {}.snapshot().requestTimeout, Duration {0});
}

TEST_F(RuntimeOwnerTest, DoubleShutdownIsNoop)
{
    const auto before = settledTasks();
    ASSERT_TRUE(RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1)).ok());
    EXPECT_EQ(RuntimeOwner::shutdown(), Cause::None);
    EXPECT_EQ(RuntimeOwner::shutdown(), Cause::None);
    EXPECT_FALSE(RuntimeOwner::running());
    EXPECT_EQ(settledTasks(), before);
}

TEST_F(RuntimeOwnerTest, OwnerApiFromOtherThreadFails)
{
    auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
    ASSERT_TRUE(ref.ok());

    Cause start = Cause::None;
    Cause begin = Cause::None;
    Cause shutdown = Cause::None;
    std::thread other(
        [&]()
        {
            start = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1)).cause;
            begin = RuntimeOwner::beginShutdown(std::chrono::steady_clock::now());
            shutdown = RuntimeOwner::shutdown();
        });
    other.join();

    EXPECT_EQ(start, Cause::UsageError);
    EXPECT_EQ(begin, Cause::UsageError);
    EXPECT_EQ(shutdown, Cause::UsageError);
    EXPECT_TRUE(RuntimeOwner::running());
    EXPECT_TRUE(ref.value.valid());
    EXPECT_FALSE(ref.value.shutdownDeadline().has_value());
}

TEST_F(RuntimeOwnerTest, StaleRefAfterRestartInvalid)
{
    auto first = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(first.value.valid());
    ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);

    auto second = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
    ASSERT_TRUE(second.ok());
    EXPECT_FALSE(first.value.valid());
    EXPECT_EQ(first.value.client("stale", {}).cause, Cause::InvalidState);
    EXPECT_EQ(first.value.snapshot().networkThreads, 0u);

    EXPECT_TRUE(second.value.valid());
    EXPECT_TRUE(second.value.client("fresh", {}).ok());
}

TEST_F(RuntimeOwnerTest, FailedStartLeavesNoThreads)
{
    const auto before = settledTasks();
    auto failed = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 0)); // cpu_threads out of range.
    EXPECT_EQ(failed.cause, Cause::InvalidConfig);
    EXPECT_FALSE(RuntimeOwner::running());
    EXPECT_EQ(settledTasks(), before);

    auto unknown = RuntimeOwner::start(
        ProcessId::Analysisd,
        MapSource({{"analysisd.indexer_client_network_threads", "1"}, {"analysisd.indexer_client_bogus", "1"}}));
    EXPECT_EQ(unknown.cause, Cause::InvalidConfig);
    EXPECT_EQ(settledTasks(), before);

    auto ok = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
    ASSERT_TRUE(ok.ok()) << ok.reason;
    EXPECT_EQ(settledTasks().size(), before.size() + 2);
}

// Credentials are mandatory (also with http hosts). A missing one fails the start with InvalidConfig
// before any thread exists, and the reason never carries the value that was given.
TEST_F(RuntimeOwnerTest, MissingCredentialsUser)
{
    const std::string password = "s3cr3t-Pa55";
    const auto before = settledTasks();
    auto failed = RuntimeOwner::start(
        ProcessId::Analysisd,
        MapSource({{"analysisd.indexer_client_network_threads", "1"}, {"analysisd.indexer_client_cpu_threads", "1"}},
                  {"", password}));
    EXPECT_EQ(failed.cause, Cause::InvalidConfig) << failed.reason;
    EXPECT_NE(failed.reason.find("user"), std::string::npos) << failed.reason;
    EXPECT_EQ(failed.reason.find(password), std::string::npos) << "the reason leaks the password";
    EXPECT_FALSE(RuntimeOwner::running());
    EXPECT_EQ(settledTasks(), before);
}

TEST_F(RuntimeOwnerTest, MissingCredentialsPassword)
{
    const std::string user = "indexer-writer-7";
    const auto before = settledTasks();
    auto failed = RuntimeOwner::start(
        ProcessId::Analysisd,
        MapSource({{"analysisd.indexer_client_network_threads", "1"}, {"analysisd.indexer_client_cpu_threads", "1"}},
                  {user, ""}));
    EXPECT_EQ(failed.cause, Cause::InvalidConfig) << failed.reason;
    EXPECT_NE(failed.reason.find("password"), std::string::npos) << failed.reason;
    EXPECT_EQ(failed.reason.find(user), std::string::npos) << "the reason leaks the user";
    EXPECT_FALSE(RuntimeOwner::running());
    EXPECT_EQ(settledTasks(), before);
}

TEST_F(RuntimeOwnerTest, ClientAfterShutdownFails)
{
    auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
    ASSERT_TRUE(ref.ok());
    auto client = ref.value.client("early", {BucketSpec {"b"}});
    ASSERT_TRUE(client.ok());
    ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);

    EXPECT_FALSE(ref.value.valid());
    EXPECT_EQ(ref.value.client("late", {}).cause, Cause::InvalidState);
    EXPECT_FALSE(detail::testing::postToPool([]() {}));

    // A client that outlives the runtime still closes cleanly.
    EXPECT_TRUE(client.value->awaitClosed(std::chrono::steady_clock::now() + 1s).ok());
    client.value.reset();
}

TEST_F(RuntimeOwnerTest, AwaitClosedFromRuntimeThreadIsReentrancy)
{
    for (const auto where : {Where::Pool, Where::IoLoop})
    {
        SCOPED_TRACE(whereName(where));
        auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
        ASSERT_TRUE(ref.ok());
        auto client = ref.value.client("reentrant", {BucketSpec {"b"}});
        ASSERT_TRUE(client.ok());

        {
            Watchdog watchdog(10s, "AwaitClosedFromRuntimeThreadIsReentrancy");
            std::promise<std::pair<bool, Cause>> result;
            ASSERT_TRUE(postTo(where,
                               [&result, c = client.value]()
                               {
                                   const bool flagged = detail::testing::onRuntimeThread();
                                   result.set_value(
                                       {flagged, c->awaitClosed(std::chrono::steady_clock::now() + 60s).cause});
                               }));
            const auto [flagged, cause] = result.get_future().get();
            EXPECT_TRUE(flagged);
            EXPECT_EQ(cause, Cause::Reentrancy);
        }
        EXPECT_FALSE(detail::testing::onRuntimeThread());
        EXPECT_TRUE(client.value->awaitClosed(std::chrono::steady_clock::now() + 1s).ok());
        client.value.reset();
        ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
    }
}

TEST_F(RuntimeOwnerTest, RequestCloseFromRuntimeThreadDoesNotBlock)
{
    for (const auto where : {Where::Pool, Where::IoLoop})
    {
        SCOPED_TRACE(whereName(where));
        auto ref = RuntimeOwner::start(ProcessId::Analysisd, sourceWith(1, 1));
        ASSERT_TRUE(ref.ok());
        auto client = ref.value.client("closing", {BucketSpec {"b"}});
        ASSERT_TRUE(client.ok());
        const auto usageErrorsBefore = detail::testing::usageErrors();

        {
            Watchdog watchdog(10s, "RequestCloseFromRuntimeThreadDoesNotBlock");
            std::promise<std::chrono::steady_clock::duration> elapsed;
            // The task holds the last reference: requestClose() and then the (misused) destruction both run on the
            // runtime thread, and neither may wait.
            ASSERT_TRUE(postTo(where,
                               [&elapsed, c = std::move(client.value)]() mutable
                               {
                                   const auto begin = std::chrono::steady_clock::now();
                                   c->requestClose();
                                   c.reset();
                                   elapsed.set_value(std::chrono::steady_clock::now() - begin);
                               }));
            EXPECT_LT(elapsed.get_future().get(), std::chrono::steady_clock::duration(1s));
        }
        EXPECT_EQ(detail::testing::usageErrors(), usageErrorsBefore + 1)
            << "destroying a Client on a runtime thread is a counted usage error (logged, no abort)";
        EXPECT_EQ(ref.value.snapshot().clients, 0u);
        ASSERT_EQ(RuntimeOwner::shutdown(), Cause::None);
    }
}
