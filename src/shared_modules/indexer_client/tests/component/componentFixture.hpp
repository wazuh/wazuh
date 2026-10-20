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

#ifndef _INDEXER_CLIENT_TESTS_COMPONENT_FIXTURE_HPP
#define _INDEXER_CLIENT_TESTS_COMPONENT_FIXTURE_HPP

// Shared by the component suites of the transport (plan 18, plan-E2a-1 §Tests): the runtime fixture, a test-owned
// IConfigSource, the result collector and small helpers. Every wait is bounded; the state callbacks touch is held by
// shared_ptr, so a test that gives up on a wait never leaves a callback writing into a dead frame.

#include <pthread.h>
#include <sys/socket.h>
#include <unistd.h>

#include <netinet/in.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include "indexer_client/runtime.hpp"
#include "testing/hooks.hpp"
#include "transport/transport.hpp"

namespace component
{
    using namespace std::chrono_literals;
    using indexer_client::detail::HttpMethod;
    using indexer_client::detail::HttpRequest;
    using indexer_client::detail::HttpResult;
    using indexer_client::detail::Transport;
    using indexer_client::detail::TransportCause;

    /// Test-owned configuration source: `analysisd.indexer_client_<name>` keys.
    class MapSource final : public indexer_client::IConfigSource
    {
    public:
        /// `indexerJson` is the <indexer> section (default: one http host, no ssl).
        explicit MapSource(std::map<std::string, std::string> values,
                           std::string indexerJson = R"({"hosts":["http://127.0.0.1:9200"]})")
            : m_values(std::move(values))
            , m_indexerJson(std::move(indexerJson))
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
            return m_indexerJson;
        }

        indexer_client::Credentials credentials() const override
        {
            return {"user", "pass"};
        }

    private:
        std::map<std::string, std::string> m_values;
        std::string m_indexerJson;
    };

    /// Polls `predicate` (1 ms apart) for a condition that has no notification of its own; false past `timeout`.
    inline bool eventually(const std::function<bool()>& predicate, std::chrono::milliseconds timeout)
    {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!predicate())
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return predicate();
            }
            std::this_thread::sleep_for(1ms);
        }
        return true;
    }

    inline std::string currentThreadName()
    {
        char buffer[16] = {};
        pthread_getname_np(pthread_self(), buffer, sizeof(buffer));
        return buffer;
    }

    /// A loopback port with nothing listening (bound, then closed): connecting to it is refused at once.
    inline int closedPort()
    {
        const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_in address {};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        socklen_t length = sizeof(address);
        ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
        ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
        ::close(fd);
        return ntohs(address.sin_port);
    }

    inline std::uint64_t sumOf(const std::vector<std::uint64_t>& values)
    {
        std::uint64_t total = 0;
        for (const auto value : values)
        {
            total += value;
        }
        return total;
    }

    /// Records every result by a test-chosen key (the id is only known once submit returns, the callback may come
    /// first): how many times each key was called back, the last result and the thread it ran on.
    class Collector final : public std::enable_shared_from_this<Collector>
    {
    public:
        static std::shared_ptr<Collector> create()
        {
            return std::shared_ptr<Collector>(new Collector());
        }

        /// The callback for `key`. It holds the collector by shared_ptr.
        indexer_client::detail::ResultCallback callbackFor(std::uint64_t key)
        {
            return [self = shared_from_this(), key](HttpResult&& result)
            {
                const auto name = currentThreadName();
                {
                    std::lock_guard<std::mutex> lock(self->m_mutex);
                    ++self->m_count[key];
                    self->m_threads[key] = name;
                    self->m_results[key] = std::move(result);
                    ++self->m_total;
                }
                self->m_cv.notify_all();
            };
        }

        std::uint64_t newKey()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_nextKey++;
        }

        bool waitTotal(std::size_t total, std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_total >= total; });
        }

        bool waitKey(std::uint64_t key, std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_count.count(key) != 0; });
        }

        /// Waits until `predicate` holds, re-checked on every callback (and at least every 50 ms).
        bool waitFor(const std::function<bool()>& predicate, std::chrono::milliseconds timeout)
        {
            const auto deadline = std::chrono::steady_clock::now() + timeout;
            std::unique_lock<std::mutex> lock(m_mutex);
            for (;;)
            {
                lock.unlock();
                if (predicate())
                {
                    return true;
                }
                lock.lock();
                if (std::chrono::steady_clock::now() >= deadline)
                {
                    lock.unlock();
                    return predicate();
                }
                m_cv.wait_for(lock, 50ms);
            }
        }

        int count(std::uint64_t key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto it = m_count.find(key);
            return it == m_count.end() ? 0 : it->second;
        }

        std::size_t total() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_total;
        }

        std::optional<HttpResult> result(std::uint64_t key) const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            const auto it = m_results.find(key);
            if (it == m_results.end())
            {
                return std::nullopt;
            }
            return it->second;
        }

        std::map<std::uint64_t, std::string> threads() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_threads;
        }

        std::map<std::uint64_t, int> counts() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_count;
        }

    private:
        Collector() = default;

        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::uint64_t m_nextKey {0};
        std::size_t m_total {0};
        std::map<std::uint64_t, int> m_count;
        std::map<std::uint64_t, std::string> m_threads;
        std::map<std::uint64_t, HttpResult> m_results;
    };

    struct Submitted final
    {
        std::uint64_t key {0};
        indexer_client::detail::Admission admission;
    };

    inline HttpRequest request(HttpMethod method,
                               std::string url,
                               std::shared_ptr<const std::string> body = nullptr,
                               indexer_client::Duration timeout = indexer_client::Duration {0})
    {
        HttpRequest req;
        req.method = method;
        req.url = std::move(url);
        req.body = std::move(body);
        req.timeout = timeout;
        return req;
    }

    inline Submitted submitTo(Transport& transport, const std::shared_ptr<Collector>& collector, HttpRequest req)
    {
        Submitted submitted;
        submitted.key = collector->newKey();
        submitted.admission = transport.submit(std::move(req), collector->callbackFor(submitted.key));
        return submitted;
    }

    /// A task that occupies one runtime thread (a network loop or a pool worker) until released, so a test can line
    /// work up behind it. Bounded: it lets go by itself after `limit`.
    class Blocker final : public std::enable_shared_from_this<Blocker>
    {
    public:
        static std::shared_ptr<Blocker> create(std::chrono::milliseconds limit = 15s)
        {
            return std::shared_ptr<Blocker>(new Blocker(limit));
        }

        std::function<void()> task()
        {
            return [self = shared_from_this()]()
            {
                std::unique_lock<std::mutex> lock(self->m_mutex);
                ++self->m_started;
                self->m_cv.notify_all();
                if (!self->m_cv.wait_for(lock, self->m_limit, [&] { return self->m_released; }))
                {
                    self->m_expired = true;
                }
            };
        }

        bool waitStarted(std::size_t count, std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            return m_cv.wait_for(lock, timeout, [&] { return m_started >= count; });
        }

        void release()
        {
            {
                std::lock_guard<std::mutex> lock(m_mutex);
                m_released = true;
            }
            m_cv.notify_all();
        }

        /// Whether a blocked task let go on its own (the test never released it in time).
        bool expired() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_expired;
        }

    private:
        explicit Blocker(std::chrono::milliseconds limit)
            : m_limit(limit)
        {
        }

        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::chrono::milliseconds m_limit;
        std::size_t m_started {0};
        bool m_released {false};
        bool m_expired {false};
    };

    /// Releases a Blocker when the scope ends, so an early ASSERT return never leaves a runtime thread pinned.
    /// Declare it after any AsyncCall that waits on the blocked thread: it must run first.
    class ReleaseOnExit final
    {
    public:
        explicit ReleaseOnExit(std::shared_ptr<Blocker> blocker)
            : m_blocker(std::move(blocker))
        {
        }

        ~ReleaseOnExit()
        {
            m_blocker->release();
        }

        ReleaseOnExit(const ReleaseOnExit&) = delete;
        ReleaseOnExit& operator=(const ReleaseOnExit&) = delete;

    private:
        std::shared_ptr<Blocker> m_blocker;
    };

    /// Runs `body` on a thread and lets the test wait for it with a bound. If the bound passes the thread is
    /// detached (it only holds shared state), so a hang becomes a failure, never a frozen suite.
    class AsyncCall final
    {
    public:
        explicit AsyncCall(std::function<void()> body)
            : m_state(std::make_shared<State>())
        {
            m_thread = std::thread(
                [state = m_state, body = std::move(body)]()
                {
                    body();
                    {
                        std::lock_guard<std::mutex> lock(state->mutex);
                        state->done = true;
                    }
                    state->cv.notify_all();
                });
        }

        ~AsyncCall()
        {
            if (m_thread.joinable())
            {
                if (wait(30s))
                {
                    m_thread.join();
                }
                else
                {
                    m_thread.detach();
                }
            }
        }

        AsyncCall(const AsyncCall&) = delete;
        AsyncCall& operator=(const AsyncCall&) = delete;

        bool wait(std::chrono::milliseconds timeout)
        {
            std::unique_lock<std::mutex> lock(m_state->mutex);
            return m_state->cv.wait_for(lock, timeout, [&] { return m_state->done; });
        }

        bool done() const
        {
            std::lock_guard<std::mutex> lock(m_state->mutex);
            return m_state->done;
        }

    private:
        struct State final
        {
            std::mutex mutex;
            std::condition_variable cv;
            bool done {false};
        };

        std::shared_ptr<State> m_state;
        std::thread m_thread;
    };

    /// Kernel tasks of this process.
    inline std::set<std::string> tasks()
    {
        std::set<std::string> ids;
        for (const auto& entry : std::filesystem::directory_iterator("/proc/self/task"))
        {
            ids.insert(entry.path().filename().string());
        }
        return ids;
    }

    /// Two consecutive listings that agree (a joined thread can linger in /proc for a moment).
    inline std::set<std::string> settledTasks()
    {
        auto previous = tasks();
        for (int i = 0; i < 400; ++i)
        {
            std::this_thread::sleep_for(5ms);
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

    /// curl_easy_init calls made by the library since process start, counted by the interposer defined in
    /// transportConnections_test.cpp: a delta of 0 across a transfer means it reused an easy from the free-list.
    std::uint64_t easyHandlesCreated();
} // namespace component

/// Every transport component case: starts the runtime with a test source, reaches the transport through
/// detail::runtimeTransport() and always shuts the runtime down and clears the hooks.
class TransportTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        indexer_client::testing_hooks::resetAll();
    }

    void TearDown() override
    {
        indexer_client::RuntimeOwner::shutdown();
        indexer_client::testing_hooks::resetAll();
        EXPECT_FALSE(indexer_client::RuntimeOwner::running());
    }

    /// Starts a runtime with K network and M CPU threads (plus any other `indexer_client_<name>` values).
    std::shared_ptr<indexer_client::detail::Transport>
    startRuntime(std::uint32_t k, std::uint32_t m, std::map<std::string, std::string> extra = {})
    {
        std::map<std::string, std::string> values {{"analysisd.indexer_client_network_threads", std::to_string(k)},
                                                   {"analysisd.indexer_client_cpu_threads", std::to_string(m)}};
        for (auto& [name, value] : extra)
        {
            values["analysisd.indexer_client_" + name] = value;
        }
        auto started =
            indexer_client::RuntimeOwner::start(indexer_client::ProcessId::Analysisd, component::MapSource(values));
        EXPECT_TRUE(started.ok()) << indexer_client::toString(started.cause) << ": " << started.reason;
        auto transport = indexer_client::detail::runtimeTransport();
        EXPECT_NE(transport, nullptr);
        return transport;
    }
};

#endif // _INDEXER_CLIENT_TESTS_COMPONENT_FIXTURE_HPP
