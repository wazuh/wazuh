/*
 * Wazuh task manager module
 * Copyright (C) 2015, Wazuh Inc.
 * September 1, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_TEST_DOUBLES_HPP
#define _TASK_MANAGER_TEST_DOUBLES_HPP

#include "execution/ownership.hpp"
#include "handlers/iHandler.hpp"
#include "host/iHostOps.hpp"
#include "registry/taskRegistry.hpp"
#include "storage/sqliteTaskStore.hpp"

#include <csignal>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace task_manager::test
{
    /**
     * @brief A handler whose outcome and duration the test controls, and which records what it ran.
     *
     * Not a gmock: the executor calls handlers from several worker threads at once, and what these
     * tests assert is what those threads DID -- how many ran, which ids, how many at a time -- which
     * is a recording, not a sequence of expectations.
     */
    class TestHandler final : public IHandler
    {
    public:
        explicit TestHandler(HandlerResult result = HandlerResult::ok())
            : m_result {std::move(result)}
        {
        }

        HandlerResult run(const ClaimedTask& task, const StopToken& stop) override
        {
            {
                std::lock_guard lock {m_mutex};
                m_ran.push_back(task.taskId);
                ++m_concurrent;
                m_peakConcurrent = std::max(m_peakConcurrent, m_concurrent);
            }

            if (m_hold.load())
            {
                // Held until the test releases it, so overlapping runs are observable rather than
                // inferred from timing.
                std::unique_lock lock {m_holdMutex};
                m_holdCondition.wait_for(
                    lock, std::chrono::seconds {5}, [this, &stop] { return !m_hold.load() || stop.stopRequested(); });
            }

            HandlerResult result;
            {
                std::lock_guard lock {m_mutex};
                --m_concurrent;
                result = m_nextResults.empty() ? m_result : m_nextResults.front();
                if (!m_nextResults.empty())
                {
                    m_nextResults.pop_front();
                }
                m_finished.notify_all();
            }

            return result;
        }

        /// @brief Queue one outcome per upcoming run; runs past the queue take the default.
        void queueResult(HandlerResult result)
        {
            std::lock_guard lock {m_mutex};
            m_nextResults.push_back(std::move(result));
        }

        void holdRuns(const bool hold)
        {
            m_hold.store(hold);
            std::lock_guard lock {m_holdMutex};
            m_holdCondition.notify_all();
        }

        std::vector<std::string> ran() const
        {
            std::lock_guard lock {m_mutex};
            return m_ran;
        }

        std::size_t runCount() const
        {
            std::lock_guard lock {m_mutex};
            return m_ran.size();
        }

        int peakConcurrent() const
        {
            std::lock_guard lock {m_mutex};
            return m_peakConcurrent;
        }

        /// @return true if `count` runs happened before the deadline.
        bool waitForRuns(const std::size_t count, const std::chrono::milliseconds timeout)
        {
            std::unique_lock lock {m_mutex};
            return m_finished.wait_for(lock, timeout, [this, count] { return m_ran.size() >= count; });
        }

    private:
        mutable std::mutex m_mutex;
        std::condition_variable m_finished;
        std::vector<std::string> m_ran;
        std::deque<HandlerResult> m_nextResults;
        HandlerResult m_result;
        int m_concurrent {0};
        int m_peakConcurrent {0};

        std::atomic<bool> m_hold {false};
        std::mutex m_holdMutex;
        std::condition_variable m_holdCondition;
    };

    /// @brief Build a registry of one type backed by `handler`, with everything else defaulted.
    inline registry::TaskRegistry registryWith(std::shared_ptr<IHandler> handler,
                                               const std::string& name = "test_type",
                                               const int maxConcurrent = 1,
                                               const std::string& group = {})
    {
        registry::TaskTypeDescriptor descriptor;
        descriptor.name = name;
        descriptor.concurrencyGroup = group.empty() ? name : group;
        descriptor.maxConcurrent = maxConcurrent;
        descriptor.watchdogBudget = std::chrono::seconds {60};
        descriptor.handler = std::move(handler);

        std::vector<registry::TaskTypeDescriptor> descriptors;
        descriptors.push_back(std::move(descriptor));
        return registry::TaskRegistry {registry::RetryPolicy {}, std::move(descriptors)};
    }

    /// @brief An in-memory store, committing every write immediately so a test never races a batch.
    inline std::unique_ptr<storage::SqliteTaskStore> makeMemoryStore()
    {
        storage::SqliteTaskStore::Options options;
        options.dbPath = DB_MEMORY;
        options.groupCommitWindow = std::chrono::milliseconds {0};
        return std::make_unique<storage::SqliteTaskStore>(std::move(options));
    }

    inline storage::CreateManagerTaskRequest pendingRow(const std::string& id,
                                                        const std::string& type = "test_type")
    {
        storage::CreateManagerTaskRequest request;
        request.taskId = id;
        request.taskType = type;
        request.payload = "{}";
        // nextAttemptAt deliberately left unset: the store seeds it from createTime, which is in
        // the past, so the row is eligible now AND the seeding rule is the thing under test rather
        // than something the fixture bypassed.
        request.createTime = 1000;
        return request;
    }

    /**
     * @brief An IHostOps the test drives directly.
     *
     * Scripted rather than mocked because the handlers using it loop, and what matters is the
     * SEQUENCE they see -- which agents come back, which lookups fail, what authd answers -- plus
     * a record of how many times they asked, which is what the bounding tests assert on.
     */
    class FakeHostOps final : public host::IHostOps
    {
    public:
        int workerState() override { return workerStateValue; }

        std::optional<std::vector<int>> disconnectAgents(long, const std::string&) override
        {
            ++disconnectCalls;

            if (afterDisconnectAgents)
            {
                afterDisconnectAgents();
            }

            return disconnected;
        }

        std::optional<std::vector<int>> agentsByStatusFrom(const int afterId, const std::string&) override
        {
            ++candidateCalls;
            lastCursor = afterId;

            if (afterCandidateQuery)
            {
                afterCandidateQuery();
            }

            if (!candidates.has_value())
            {
                return std::nullopt;
            }

            std::vector<int> page;
            for (const auto id : *candidates)
            {
                if (id > afterId)
                {
                    page.push_back(id);
                }
            }
            return page;
        }

        std::optional<nlohmann::json> agentInfo(const int agentId) override
        {
            ++infoCalls;

            if (missingInfoFor.count(agentId) != 0)
            {
                return std::nullopt;
            }

            // A scripted row wins, so the upgrade tests can supply os_platform/os_arch/version.
            // Wrapped in an ARRAY on purpose: that is the shape wazuh-db actually answers with and
            // the shim passes through verbatim, and a double that quietly unwrapped it would let a
            // caller that forgot host::agentRow() pass here and fail in production.
            if (const auto scripted {agentRows.find(agentId)}; scripted != agentRows.end())
            {
                return nlohmann::json::array({scripted->second});
            }

            return nlohmann::json {{"name", "agent-" + std::to_string(agentId)},
                                   {"last_keepalive", lastKeepalive}};
        }

        bool removeAgent(const int agentId, int, int& authdError) override
        {
            ++removeCalls;
            removed.push_back(agentId);
            authdError = nextAuthdError;
            return authdAnswers;
        }

        bool rotateLogDaily(bool, int, int) override
        {
            ++dailyRotations;
            return dailyRotationSucceeds;
        }

        bool rotateLogBySize(bool, int, int, long) override
        {
            ++sizeRotations;
            return sizeRotationHappens;
        }

        int workerStateValue {0};
        std::optional<std::vector<int>> disconnected {std::vector<int> {}};
        std::optional<std::vector<int>> candidates {std::vector<int> {}};
        std::set<int> missingInfoFor;
        /// @brief Per-agent rows for callers that need real OS fields, keyed by agent id.
        std::map<int, nlohmann::json> agentRows;
        Timestamp lastKeepalive {0};
        bool authdAnswers {true};
        int nextAuthdError {0};
        bool dailyRotationSucceeds {true};
        bool sizeRotationHappens {true};

        /* Both sweeps bail out before touching wazuh-db when a stop is already pending, so a token
         * stopped before run() only ever exercises that pre-flight check. These fire once the query
         * has been issued and answered, which is the only place a test can put a stop request that
         * the sweep's mid-walk checks are the ones to observe. */
        std::function<void()> afterDisconnectAgents;
        std::function<void()> afterCandidateQuery;

        std::atomic<int> disconnectCalls {0};
        std::atomic<int> candidateCalls {0};
        std::atomic<int> infoCalls {0};
        std::atomic<int> removeCalls {0};
        std::atomic<int> dailyRotations {0};
        std::atomic<int> sizeRotations {0};
        int lastCursor {-1};
        std::vector<int> removed;
    };

    /**
     * @brief A real process that is alive and is not this one, for the ownership rules that need a
     *        Foreign owner rather than a fabricated one.
     *
     * A forked child rather than pid 1, deliberately. On a booted system init's `starttime` in
     * /proc/<pid>/stat is genuinely 0, and 0 is also what processStartTime() returns when it cannot
     * read the file at all -- so pid 1 is the single pid where a test cannot tell a real start time
     * from a failure to read one, and a test written against it asserts nothing. A child of this
     * process started well after boot always has a non-zero tick.
     */
    class LiveForeignProcess
    {
    public:
        LiveForeignProcess()
        {
            m_pid = ::fork();

            if (m_pid == 0)
            {
                // Nothing here may return into gtest or run its exit handlers: this is a fork of an
                // instrumented test binary, and letting it unwind would duplicate every report the
                // parent is about to write. pause() only returns on a signal, and SIGKILL does not
                // return at all.
                for (;;)
                {
                    ::pause();
                }
            }

            if (m_pid > 0)
            {
                m_startTime = execution::processStartTime(m_pid);
            }
        }

        ~LiveForeignProcess()
        {
            if (m_pid > 0)
            {
                ::kill(m_pid, SIGKILL);
                ::waitpid(m_pid, nullptr, 0);
            }
        }

        LiveForeignProcess(const LiveForeignProcess&) = delete;
        LiveForeignProcess& operator=(const LiveForeignProcess&) = delete;

        bool valid() const { return m_pid > 0 && m_startTime > 0; }

        std::int32_t pid() const { return static_cast<std::int32_t>(m_pid); }

        std::uint64_t startTime() const { return m_startTime; }

        /// @brief The OWNER string this process would write, in the module's own format.
        std::string owner(const int workerIndex = 0) const
        {
            return std::to_string(m_pid) + ':' + std::to_string(m_startTime) + ":w" +
                   std::to_string(workerIndex);
        }

    private:
        ::pid_t m_pid {-1};
        std::uint64_t m_startTime {0};
    };
} // namespace task_manager::test

#endif // _TASK_MANAGER_TEST_DOUBLES_HPP
