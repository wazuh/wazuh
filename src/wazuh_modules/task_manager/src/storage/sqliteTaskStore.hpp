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

#ifndef _TASK_MANAGER_STORAGE_SQLITE_TASK_STORE_HPP
#define _TASK_MANAGER_STORAGE_SQLITE_TASK_STORE_HPP

#include "iTaskStore.hpp"
#include "statements.hpp"

#include <sqlite3Wrapper.hpp>

#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace task_manager::storage
{
    /**
     * @brief The module's SQLite-backed store. Sole owner of tasks.db.
     *
     * CONNECTIONS. One connection behind one mutex, for everything. WAL allows exactly one writer
     * anyway, so serialising ourselves removes SQLITE_BUSY as a category rather than retrying
     * around it.
     *
     * A read-only connection pool was considered and rejected. It would serve only get/list/count
     * and the liveness probe: the one high-frequency route, taking an agent's pending tasks, marks
     * them delivered and is therefore a WRITE, and the negative cache keeps idle polls out of
     * SQLite altogether. So the pool would add a lease, a free-list, a shared-cache special case
     * for :memory: tests, and a read-freshness question -- reader snapshots cannot see a batched
     * write -- to speed up operations that are already microseconds and rare. One connection makes
     * every read see this module's own uncommitted writes, which is both simpler and more correct.
     *
     * GROUP COMMIT. With synchronous=FULL every commit is an fsync, and at task rates the fsync
     * dominates. Writes that must be durable before they are observed -- createManagerTask() and
     * claim() -- commit inline. Everything else (outcomes, re-queues, schedule advances, retention)
     * accumulates in one open transaction that is committed by the next inline write, by the
     * scheduler's tick, or once the window expires, whichever comes first.
     *
     * That is safe for exactly the reason the design gives for not committing outcomes at all: if
     * the process dies with an outcome unwritten, the row stays claimed, the next boot's sweep
     * reclaims it and the handler runs again. Every handler is idempotent, so the repeat is
     * absorbed. Group commit only widens a window the design already had to survive.
     *
     * The one consequence worth stating: a statement that throws rolls back the whole open batch,
     * so writes batched alongside it are lost too. They are re-derivable from the rows' own state
     * for the same reason, and the failure is logged loudly by the caller.
     */
    class SqliteTaskStore final : public ITaskStore
    {
    public:
        struct Options
        {
            /// @brief Absolute path, or DB_MEMORY for tests.
            std::string dbPath;
            /// @brief How long a batched write may wait for its commit.
            std::chrono::milliseconds groupCommitWindow {20};
        };

        explicit SqliteTaskStore(Options options);
        ~SqliteTaskStore() override;

        SqliteTaskStore(const SqliteTaskStore&) = delete;
        SqliteTaskStore& operator=(const SqliteTaskStore&) = delete;

        // ---- agent tasks ---------------------------------------------------------------------
        bool createAgentTask(const AgentTask& task) override;
        std::vector<bool> createAgentTasks(const std::vector<AgentTask>& tasks) override;
        std::vector<AgentTask> takePendingAgentTasks(const std::string& agentId, int maxTasks) override;
        std::int64_t expireAgentTasks(Timestamp createdBefore) override;
        std::int64_t deleteOldAgentTasks(Timestamp before) override;

        // ---- manager tasks -------------------------------------------------------------------
        CreateManagerTaskOutcome createManagerTask(const CreateManagerTaskRequest& request) override;
        std::optional<ClaimedTask> claim(const std::string& taskType,
                                         const std::string& owner,
                                         Timestamp now) override;
        RequeueResult requeue(const RequeueRequest& request) override;
        void setResult(const std::string& taskId,
                       TaskStatus status,
                       int attempts,
                       int deferCount,
                       const std::optional<std::string>& lastError,
                       Timestamp endTime) override;
        std::optional<ManagerTask> getManagerTask(const std::string& taskId) override;
        std::optional<ManagerTask> getManagerTaskByAgent(const std::string& agentId,
                                                         const std::string& taskType) override;
        std::vector<ManagerTaskSummary> listManagerTasks(const std::string& taskType,
                                                         const std::optional<TaskStatus>& status,
                                                         const std::string& afterTaskId,
                                                         int limit) override;
        std::int64_t countManagerTasks(const std::string& taskType, TaskStatus status) override;
        std::vector<DueType> pendingTypes() override;
        std::optional<Timestamp> minPendingNextAttemptAt() override;
        std::vector<std::string> distinctPendingTaskTypes() override;
        std::int64_t failPendingByType(const std::string& taskType,
                                       const std::string& lastError,
                                       Timestamp endTime) override;
        std::vector<ClaimedRow> claimedRows(const std::string& owner,
                                            const std::string& afterTaskId,
                                            int limit) override;
        RetentionStats applyRetention(const RetentionRules& rules) override;

        // ---- schedules -----------------------------------------------------------------------
        std::optional<ScheduleRow> upsertSchedule(const std::string& scheduleId,
                                                  Timestamp nextRunAt,
                                                  bool enabled) override;
        void setScheduleNextRun(const std::string& scheduleId, Timestamp nextRunAt) override;
        std::vector<ScheduleRow> dueSchedules(Timestamp now) override;
        bool scheduleHasActiveRun(const std::string& scheduleId) override;
        std::optional<Timestamp> minScheduleNextRun() override;

        // ---- maintenance ---------------------------------------------------------------------
        void flushWrites() override;
        void vacuum() override;
        std::optional<std::string> getMetadata(const std::string& key) override;
        void setMetadata(const std::string& key, const std::string& value) override;

    private:
        struct SqliteDeleter
        {
            void operator()(sqlite3* handle) const noexcept;
        };

        /// @brief The connection and its prepared statements.
        ///
        /// Member ORDER is load-bearing: statements are finalized before the handle is closed, and
        /// every Statement holds a reference to the Connection beside it, so the whole Session is
        /// held by unique_ptr to keep that address stable.
        struct Session
        {
            explicit Session(const std::string& path);

            /// @brief Open the database and hand back an owning raw handle.
            ///
            /// Separate from the constructor body because SQLite3Wrapper::Connection declares a
            /// destructor and is therefore neither movable nor assignable -- the connection must
            /// be built in the member initialiser list, from a handle that already exists.
            static sqlite3* openHandle(const std::string& path);

            std::unique_ptr<sqlite3, SqliteDeleter> handle;
            SQLite3Wrapper::Connection connection;
            std::array<std::unique_ptr<SQLite3Wrapper::Statement>, STATEMENT_COUNT> statements;

            /// @brief Reset and return a statement, ready to be bound. Resetting on the way IN
            ///        rather than out means a statement left mid-cursor by an early return or an
            ///        exception is still clean for the next caller.
            SQLite3Wrapper::Statement& stmt(Stmt id);
        };

        /// @brief Run `fn` inside a transaction, holding the connection mutex.
        /// @param commitNow true for the two writes whose return is treated as durable by their
        ///                  caller. false batches, subject to the group-commit window.
        template<typename Fn>
        auto inTransaction(bool commitNow, Fn&& fn) -> decltype(fn(std::declval<Session&>()));

        /// @brief Run a pure read, holding the connection mutex. Reads see this module's own
        ///        uncommitted writes, so no flush is needed.
        template<typename Fn>
        auto inRead(Fn&& fn) -> decltype(fn(std::declval<Session&>()));

        void beginIfNeededLocked();
        void commitLocked();
        void rollbackLocked();

        void applyPragmas() const;
        void applySchema() const;
        void migrate();

        Options m_options;

        std::mutex m_mutex;
        std::unique_ptr<Session> m_session;
        bool m_txnOpen {false};
        std::chrono::steady_clock::time_point m_txnOpenedAt {};
    };
} // namespace task_manager::storage

#endif // _TASK_MANAGER_STORAGE_SQLITE_TASK_STORE_HPP
