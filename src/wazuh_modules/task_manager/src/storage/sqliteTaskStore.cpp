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

#include "sqliteTaskStore.hpp"

#include "schema.hpp"

#include <sys/stat.h>

#include <algorithm>
#include <ctime>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace
{
    using SQLite3Wrapper::Statement;
    using task_manager::Timestamp;

    /// @brief Bind a value that may be SQL NULL. bindNull() must go through the wrapper: step()
    ///        only executes once every parameter is accounted for.
    void bindOptional(Statement& statement, const int index, const std::optional<std::string>& value)
    {
        if (value.has_value())
        {
            statement.bind(index, *value);
        }
        else
        {
            statement.bindNull(index);
        }
    }

    void bindOptional(Statement& statement, const int index, const std::optional<Timestamp>& value)
    {
        if (value.has_value())
        {
            statement.bind(index, static_cast<std::int64_t>(*value));
        }
        else
        {
            statement.bindNull(index);
        }
    }

    std::optional<std::string> readOptionalText(const Statement& statement, const int index)
    {
        if (!statement.hasValue(index))
        {
            return std::nullopt;
        }
        return statement.value<std::string>(index);
    }

    std::optional<Timestamp> readOptionalTime(const Statement& statement, const int index)
    {
        if (!statement.hasValue(index))
        {
            return std::nullopt;
        }
        return static_cast<Timestamp>(statement.value<std::int64_t>(index));
    }

    /// @brief Read a MANAGER_TASKS row from the 15-column projection shared by MtGet and
    ///        MtGetByAgent. Both statements carry the same column list and order precisely so this
    ///        function can serve them both; changing one without the other silently misreads rows.
    task_manager::ManagerTask readManagerTaskRow(const Statement& statement)
    {
        task_manager::ManagerTask task;
        task.taskId = statement.value<std::string>(0);
        task.taskType = statement.value<std::string>(1);
        task.agentId = readOptionalText(statement, 2);
        task.payload = statement.value<std::string>(3);
        task.createTime = static_cast<Timestamp>(statement.value<std::int64_t>(4));
        task.status = task_manager::taskStatusFromString(statement.value<std::string>(5))
                          .value_or(task_manager::TaskStatus::Pending);
        task.owner = readOptionalText(statement, 6);
        task.claimTime = readOptionalTime(statement, 7);
        task.attempts = statement.value<std::int32_t>(8);
        task.deferCount = statement.value<std::int32_t>(9);
        task.lastError = readOptionalText(statement, 10);
        task.nextAttemptAt = static_cast<Timestamp>(statement.value<std::int64_t>(11));
        task.scheduleId = readOptionalText(statement, 12);
        task.scheduledRunAt = readOptionalTime(statement, 13);
        task.endTime = readOptionalTime(statement, 14);
        return task;
    }

    int clampLimit(const int limit)
    {
        if (limit <= 0)
        {
            return task_manager::storage::DEFAULT_PAGE_SIZE;
        }
        return std::min(limit, task_manager::storage::MAX_PAGE_SIZE);
    }

    /// @brief Did the last statement fail because the row already exists?
    ///
    /// Both extended codes are accepted on purpose. TASK_ID is a TEXT PRIMARY KEY on a rowid
    /// table, which SQLite implements as an automatic unique index, and which of
    /// SQLITE_CONSTRAINT_PRIMARYKEY or SQLITE_CONSTRAINT_UNIQUE it reports has not been stable
    /// across versions -- the error message says "UNIQUE constraint failed" either way. Since the
    /// build can import a precompiled libsqlite3 whose version we do not control, treating only
    /// one of them as a duplicate would turn an ordinary idempotent re-create into a hard error
    /// on some hosts and not others.
    bool isDuplicateKey(sqlite3* handle)
    {
        const auto code {sqlite3_extended_errcode(handle)};
        return code == SQLITE_CONSTRAINT_PRIMARYKEY || code == SQLITE_CONSTRAINT_UNIQUE;
    }
} // namespace

namespace task_manager::storage
{
    void SqliteTaskStore::SqliteDeleter::operator()(sqlite3* handle) const noexcept
    {
        if (handle != nullptr)
        {
            sqlite3_close_v2(handle);
        }
    }

    sqlite3* SqliteTaskStore::Session::openHandle(const std::string& path)
    {
        sqlite3* raw {nullptr};
        const auto flags {SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE};

        if (const auto result {sqlite3_open_v2(path.c_str(), &raw, flags, nullptr)}; result != SQLITE_OK)
        {
            std::string message {"Failed to open tasks database at '" + path + "': "};
            message += sqlite3_errstr(result);
            if (raw != nullptr)
            {
                message += " - ";
                message += sqlite3_errmsg(raw);
                sqlite3_close_v2(raw);
            }
            throw std::runtime_error(message);
        }

        // A transient lock -- a previous process instance whose WAL handle has not been released
        // across a fast restart -- would otherwise surface as an immediate "database is locked".
        sqlite3_busy_timeout(raw, DB_BUSY_TIMEOUT_MS);
        return raw;
    }

    SqliteTaskStore::Session::Session(const std::string& path)
        : handle {openHandle(path)}
        , connection {handle.get()}
    {
        if (path != DB_MEMORY)
        {
            // 0640: readable by the wazuh group, writable only by the owner. The database holds
            // task payloads, which can carry Active Response parameters.
            if (::chmod(path.c_str(), DB_PERMISSIONS) != 0)
            {
                throw std::runtime_error("Failed to set permissions on tasks database '" + path + "'");
            }
        }
    }

    SQLite3Wrapper::Statement& SqliteTaskStore::Session::stmt(const Stmt id)
    {
        auto& slot {statements.at(static_cast<std::size_t>(id))};
        if (!slot)
        {
            slot =
                std::make_unique<SQLite3Wrapper::Statement>(connection, STATEMENT_SQL.at(static_cast<std::size_t>(id)));
        }
        slot->reset();
        return *slot;
    }

    SqliteTaskStore::SqliteTaskStore(Options options)
        : m_options {std::move(options)}
    {
        m_session = std::make_unique<Session>(m_options.dbPath);
        applyPragmas();
        applySchema();
        migrate();

        // Prepare every statement up front rather than lazily. Preparing is microseconds, and
        // doing it here turns a typo in the catalogue into a startup failure instead of a
        // first-use failure on some rarely exercised path.
        for (std::size_t i = 0; i < STATEMENT_COUNT; ++i)
        {
            static_cast<void>(m_session->stmt(static_cast<Stmt>(i)));
        }
    }

    SqliteTaskStore::~SqliteTaskStore()
    {
        try
        {
            flushWrites();
        }
        catch (...) // NOLINT(bugprone-empty-catch)
        {
            // A destructor may not throw, and there is nothing left to do about it: the rows the
            // lost batch describes stay claimed and the next boot's sweep reclaims them.
        }
    }

    void SqliteTaskStore::applyPragmas() const
    {
        const auto& connection {m_session->connection};

        // WAL, on EVERY open rather than only on create. A create-only pragma would leave a
        // database made by an earlier version in rollback-journal mode forever. journal_mode
        // returns a row and cannot run inside a transaction, hence execute() before anything else.
        connection.execute("PRAGMA journal_mode=WAL;");

        // FULL, deliberately, and NOT the NORMAL that global.db uses. Under WAL, NORMAL means a
        // committed transaction can be lost to a host crash until the next checkpoint -- a strange
        // thing to trade away for the one database whose entire purpose is durability.
        connection.execute("PRAGMA synchronous=FULL;");

        connection.execute("PRAGMA foreign_keys=OFF;");
        connection.execute("PRAGMA temp_store=MEMORY;");
    }

    void SqliteTaskStore::applySchema() const
    {
        // Idempotent: every statement is CREATE ... IF NOT EXISTS. That also means it CANNOT alter
        // an existing table's shape -- any such change needs a real step in migrate().
        m_session->connection.execute(SCHEMA_DDL);
    }

    void SqliteTaskStore::migrate()
    {
        const auto& connection {m_session->connection};

        SQLite3Wrapper::Statement read {connection, "PRAGMA user_version;"};
        int version {0};
        if (read.step() == SQLITE_ROW)
        {
            version = read.value<std::int32_t>(0);
        }

        if (version > SCHEMA_VERSION)
        {
            throw std::runtime_error("tasks database is at schema version " + std::to_string(version) +
                                     ", newer than this build understands (" + std::to_string(SCHEMA_VERSION) +
                                     "). Refusing to open it.");
        }

        // No migration steps yet: 5.0 is always a fresh install, so version 0 (a database created
        // before the pragma was set) and version 1 are the same shape. Future steps go here, each
        // guarded by `if (version < N)`, ending with the pragma write below.
        if (version != SCHEMA_VERSION)
        {
            connection.execute("PRAGMA user_version = " + std::to_string(SCHEMA_VERSION) + ";");
        }
    }

    void SqliteTaskStore::beginIfNeededLocked()
    {
        if (!m_txnOpen)
        {
            // IMMEDIATE, not DEFERRED: take the write lock now. Everything here serialises on
            // m_mutex anyway, so there is no lock to contend for -- but a deferred transaction
            // that upgrades mid-way can fail with SQLITE_BUSY_SNAPSHOT, and this cannot.
            m_session->connection.execute("BEGIN IMMEDIATE;");
            m_txnOpen = true;
            m_txnOpenedAt = std::chrono::steady_clock::now();
        }
    }

    void SqliteTaskStore::commitLocked()
    {
        if (m_txnOpen)
        {
            m_session->connection.execute("COMMIT;");
            m_txnOpen = false;
        }
    }

    void SqliteTaskStore::rollbackLocked()
    {
        if (m_txnOpen)
        {
            try
            {
                m_session->connection.execute("ROLLBACK;");
            }
            catch (...) // NOLINT(bugprone-empty-catch)
            {
                // Nothing useful to do: the connection is already in trouble and the caller is
                // about to see the original exception, which is the informative one.
            }
            m_txnOpen = false;
        }
    }

    template<typename Fn>
    auto SqliteTaskStore::inTransaction(const bool commitNow, Fn&& fn) -> decltype(fn(std::declval<Session&>()))
    {
        using Result = decltype(fn(std::declval<Session&>()));

        std::lock_guard lock {m_mutex};
        beginIfNeededLocked();

        // Committing when the window has already elapsed, rather than only on a timer, is what
        // bounds a batch under sustained load: the first write past the window closes it, so no
        // caller ever waits for the scheduler's tick to make its predecessor durable.
        const auto shouldCommit {
            [&]
            { return commitNow || std::chrono::steady_clock::now() - m_txnOpenedAt >= m_options.groupCommitWindow; }};

        try
        {
            if constexpr (std::is_void_v<Result>)
            {
                fn(*m_session);
                if (shouldCommit())
                {
                    commitLocked();
                }
            }
            else
            {
                auto result = fn(*m_session);
                if (shouldCommit())
                {
                    commitLocked();
                }
                return result;
            }
        }
        catch (...)
        {
            // Rolls back the whole open batch, not just this statement. Writes batched alongside
            // it are re-derivable from their rows' own state -- an unwritten outcome leaves the
            // row claimed for the sweep to reclaim -- which is the same property that makes group
            // commit safe in the first place.
            rollbackLocked();
            throw;
        }
    }

    template<typename Fn>
    auto SqliteTaskStore::inRead(Fn&& fn) -> decltype(fn(std::declval<Session&>()))
    {
        std::lock_guard lock {m_mutex};
        return fn(*m_session);
    }

    // ---- agent tasks -------------------------------------------------------------------------

    bool SqliteTaskStore::createAgentTask(const AgentTask& task)
    {
        return createAgentTasks({task}).front();
    }

    std::vector<bool> SqliteTaskStore::createAgentTasks(const std::vector<AgentTask>& tasks)
    {
        std::vector<bool> results;
        results.reserve(tasks.size());

        // One transaction for the whole batch. This is what makes a fleet-wide restart -- which
        // the framework issues in chunks of 500 -- one fsync instead of 500 round trips.
        inTransaction(true,
                      [&](Session& session)
                      {
                          for (const auto& task : tasks)
                          {
                              auto& statement {session.stmt(Stmt::AgentTaskInsert)};
                              statement.bind(1, task.taskId);
                              statement.bind(2, task.agentId);
                              statement.bind(3, task.taskType);
                              statement.bind(4, task.payload);
                              statement.bind(5, static_cast<std::int64_t>(task.createTime));

                              try
                              {
                                  statement.step();
                                  results.push_back(true);
                              }
                              catch (const SQLite3Wrapper::Sqlite3Error&)
                              {
                                  // A duplicate id is SUCCESS: ids are deterministic, so the same
                                  // logical request arriving twice -- from a retry, or from two
                                  // cluster nodes -- is one task, not an error. Any other SQLite
                                  // failure would have aborted the transaction, and does: it
                                  // propagates out of inTransaction().
                                  if (isDuplicateKey(session.handle.get()))
                                  {
                                      results.push_back(true);
                                  }
                                  else
                                  {
                                      throw;
                                  }
                              }
                          }
                      });

        return results;
    }

    std::vector<AgentTask> SqliteTaskStore::takePendingAgentTasks(const std::string& agentId, const int maxTasks)
    {
        std::vector<AgentTask> tasks;

        // Read and mark delivered in ONE transaction. The retired C path spent a whole wazuh-db
        // connect/query/close cycle per returned task; this is one commit for all of them.
        //
        // Batched rather than committed inline: marking delivered before delivery is attempted is
        // pre-existing behaviour that both remoted pollers compensate for with their own retry
        // lists, and wazuh-db already deferred this write by up to 60 seconds. Re-delivery after a
        // crash was therefore always possible; batching does not make it more so.
        inTransaction(false,
                      [&](Session& session)
                      {
                          auto& select {session.stmt(Stmt::AgentTaskGetPending)};
                          select.bind(1, agentId);
                          select.bind(2, maxTasks > 0 ? maxTasks : DEFAULT_PAGE_SIZE);

                          while (select.step() == SQLITE_ROW)
                          {
                              AgentTask task;
                              task.taskId = select.value<std::string>(0);
                              task.agentId = agentId;
                              task.taskType = select.value<std::string>(1);
                              task.payload = select.value<std::string>(2);
                              task.createTime = static_cast<Timestamp>(select.value<std::int64_t>(3));
                              tasks.push_back(std::move(task));
                          }

                          if (tasks.empty())
                          {
                              return;
                          }

                          const auto deliveryTime {static_cast<std::int64_t>(std::time(nullptr))};
                          for (const auto& task : tasks)
                          {
                              auto& mark {session.stmt(Stmt::AgentTaskMarkDelivered)};
                              mark.bind(1, deliveryTime);
                              mark.bind(2, task.taskId);
                              mark.step();
                          }
                      });

        return tasks;
    }

    std::int64_t SqliteTaskStore::expireAgentTasks(const Timestamp createdBefore)
    {
        return inTransaction(false,
                             [&](Session& session)
                             {
                                 auto& statement {session.stmt(Stmt::AgentTaskExpire)};
                                 statement.bind(1, static_cast<std::int64_t>(createdBefore));
                                 statement.step();
                                 return session.connection.changes();
                             });
    }

    std::int64_t SqliteTaskStore::deleteOldAgentTasks(const Timestamp before)
    {
        return inTransaction(false,
                             [&](Session& session)
                             {
                                 auto& statement {session.stmt(Stmt::AgentTaskDeleteOld)};
                                 statement.bind(1, static_cast<std::int64_t>(before));
                                 statement.bind(2, static_cast<std::int64_t>(before));
                                 statement.step();
                                 return session.connection.changes();
                             });
    }

    // ---- manager tasks -----------------------------------------------------------------------

    CreateManagerTaskOutcome SqliteTaskStore::createManagerTask(const CreateManagerTaskRequest& request)
    {
        // Commits inline. authd drops its journal lines on this return, so an `ok` that is only
        // buffered would move the orphan window one process to the right rather than closing it.
        return inTransaction(
            true,
            [&](Session& session) -> CreateManagerTaskOutcome
            {
                // (a) Coalesce probe, for types that opt in. Per-type rather than universal:
                // dedup'ing every (AGENT_ID, TASK_TYPE) would collapse two distinct deletions of
                // one agent into one row.
                if (request.coalesce && request.agentId.has_value())
                {
                    auto& probe {session.stmt(Stmt::MtFindPendingByAgent)};
                    probe.bind(1, *request.agentId);
                    probe.bind(2, request.taskType);
                    if (probe.step() == SQLITE_ROW)
                    {
                        // The SURVIVING id, not the requested one -- otherwise the caller holds an
                        // id with no row behind it.
                        return {CreateResult::Coalesced, probe.value<std::string>(0)};
                    }
                }

                // (b) Admission bound. Exact because it shares this transaction with the insert.
                if (request.maxPending != UNBOUNDED)
                {
                    auto& count {session.stmt(Stmt::MtCountPendingByType)};
                    count.bind(1, request.taskType);
                    if (count.step() == SQLITE_ROW && count.value<std::int64_t>(0) >= request.maxPending)
                    {
                        return {CreateResult::QueueFull, {}};
                    }
                }

                auto& insert {session.stmt(Stmt::MtInsert)};
                insert.bind(1, request.taskId);
                insert.bind(2, request.taskType);
                insert.bind(3, request.payload);
                insert.bind(4, static_cast<std::int64_t>(request.createTime));
                bindOptional(insert, 5, request.agentId);
                insert.bind(6, static_cast<std::int64_t>(request.nextAttemptAt.value_or(request.createTime)));
                bindOptional(insert, 7, request.scheduleId);
                bindOptional(insert, 8, request.scheduledRunAt);

                try
                {
                    insert.step();
                }
                catch (const SQLite3Wrapper::Sqlite3Error&)
                {
                    if (isDuplicateKey(session.handle.get()))
                    {
                        // Normal for a deterministic id, a broken RNG for a random one. The caller
                        // knows which of the two it asked for and logs accordingly.
                        return {CreateResult::Collided, request.taskId};
                    }
                    throw;
                }

                return {CreateResult::Created, request.taskId};
            });
    }

    std::optional<ClaimedTask>
    SqliteTaskStore::claim(const std::string& taskType, const std::string& owner, const Timestamp now)
    {
        // Commits inline. Winning the UPDATE is not enough: the claim's whole purpose is to be
        // visible to other workers before the handler runs.
        return inTransaction(true,
                             [&](Session& session) -> std::optional<ClaimedTask>
                             {
                                 auto& select {session.stmt(Stmt::MtSelectClaimable)};
                                 select.bind(1, taskType);
                                 select.bind(2, static_cast<std::int64_t>(now));

                                 if (select.step() != SQLITE_ROW)
                                 {
                                     return std::nullopt;
                                 }

                                 ClaimedTask claimed;
                                 claimed.taskId = select.value<std::string>(0);
                                 claimed.taskType = select.value<std::string>(1);
                                 claimed.agentId = readOptionalText(select, 2);
                                 claimed.payload = select.value<std::string>(3);
                                 claimed.attempts = select.value<std::int32_t>(4);
                                 claimed.deferCount = select.value<std::int32_t>(5);

                                 auto& update {session.stmt(Stmt::MtClaim)};
                                 update.bind(1, owner);
                                 update.bind(2, static_cast<std::int64_t>(now));
                                 update.bind(3, claimed.taskId);
                                 update.step();

                                 return claimed;
                             });
    }

    RequeueResult SqliteTaskStore::requeue(const RequeueRequest& request)
    {
        return inTransaction(false,
                             [&](Session& session) -> RequeueResult
                             {
                                 if (request.coalesce && request.agentId.has_value() && request.taskType.has_value())
                                 {
                                     auto& probe {session.stmt(Stmt::MtFindCompetingPending)};
                                     probe.bind(1, *request.agentId);
                                     probe.bind(2, *request.taskType);
                                     probe.bind(3, request.taskId);

                                     if (probe.step() == SQLITE_ROW)
                                     {
                                         const auto survivorId {probe.value<std::string>(0)};
                                         const auto survivorAttempts {probe.value<std::int32_t>(1)};
                                         const auto survivorDefers {probe.value<std::int32_t>(2)};

                                         // The survivor inherits the MAXIMUM of both rows' counters, so the budget
                                         // belongs to the work rather than to the row. Without this a coalescing
                                         // type can never dead-letter under load: every timed-out row is superseded
                                         // by a fresh row starting at zero and nothing ever terminates -- quietly,
                                         // because the pending count stays bounded and nothing looks wrong.
                                         auto& inherit {session.stmt(Stmt::MtInheritCounters)};
                                         inherit.bind(1, std::max(survivorAttempts, request.attempts));
                                         inherit.bind(2, std::max(survivorDefers, request.deferCount));
                                         inherit.bind(3, survivorId);
                                         inherit.step();

                                         auto& supersede {session.stmt(Stmt::MtSupersede)};
                                         bindOptional(supersede, 1, request.lastError);
                                         supersede.bind(2, static_cast<std::int64_t>(request.nextAttemptAt));
                                         supersede.bind(3, request.taskId);
                                         supersede.step();

                                         return RequeueResult::Superseded;
                                     }
                                 }

                                 auto& update {session.stmt(Stmt::MtRequeue)};
                                 update.bind(1, static_cast<std::int64_t>(request.nextAttemptAt));
                                 update.bind(2, request.attempts);
                                 update.bind(3, request.deferCount);
                                 bindOptional(update, 4, request.lastError);
                                 update.bind(5, request.taskId);
                                 update.step();

                                 return RequeueResult::Requeued;
                             });
    }

    void SqliteTaskStore::setResult(const std::string& taskId,
                                    const TaskStatus status,
                                    const int attempts,
                                    const int deferCount,
                                    const std::optional<std::string>& lastError,
                                    const Timestamp endTime)
    {
        if (!isTerminal(status) || status == TaskStatus::Superseded)
        {
            // Superseded is decided at re-queue time by observing a competing row; no handler can
            // report it, so accepting it here would let one bypass that check.
            throw std::invalid_argument("setResult accepts completed, failed or dead_letter only");
        }

        inTransaction(false,
                      [&](Session& session)
                      {
                          auto& update {session.stmt(Stmt::MtSetResult)};
                          update.bind(1, std::string {toString(status)});
                          bindOptional(update, 2, lastError);
                          update.bind(3, attempts);
                          update.bind(4, deferCount);
                          update.bind(5, static_cast<std::int64_t>(endTime));
                          update.bind(6, taskId);
                          update.step();
                      });
    }

    std::optional<ManagerTask> SqliteTaskStore::getManagerTask(const std::string& taskId)
    {
        return inRead(
            [&](Session& session) -> std::optional<ManagerTask>
            {
                auto& statement {session.stmt(Stmt::MtGet)};
                statement.bind(1, taskId);
                if (statement.step() != SQLITE_ROW)
                {
                    return std::nullopt;
                }
                return readManagerTaskRow(statement);
            });
    }

    std::optional<ManagerTask> SqliteTaskStore::getManagerTaskByAgent(const std::string& agentId,
                                                                      const std::string& taskType)
    {
        return inRead(
            [&](Session& session) -> std::optional<ManagerTask>
            {
                auto& statement {session.stmt(Stmt::MtGetByAgent)};
                statement.bind(1, agentId);
                statement.bind(2, taskType);
                if (statement.step() != SQLITE_ROW)
                {
                    return std::nullopt;
                }
                return readManagerTaskRow(statement);
            });
    }

    std::vector<ManagerTaskSummary> SqliteTaskStore::listManagerTasks(const std::string& taskType,
                                                                      const std::optional<TaskStatus>& status,
                                                                      const std::string& afterTaskId,
                                                                      const int limit)
    {
        const auto pageSize {clampLimit(limit)};

        return inRead(
            [&](Session& session)
            {
                std::vector<ManagerTaskSummary> rows;

                auto& statement {status.has_value() ? session.stmt(Stmt::MtListByTypeStatus)
                                                    : session.stmt(Stmt::MtListByType)};
                int index {1};
                statement.bind(index++, taskType);
                if (status.has_value())
                {
                    statement.bind(index++, std::string {toString(*status)});
                }
                statement.bind(index++, afterTaskId);
                statement.bind(index, pageSize);

                while (statement.step() == SQLITE_ROW)
                {
                    ManagerTaskSummary row;
                    row.taskId = statement.value<std::string>(0);
                    row.agentId = readOptionalText(statement, 1);
                    row.status = taskStatusFromString(statement.value<std::string>(2)).value_or(TaskStatus::Pending);
                    row.createTime = static_cast<Timestamp>(statement.value<std::int64_t>(3));
                    row.lastError = readOptionalText(statement, 4);
                    rows.push_back(std::move(row));
                }

                return rows;
            });
    }

    std::int64_t SqliteTaskStore::countManagerTasks(const std::string& taskType, const TaskStatus status)
    {
        return inRead(
            [&](Session& session) -> std::int64_t
            {
                auto& statement {session.stmt(Stmt::MtCountByTypeStatus)};
                statement.bind(1, taskType);
                statement.bind(2, std::string {toString(status)});
                if (statement.step() != SQLITE_ROW)
                {
                    return 0;
                }
                return statement.value<std::int64_t>(0);
            });
    }

    std::vector<DueType> SqliteTaskStore::pendingTypes()
    {
        return inRead(
            [&](Session& session)
            {
                std::vector<DueType> types;
                auto& statement {session.stmt(Stmt::MtPollDue)};
                while (statement.step() == SQLITE_ROW)
                {
                    types.push_back(
                        {statement.value<std::string>(0), static_cast<Timestamp>(statement.value<std::int64_t>(1))});
                }
                return types;
            });
    }

    std::optional<Timestamp> SqliteTaskStore::minPendingNextAttemptAt()
    {
        return inRead(
            [&](Session& session) -> std::optional<Timestamp>
            {
                auto& statement {session.stmt(Stmt::MtMinPendingNextAttempt)};
                if (statement.step() != SQLITE_ROW || !statement.hasValue(0))
                {
                    // MIN() over an empty set is one row containing NULL, not zero rows.
                    return std::nullopt;
                }
                return static_cast<Timestamp>(statement.value<std::int64_t>(0));
            });
    }

    std::vector<std::string> SqliteTaskStore::distinctPendingTaskTypes()
    {
        return inRead(
            [&](Session& session)
            {
                std::vector<std::string> types;
                auto& statement {session.stmt(Stmt::MtPendingTypes)};
                while (statement.step() == SQLITE_ROW)
                {
                    types.push_back(statement.value<std::string>(0));
                }
                return types;
            });
    }

    std::int64_t SqliteTaskStore::failPendingByType(const std::string& taskType,
                                                    const std::string& lastError,
                                                    const Timestamp endTime)
    {
        return inTransaction(false,
                             [&](Session& session)
                             {
                                 auto& statement {session.stmt(Stmt::MtFailByType)};
                                 statement.bind(1, lastError);
                                 statement.bind(2, static_cast<std::int64_t>(endTime));
                                 statement.bind(3, taskType);
                                 statement.step();
                                 return session.connection.changes();
                             });
    }

    std::vector<ClaimedRow>
    SqliteTaskStore::claimedRows(const std::string& owner, const std::string& afterTaskId, const int limit)
    {
        const auto pageSize {clampLimit(limit)};

        return inRead(
            [&](Session& session)
            {
                std::vector<ClaimedRow> rows;

                // An empty owner means EVERY claimed row, whoever owns it -- the startup form,
                // whose result set is bounded by nothing after repeated crashes. Both forms page
                // on TASK_ID rather than OFFSET.
                auto& statement {owner.empty() ? session.stmt(Stmt::MtSelectClaimedAny)
                                               : session.stmt(Stmt::MtSelectClaimedByOwner)};
                int index {1};
                if (!owner.empty())
                {
                    statement.bind(index++, owner);
                }
                statement.bind(index++, afterTaskId);
                statement.bind(index, pageSize);

                while (statement.step() == SQLITE_ROW)
                {
                    ClaimedRow row;
                    row.taskId = statement.value<std::string>(0);
                    row.taskType = statement.value<std::string>(1);
                    row.agentId = readOptionalText(statement, 2);
                    row.owner = statement.value<std::string>(3);
                    row.claimTime = static_cast<Timestamp>(statement.value<std::int64_t>(4));
                    row.attempts = statement.value<std::int32_t>(5);
                    row.deferCount = statement.value<std::int32_t>(6);
                    rows.push_back(std::move(row));
                }

                return rows;
            });
    }

    RetentionStats SqliteTaskStore::applyRetention(const RetentionRules& rules)
    {
        return inTransaction(false,
                             [&](Session& session)
                             {
                                 RetentionStats stats;

                                 if (rules.terminalBefore.has_value())
                                 {
                                     auto& statement {session.stmt(Stmt::MtDeleteTerminalOld)};
                                     statement.bind(1, static_cast<std::int64_t>(*rules.terminalBefore));
                                     statement.step();
                                     stats.byAge += session.connection.changes();
                                 }

                                 if (rules.deadLetterBefore.has_value())
                                 {
                                     auto& statement {session.stmt(Stmt::MtDeleteDeadLetterOld)};
                                     statement.bind(1, static_cast<std::int64_t>(*rules.deadLetterBefore));
                                     statement.step();
                                     stats.byAge += session.connection.changes();
                                 }

                                 if (rules.historyPerSchedule != UNBOUNDED)
                                 {
                                     std::vector<std::string> scheduleIds;
                                     {
                                         auto& statement {session.stmt(Stmt::MtScheduleIds)};
                                         while (statement.step() == SQLITE_ROW)
                                         {
                                             scheduleIds.push_back(statement.value<std::string>(0));
                                         }
                                     }

                                     for (const auto& scheduleId : scheduleIds)
                                     {
                                         auto& statement {session.stmt(Stmt::MtTrimScheduleHistory)};
                                         statement.bind(1, scheduleId);
                                         statement.bind(2, scheduleId);
                                         statement.bind(3, rules.historyPerSchedule);
                                         statement.step();
                                         stats.bySchedule += session.connection.changes();
                                     }
                                 }

                                 std::int64_t total {0};
                                 {
                                     auto& statement {session.stmt(Stmt::MtCountAll)};
                                     if (statement.step() == SQLITE_ROW)
                                     {
                                         total = statement.value<std::int64_t>(0);
                                     }
                                 }

                                 if (rules.maxRows != UNBOUNDED && total > rules.maxRows)
                                 {
                                     auto& statement {session.stmt(Stmt::MtEvict)};
                                     statement.bind(1, static_cast<std::int32_t>(total - rules.maxRows));
                                     statement.step();
                                     stats.byCeiling = session.connection.changes();
                                     total -= stats.byCeiling;
                                 }

                                 // Reported so the caller can notice a ceiling it could not meet: the excess is
                                 // then pending, claimed or dead-lettered rows that no rule may remove.
                                 stats.remaining = total;
                                 return stats;
                             });
    }

    // ---- schedules ---------------------------------------------------------------------------

    std::optional<ScheduleRow>
    SqliteTaskStore::upsertSchedule(const std::string& scheduleId, const Timestamp nextRunAt, const bool enabled)
    {
        return inTransaction(true,
                             [&](Session& session) -> std::optional<ScheduleRow>
                             {
                                 std::optional<ScheduleRow> previous;
                                 {
                                     auto& statement {session.stmt(Stmt::SchedGet)};
                                     statement.bind(1, scheduleId);
                                     if (statement.step() == SQLITE_ROW)
                                     {
                                         previous =
                                             ScheduleRow {statement.value<std::string>(0),
                                                          static_cast<Timestamp>(statement.value<std::int64_t>(1)),
                                                          statement.value<std::int32_t>(2) != 0};
                                     }
                                 }

                                 if (previous.has_value())
                                 {
                                     auto& statement {session.stmt(Stmt::SchedUpdate)};
                                     statement.bind(1, static_cast<std::int64_t>(nextRunAt));
                                     statement.bind(2, enabled ? 1 : 0);
                                     statement.bind(3, scheduleId);
                                     statement.step();
                                 }
                                 else
                                 {
                                     auto& statement {session.stmt(Stmt::SchedInsert)};
                                     statement.bind(1, scheduleId);
                                     statement.bind(2, static_cast<std::int64_t>(nextRunAt));
                                     statement.bind(3, enabled ? 1 : 0);
                                     statement.step();
                                 }

                                 return previous;
                             });
    }

    void SqliteTaskStore::setScheduleNextRun(const std::string& scheduleId, const Timestamp nextRunAt)
    {
        inTransaction(false,
                      [&](Session& session)
                      {
                          auto& statement {session.stmt(Stmt::SchedSetNextRun)};
                          statement.bind(1, static_cast<std::int64_t>(nextRunAt));
                          statement.bind(2, scheduleId);
                          statement.step();
                      });
    }

    std::vector<ScheduleRow> SqliteTaskStore::dueSchedules(const Timestamp now)
    {
        return inRead(
            [&](Session& session)
            {
                std::vector<ScheduleRow> rows;
                auto& statement {session.stmt(Stmt::SchedListDue)};
                statement.bind(1, static_cast<std::int64_t>(now));
                while (statement.step() == SQLITE_ROW)
                {
                    rows.push_back({statement.value<std::string>(0),
                                    static_cast<Timestamp>(statement.value<std::int64_t>(1)),
                                    true});
                }
                return rows;
            });
    }

    bool SqliteTaskStore::scheduleHasActiveRun(const std::string& scheduleId)
    {
        return inRead(
            [&](Session& session)
            {
                auto& statement {session.stmt(Stmt::SchedHasActive)};
                statement.bind(1, scheduleId);
                return statement.step() == SQLITE_ROW;
            });
    }

    std::optional<Timestamp> SqliteTaskStore::minScheduleNextRun()
    {
        return inRead(
            [&](Session& session) -> std::optional<Timestamp>
            {
                auto& statement {session.stmt(Stmt::SchedMinNextRun)};
                if (statement.step() != SQLITE_ROW || !statement.hasValue(0))
                {
                    return std::nullopt;
                }
                return static_cast<Timestamp>(statement.value<std::int64_t>(0));
            });
    }

    // ---- maintenance -------------------------------------------------------------------------

    void SqliteTaskStore::flushWrites()
    {
        std::lock_guard lock {m_mutex};
        commitLocked();
    }

    void SqliteTaskStore::vacuum()
    {
        std::lock_guard lock {m_mutex};

        // VACUUM cannot run inside a transaction, and the retention pass that shares this tick
        // will have left one open. Committing first is what the retired wazuh-db `sql` passthrough
        // failed to do, leaving a timing-dependent failure that reproduced on some hosts only.
        commitLocked();

        // Finalize every prepared statement too: VACUUM rewrites the database file, and SQLite
        // refuses while any statement is live. Session::stmt() re-prepares lazily afterwards.
        for (auto& slot : m_session->statements)
        {
            slot.reset();
        }

        m_session->connection.execute("VACUUM;");
    }

    std::optional<std::string> SqliteTaskStore::getMetadata(const std::string& key)
    {
        return inRead(
            [&](Session& session) -> std::optional<std::string>
            {
                auto& statement {session.stmt(Stmt::MetaGet)};
                statement.bind(1, key);
                if (statement.step() != SQLITE_ROW)
                {
                    return std::nullopt;
                }
                return statement.value<std::string>(0);
            });
    }

    void SqliteTaskStore::setMetadata(const std::string& key, const std::string& value)
    {
        inTransaction(false,
                      [&](Session& session)
                      {
                          auto& statement {session.stmt(Stmt::MetaSet)};
                          statement.bind(1, key);
                          statement.bind(2, value);
                          statement.step();
                      });
    }
} // namespace task_manager::storage
