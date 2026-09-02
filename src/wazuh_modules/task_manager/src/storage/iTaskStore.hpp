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

#ifndef _TASK_MANAGER_STORAGE_I_TASK_STORE_HPP
#define _TASK_MANAGER_STORAGE_I_TASK_STORE_HPP

#include "model/task.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace task_manager::storage
{
    /// @brief Sentinel for "no bound" on the admission and retention caps.
    constexpr int UNBOUNDED {0};

    /// @brief Default and maximum page size for the paged reads. Now a policy choice rather than
    ///        a consequence of a 64 KB response buffer, which is what set it in the retired
    ///        wazuh-db path.
    constexpr int DEFAULT_PAGE_SIZE {100};
    constexpr int MAX_PAGE_SIZE {1000};

    struct CreateManagerTaskRequest
    {
        std::string taskId;
        std::string taskType;
        std::string payload;
        std::optional<std::string> agentId;
        std::optional<std::string> scheduleId;
        std::optional<Timestamp> scheduledRunAt;
        Timestamp createTime {0};
        /// @brief Absent means "seed from createTime". Never 0 -- see storage/schema.hpp.
        std::optional<Timestamp> nextAttemptAt;
        /// @brief Per-type. Dedup'ing every (AGENT_ID, TASK_TYPE) would be wrong: two distinct
        ///        deletions of one agent must never collapse into one row.
        bool coalesce {false};
        /// @brief Admission bound on pending rows of this type. UNBOUNDED disables it.
        int maxPending {UNBOUNDED};
    };

    struct CreateManagerTaskOutcome
    {
        CreateResult result {CreateResult::Created};
        /// @brief The SURVIVING row's id. On Coalesced this is the pre-existing row, not the id
        ///        that was requested -- returning the requested one would hand the caller an id
        ///        with no row behind it.
        std::string taskId;
    };

    enum class RequeueResult
    {
        Requeued,  ///< The row is pending again.
        Superseded ///< A competing pending row held its slot; this row is terminal.
    };

    struct RequeueRequest
    {
        std::string taskId;
        /// @brief Only consulted when coalesce is set, to find a competing pending row.
        std::optional<std::string> taskType;
        std::optional<std::string> agentId;
        std::optional<std::string> lastError;
        Timestamp nextAttemptAt {0};
        int attempts {0};
        int deferCount {0};
        bool coalesce {false};
    };

    /// @brief One claimed row as the ownership sweep sees it.
    struct ClaimedRow
    {
        std::string taskId;
        std::string taskType;
        std::optional<std::string> agentId;
        std::string owner;
        Timestamp claimTime {0};
        int attempts {0};
        int deferCount {0};
    };

    /// @brief A task type with pending work, and when its earliest row becomes eligible.
    struct DueType
    {
        std::string taskType;
        Timestamp minNextAttemptAt {0};
    };

    struct ScheduleRow
    {
        std::string scheduleId;
        Timestamp nextRunAt {0};
        bool enabled {false};
    };

    struct RetentionRules
    {
        /// @brief Terminal rows with END_TIME before this are removed. Absent disables the rule.
        std::optional<Timestamp> terminalBefore;
        std::optional<Timestamp> deadLetterBefore;
        int historyPerSchedule {UNBOUNDED};
        int maxRows {UNBOUNDED};
    };

    struct RetentionStats
    {
        std::int64_t byAge {0};
        std::int64_t bySchedule {0};
        std::int64_t byCeiling {0};
        /// @brief Rows left afterwards. Reported so a caller can notice a ceiling it could not
        ///        meet: the excess is then pending, claimed or dead-lettered rows that no rule may
        ///        remove, which is worth a warning rather than silence.
        std::int64_t remaining {0};
    };

    /**
     * @brief Everything the module persists.
     *
     * One interface rather than three because all of it shares one connection and one write
     * transaction; splitting it would make the transaction boundaries a caller's problem.
     *
     * THREAD SAFETY: every method is safe to call concurrently. Writes serialize on one writer
     * connection; pure reads run on their own connections, so an operator listing dead letters
     * cannot queue behind the executor.
     *
     * DURABILITY, and the one thing a caller must know: createManagerTask() and claim() COMMIT
     * before returning, because a producer treats their return as durable and a claim must be
     * visible to other workers before the handler runs. Everything else is group-committed on a
     * short timer (see flushWrites()). If the process dies before an outcome lands, the row stays
     * claimed, the next boot's sweep reclaims it and the handler runs again -- which is why every
     * handler must be idempotent.
     */
    class ITaskStore
    {
    public:
        virtual ~ITaskStore() = default;

        // ---- agent tasks ---------------------------------------------------------------------

        /// @brief Store one agent task. An existing id is SUCCESS, not an error: ids are
        ///        deterministic, so the same logical request arriving twice is one task.
        virtual bool createAgentTask(const AgentTask& task) = 0;

        /// @brief Store many agent tasks in ONE transaction, for fleet-wide restart and reload.
        /// @return One flag per input, in order.
        virtual std::vector<bool> createAgentTasks(const std::vector<AgentTask>& tasks) = 0;

        /// @brief Read an agent's pending tasks AND mark them delivered, in one transaction.
        ///
        /// Marking on read is deliberate and preserved from the C implementation: delivery is the
        /// caller's job, and both remoted pollers keep their own retry list for what they could
        /// not hand over. Changing it would change observable behaviour for them.
        virtual std::vector<AgentTask> takePendingAgentTasks(const std::string& agentId, int maxTasks) = 0;

        /// @return Rows expired.
        virtual std::int64_t expireAgentTasks(Timestamp createdBefore) = 0;

        /// @return Rows removed.
        virtual std::int64_t deleteOldAgentTasks(Timestamp before) = 0;

        // ---- manager tasks -------------------------------------------------------------------

        /// @brief Coalesce probe, admission bound and insert, in one transaction. Commits.
        virtual CreateManagerTaskOutcome createManagerTask(const CreateManagerTaskRequest& request) = 0;

        /// @brief Take the earliest eligible row of one type. Commits before returning.
        /// @return The claimed row, or nullopt when nothing is eligible -- which is normal.
        virtual std::optional<ClaimedTask> claim(const std::string& taskType,
                                                 const std::string& owner,
                                                 Timestamp now) = 0;

        /// @brief Return a row to pending, or retire it as superseded when a competing pending row
        ///        already holds its slot.
        virtual RequeueResult requeue(const RequeueRequest& request) = 0;

        /// @brief Retire a row. `status` must be terminal and must not be Superseded, which is
        ///        never a handler's decision.
        virtual void setResult(const std::string& taskId,
                               TaskStatus status,
                               int attempts,
                               int deferCount,
                               const std::optional<std::string>& lastError,
                               Timestamp endTime) = 0;

        virtual std::optional<ManagerTask> getManagerTask(const std::string& taskId) = 0;

        virtual std::optional<ManagerTask> getManagerTaskByAgent(const std::string& agentId,
                                                                 const std::string& taskType) = 0;

        virtual std::vector<ManagerTaskSummary> listManagerTasks(const std::string& taskType,
                                                                 const std::optional<TaskStatus>& status,
                                                                 const std::string& afterTaskId,
                                                                 int limit) = 0;

        virtual std::int64_t countManagerTasks(const std::string& taskType, TaskStatus status) = 0;

        /// @brief Which types have pending work, and when each becomes eligible.
        virtual std::vector<DueType> pendingTypes() = 0;

        /// @brief The earliest NEXT_ATTEMPT_AT across all pending rows, or nullopt when there are
        ///        none. This is what lets the scheduler sleep exactly rather than poll.
        virtual std::optional<Timestamp> minPendingNextAttemptAt() = 0;

        /// @brief Distinct TASK_TYPE values among pending rows, for the orphaned-type reaper.
        virtual std::vector<std::string> distinctPendingTaskTypes() = 0;

        /// @brief Retire every pending row of a type the registry does not know.
        /// @return Rows affected.
        virtual std::int64_t failPendingByType(const std::string& taskType,
                                               const std::string& lastError,
                                               Timestamp endTime) = 0;

        /// @brief One page of claimed rows. An empty `owner` means EVERY claimed row, whoever owns
        ///        it -- the startup form, whose result set is bounded by nothing after repeated
        ///        crashes, which is why it pages.
        virtual std::vector<ClaimedRow> claimedRows(const std::string& owner,
                                                    const std::string& afterTaskId,
                                                    int limit) = 0;

        virtual RetentionStats applyRetention(const RetentionRules& rules) = 0;

        // ---- schedules -----------------------------------------------------------------------

        /// @brief Insert or update a schedule.
        /// @return The row as it was BEFORE the write, or nullopt if the schedule is new. The
        ///         previous ENABLED is the only way to detect a disabled-to-enabled transition,
        ///         which is the one signal that NEXT_RUN_AT must be recomputed -- and that
        ///         transition can straddle a restart.
        virtual std::optional<ScheduleRow> upsertSchedule(const std::string& scheduleId,
                                                          Timestamp nextRunAt,
                                                          bool enabled) = 0;

        virtual void setScheduleNextRun(const std::string& scheduleId, Timestamp nextRunAt) = 0;

        virtual std::vector<ScheduleRow> dueSchedules(Timestamp now) = 0;

        /// @brief True when a non-terminal instance of this schedule exists. Overlap is skipped,
        ///        not queued.
        virtual bool scheduleHasActiveRun(const std::string& scheduleId) = 0;

        virtual std::optional<Timestamp> minScheduleNextRun() = 0;

        // ---- maintenance ---------------------------------------------------------------------

        /// @brief Commit any open group-commit transaction. Called by the scheduler on every tick
        ///        and once more at shutdown.
        virtual void flushWrites() = 0;

        /// @brief Compact the database. Commits and finalizes first: VACUUM cannot run inside a
        ///        transaction.
        virtual void vacuum() = 0;

        virtual std::optional<std::string> getMetadata(const std::string& key) = 0;
        virtual void setMetadata(const std::string& key, const std::string& value) = 0;
    };
} // namespace task_manager::storage

#endif // _TASK_MANAGER_STORAGE_I_TASK_STORE_HPP
