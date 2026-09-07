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

#ifndef _TASK_MANAGER_MODEL_TASK_ID_HPP
#define _TASK_MANAGER_MODEL_TASK_ID_HPP

#include "task.hpp"

#include <string>
#include <string_view>

namespace task_manager::taskId
{
    /*
     * Identity is per task kind, and the differences are load-bearing rather than incidental.
     *
     *   determinism is for creators that can run twice for ONE logical event;
     *   randomness  is for creators that can be called twice meaning TWO DIFFERENT things.
     *
     * Both recipes below must stay byte-identical to their C counterparts in
     * shared/src/manager_task_op.c and the retired wm_task_manager_tasks.c. Changing either
     * silently breaks idempotency: the spawn loop's crash safety is a primary-key collision, and
     * authd treats a collision as "already recorded".
     *
     * The two recipes this module does NOT implement are producer-side and stay in C:
     * manager_task_id_agent_delete (keyed on authd's journal sequence) and manager_task_id_random
     * (vd_scan). They are never derived here, only received.
     */

    /// @brief SHA-256 of `data`, rendered as 64 lowercase hex characters.
    std::string sha256Hex(std::string_view data);

    /**
     * @brief Identity of one scheduled run: SHA-256("mt:sched:<schedule_id>:<scheduled_run_at>").
     *
     * Keyed on the SLOT, not on the moment of spawning. That is the whole of the spawn loop's
     * crash safety: a crash between inserting the instance and advancing NEXT_RUN_AT re-derives
     * the same id on retry, and the primary-key collision makes the double-spawn a no-op. No
     * cross-table transaction is needed.
     *
     * @param scheduleId     A built-in schedule id. Short by construction, so this cannot differ
     *                       from the C form, which formats into a 128-byte buffer.
     * @param scheduledRunAt The slot, as seconds since the epoch.
     */
    std::string forScheduledRun(std::string_view scheduleId, Timestamp scheduledRunAt);

    /**
     * @brief Identity of an agent task, in the legacy UUID-like shape.
     *
     * SHA-256 of `<source_id>:<agent_id>:<task_type>:<create_time>`, or of
     * `<agent_id>:<task_type>:<create_time>` when source_id is absent or empty -- and yes, those
     * two forms ALIAS: an empty source_id and an omitted one produce the same id. That is
     * pre-existing behaviour on a shipping path (Active Response passes a document id, everything
     * else omits it), reproduced here deliberately rather than fixed, because changing it would
     * change ids for tasks already in flight across an upgrade.
     *
     * Only the first 16 bytes of the digest survive, formatted 8-4-4-4-12. Truncated, and
     * therefore weaker than the manager-task ids; also unchanged, for the same reason.
     */
    std::string
    forAgentTask(std::string_view sourceId, std::string_view agentId, std::string_view taskType, Timestamp createTime);
} // namespace task_manager::taskId

#endif // _TASK_MANAGER_MODEL_TASK_ID_HPP
