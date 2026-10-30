/*
 * Wazuh task manager module
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _TASK_MANAGER_UPGRADE_TASK_LINKS_HPP
#define _TASK_MANAGER_UPGRADE_TASK_LINKS_HPP

#include "storage/iTaskStore.hpp"

#include <cstddef>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace task_manager::upgrade
{
    /// @brief One remote_upgrade row to give a per-task file: its task id and the WPK file name
    /// directly under the upgrade directory.
    struct TaskLink
    {
        std::string taskId;
        std::string wpkFile;
    };

    /// @brief What a linkAndCommit() call did: rows hard-linked, WPKs copied because a link was
    /// refused, rows left without a file, the errno of the last failure, and which input rows
    /// were staged (their file exists and the directory was synced), one flag per row.
    struct LinkStats
    {
        std::size_t linked {0};
        std::size_t copied {0};
        std::size_t failed {0};
        int lastErrno {0};
        std::vector<bool> staged;
    };

    /// @brief What a backfill() call did: pending rows given a file, and pending rows expired
    /// because their WPK was missing, changed or unusable.
    struct BackfillStats
    {
        std::size_t staged {0};
        std::size_t expired {0};
    };

    /**
     * @brief Owns `<upgradeDir>/tasks/`: one `<task_id>.wpk` per remote_upgrade row, which remoted
     *        serves when an agent redeems a signed WPK download identifier.
     *
     * A row's file exists before the row is committed and goes away once the row is gone. Both
     * halves run under one mutex, so the sweep never sees a file whose row is still being written.
     */
    class TaskLinks final
    {
    public:
        /// @brief linkat(2)-shaped hook; tests replace it to refuse links the way EPERM/EMLINK do.
        using LinkAt = std::function<int(int, const char*, int, const char*, int)>;
        /// @brief fsync(2)-shaped hook for the tasks directory; tests replace it to make it fail.
        using Fsync = std::function<int(int)>;
        /// @brief Receives the indices, into the rows given to linkAndCommit(), of the rows to store.
        using Commit = std::function<void(const std::vector<std::size_t>&)>;

        TaskLinks(std::string upgradeDir, storage::ITaskStore& store, LinkAt linkAt = {}, Fsync fsync = {});

        /// @brief Gives every row its file, syncs the directory and then runs @p commit with the
        /// staged rows only, all under the mutex. A row without a file is never committed; when
        /// the directory cannot be synced no row is.
        LinkStats linkAndCommit(const std::vector<TaskLink>& rows, const Commit& commit);

        /// @brief Gives each pending remote_upgrade row without a file one, from its WPK when that
        /// is still the file the row was created for (same SHA-1); expires the rest.
        BackfillStats backfill();

        /// @brief Removes task files with no remote_upgrade row and leftover temporaries; touches
        /// nothing else. Returns the number of files removed.
        std::size_t sweep();

    private:
        std::string m_upgradeDir;
        storage::ITaskStore& m_store;
        LinkAt m_linkAt;
        Fsync m_fsync;
        std::mutex m_mutex;
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_TASK_LINKS_HPP
