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
    /// refused, rows left without a file, and the errno of the last failure.
    struct LinkStats
    {
        std::size_t linked {0};
        std::size_t copied {0};
        std::size_t failed {0};
        int lastErrno {0};
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

        TaskLinks(std::string upgradeDir, storage::ITaskStore& store, LinkAt linkAt = {});

        /// @brief Gives every row its file and then runs @p commit, all under the mutex. A row whose
        /// file could not be created is counted in `failed`; @p commit runs regardless.
        LinkStats linkAndCommit(const std::vector<TaskLink>& rows, const std::function<void()>& commit);

        /// @brief Removes task files with no remote_upgrade row and leftover temporaries; touches
        /// nothing else. Returns the number of files removed.
        std::size_t sweep();

    private:
        std::string m_upgradeDir;
        storage::ITaskStore& m_store;
        LinkAt m_linkAt;
        std::mutex m_mutex;
    };
} // namespace task_manager::upgrade

#endif // _TASK_MANAGER_UPGRADE_TASK_LINKS_HPP
