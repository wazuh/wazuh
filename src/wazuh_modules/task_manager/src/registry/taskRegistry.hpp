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

#ifndef _TASK_MANAGER_REGISTRY_TASK_REGISTRY_HPP
#define _TASK_MANAGER_REGISTRY_TASK_REGISTRY_HPP

#include "taskTypeDescriptor.hpp"

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace task_manager::registry
{
    /**
     * @brief The set of manager task types this build knows how to execute.
     *
     * Immutable once constructed. That is deliberate: the retired implementation handed out
     * `const` pointers into a table its own initialiser then wrote to, which meant the constness
     * documented nothing. Here the descriptors are validated, moved in, and never touched again,
     * so a caller holding a reference cannot be surprised.
     */
    class TaskRegistry
    {
    public:
        /**
         * @brief Validate and take ownership of the type set.
         *
         * @throws std::invalid_argument when any of the following does not hold. Each is a
         *         programming error that would otherwise fail late and quietly:
         *         - names are non-empty and unique (a duplicate would shadow a handler);
         *         - every descriptor carries a handler;
         *         - maxConcurrent is at least 1 (zero would make the type unrunnable while its
         *           rows accumulate forever, since a pending manager task never ages out);
         *         - every watchdog budget is greater than zero. A budget of zero degenerates the
         *           stall predicate to the bare margin, which healthy work legitimately exceeds --
         *           agent_delete_old is ALLOWED thirty seconds of occupancy, and rotation gzips up
         *           to half a gigabyte inline. A warning that fires on correct behaviour is worse
         *           than no warning;
         *         - types sharing a concurrency group agree on its cap. Two different caps for one
         *           group has no defensible answer, so it is refused rather than resolved.
         */
        TaskRegistry(RetryPolicy policy, std::vector<TaskTypeDescriptor> descriptors);

        /// @return nullptr when the type is unknown -- which is normal, not exceptional: a row
        ///         whose type was renamed or removed across an upgrade is exactly what the
        ///         orphaned-type reaper looks for.
        const TaskTypeDescriptor* find(std::string_view name) const noexcept;

        const std::vector<TaskTypeDescriptor>& all() const noexcept { return m_descriptors; }

        const RetryPolicy& policy() const noexcept { return m_policy; }

        /// @brief Concurrency cap per group, resolved from the descriptors.
        const std::map<std::string, int, std::less<>>& groupLimits() const noexcept { return m_groupLimits; }

        /// @brief Every registered type name, for the orphaned-type reaper's known set.
        std::vector<std::string> typeNames() const;

    private:
        RetryPolicy m_policy;
        std::vector<TaskTypeDescriptor> m_descriptors;
        std::map<std::string, int, std::less<>> m_groupLimits;
    };
} // namespace task_manager::registry

#endif // _TASK_MANAGER_REGISTRY_TASK_REGISTRY_HPP
