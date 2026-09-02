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

#include "taskRegistry.hpp"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <utility>

namespace task_manager::registry
{
    TaskRegistry::TaskRegistry(RetryPolicy policy, std::vector<TaskTypeDescriptor> descriptors)
        : m_policy {std::move(policy)}
        , m_descriptors {std::move(descriptors)}
    {
        std::set<std::string, std::less<>> seen;

        for (auto& descriptor : m_descriptors)
        {
            if (descriptor.name.empty())
            {
                throw std::invalid_argument("task type registered with an empty name");
            }

            if (!seen.insert(descriptor.name).second)
            {
                throw std::invalid_argument("task type '" + descriptor.name + "' registered twice");
            }

            if (!descriptor.handler)
            {
                throw std::invalid_argument("task type '" + descriptor.name + "' has no handler");
            }

            if (descriptor.maxConcurrent < 1)
            {
                throw std::invalid_argument("task type '" + descriptor.name +
                                            "' has a concurrency cap below one, which would make it "
                                            "unrunnable while its rows accumulate forever");
            }

            if (descriptor.watchdogBudget.count() <= 0)
            {
                throw std::invalid_argument("task type '" + descriptor.name +
                                            "' has no watchdog budget; the stall predicate would then "
                                            "fire on healthy work");
            }

            if (descriptor.concurrencyGroup.empty())
            {
                descriptor.concurrencyGroup = descriptor.name;
            }

            const auto [it, inserted] {
                m_groupLimits.emplace(descriptor.concurrencyGroup, descriptor.maxConcurrent)};

            if (!inserted && it->second != descriptor.maxConcurrent)
            {
                throw std::invalid_argument("concurrency group '" + descriptor.concurrencyGroup +
                                            "' is declared with two different caps (" +
                                            std::to_string(it->second) + " and " +
                                            std::to_string(descriptor.maxConcurrent) +
                                            "); there is no defensible way to resolve that");
            }
        }
    }

    const TaskTypeDescriptor* TaskRegistry::find(const std::string_view name) const noexcept
    {
        const auto it {std::find_if(m_descriptors.cbegin(),
                                    m_descriptors.cend(),
                                    [&name](const TaskTypeDescriptor& descriptor)
                                    { return descriptor.name == name; })};

        return it == m_descriptors.cend() ? nullptr : &(*it);
    }

    std::vector<std::string> TaskRegistry::typeNames() const
    {
        std::vector<std::string> names;
        names.reserve(m_descriptors.size());
        for (const auto& descriptor : m_descriptors)
        {
            names.push_back(descriptor.name);
        }
        return names;
    }
} // namespace task_manager::registry
