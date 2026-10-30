/*
 * Wazuh Container Instances - container synchronization admission
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <algorithm>
#include <cstddef>
#include <iterator>
#include <set>
#include <string>

namespace wazuh::container_instances
{

    /* Which containers may report to the manager (#40097 follow-up),
     * kept apart from the store that applies it so it can be tested without a
     * snapshot, a socket or a clock.
     *
     * This is a THIRD layer, above the two that already exist. A row budget
     * refuses the store; a document budget gates the sync flag per dimension;
     * this one decides, per container, whether that container reports AT ALL.
     * Without it the total the agent ships is still unbounded -- the per-container
     * budgets multiply by however many containers the runtime happens to run.
     *
     * The decision is deliberately NOT a truncation of the container list.
     * sweepStale() and sweepContainerRowsNotIn() both delete on absence from the
     * known list, and MetadataStore erases a container that stops appearing after
     * REMOVAL_GRACE, emitting a `removed` event that consumers treat as authority
     * to delete that container's rows. So a container that is not admitted stays
     * fully present everywhere and only its sync flag changes.
     */

    /**
     * @brief Decide which containers may synchronize with the manager.
     *
     * @param known    Every container that currently exists. Not filtered, not
     *                 truncated -- see the note above on why.
     * @param admitted The previous decision, so incumbents can keep their slots.
     * @param limit    Containers that may report; <= 0 means unlimited.
     * @return The new admitted set, a subset of @p known.
     *
     * Two properties, and both are load-bearing:
     *
     * STICKY. An admitted container keeps its slot until it genuinely leaves
     * `known`. A new container never evicts an incumbent, so a steady node never
     * churns. The alternative -- ranking the whole set every pass -- looks
     * simpler and is not: container ids are random hex, so a new container sorts
     * below the incumbent Nth roughly N/M of the time, and each time it does the
     * manager is told to delete one container's rows and create another's. At
     * N=10, M=50 that is one container creation in five.
     *
     * DETERMINISTIC. Free slots fill by lowest id, so the same container set
     * yields the same decision on any agent and after any restart. Nothing on
     * this path can be ranked by age: there is no container creation time
     * anywhere in the record -- `startedAt` is the start of the CURRENT run, it
     * resets on restart, and it is absent entirely for a stopped Kubernetes
     * container. Lowest-id is arbitrary, but it is arbitrary in a way that is
     * reproducible, which walk order is not.
     */
    [[nodiscard]] inline std::set<std::string> admitContainers(const std::set<std::string>& known,
                                                               const std::set<std::string>& admitted,
                                                               int limit)
    {
        if (limit <= 0)
        {
            return known;
        }

        const auto ceiling = static_cast<std::size_t>(limit);

        // Incumbents that still exist. Anything in `admitted` but no longer in
        // `known` has been removed by the runtime, and its slot is free.
        std::set<std::string> result;
        std::set_intersection(admitted.begin(),
                              admitted.end(),
                              known.begin(),
                              known.end(),
                              std::inserter(result, result.end()));

        // The operator lowered the cap below what is already admitted. Drop the
        // highest ids rather than an arbitrary subset, so the survivors are the
        // same ones a cold start at this limit would have picked.
        if (result.size() > ceiling)
        {
            auto first = result.begin();
            std::advance(first, static_cast<std::ptrdiff_t>(ceiling));
            result.erase(first, result.end());
        }

        // Fill what is left in ascending id order. `known` is ordered, so this
        // takes the lowest ids not already held.
        for (const auto& containerId : known)
        {
            if (result.size() >= ceiling)
            {
                break;
            }

            result.insert(containerId);
        }

        return result;
    }

} // namespace wazuh::container_instances
