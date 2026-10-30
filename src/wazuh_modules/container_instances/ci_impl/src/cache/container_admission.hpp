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
     * @param known    Every container that currently exists, whether or not the
     *                  resolver has keyed it. Not filtered, not truncated -- see
     *                  the note above on why.
     * @param visible  The subset the connector can publish. A container the
     *                 resolver has not keyed is absent from this and present in
     *                 @p known.
     * @param admitted The previous decision, so incumbents can keep their slots.
     * @param limit    Containers that may report; <= 0 means unlimited.
     * @return The new admitted set, a subset of @p known.
     *
     * Three properties, and all of them are load-bearing:
     *
     * STICKY. An admitted container keeps its slot until it genuinely leaves
     * `known`. A new container never evicts an incumbent, so a steady node never
     * churns. The alternative -- ranking the whole set every pass -- looks
     * simpler and is not: container ids are random hex, so a new container sorts
     * below the incumbent Nth roughly N/M of the time, and each time it does the
     * manager is told to delete one container's rows and create another's. At
     * N=10, M=50 that is one container creation in five.
     *
     * DETERMINISTIC, FOR THE INPUTS IT IS GIVEN. Free slots fill by lowest id,
     * so the same four arguments always yield the same answer, on any agent and
     * in any order of arrival. Nothing on this path can be ranked by age: there
     * is no container creation time anywhere in the record -- `startedAt` is the
     * start of the CURRENT run, it resets on restart, and it is absent entirely
     * for a stopped Kubernetes container. Lowest-id is arbitrary, but it is
     * arbitrary in a way that is reproducible, which walk order is not.
     *
     * It is NOT history-independent, and the difference matters. `admitted` is
     * an input, so a set carried forward can differ from the one a cold start at
     * the same limit would pick -- STICKY is exactly that, deliberately. What
     * makes the FIRST verdict after a restart reproducible is not this function
     * but its caller: MetadataStore withholds the verdict until every source has
     * enumerated and the resolver has keyed what it can, so the cold start ranks
     * the whole node rather than whoever happened to be keyed first.
     *
     * VISIBLE FIRST, THEN ANYTHING THAT EXISTS. Incumbents are held from `known`;
     * free slots are offered to `visible` before the rest of `known`. The two
     * sets answer two different questions and neither one answers both:
     *
     *   rank `visible` alone   a container that restarts has no key for a moment,
     *                          leaves the ranking, and hands its slot to the next
     *                          id -- so every restart withdraws a container's
     *                          documents from the manager and creates another's.
     *                          Worse, nothing then refuses the restarting one, so
     *                          every consumer reports it and the node runs over
     *                          the cap for the length of the restart.
     *   fill from `visible`    a container with no key yet is refused even when
     *   alone                  slots are free, which is the ordinary state for
     *                          the seconds after a restart. Its documents are
     *                          retracted and re-created for nothing, and with the
     *                          cap full the winner depends on resolver timing.
     *   rank `known` alone     a container the resolver can never key takes a slot
     *                          a publishable one wanted. It publishes nothing, so
     *                          the node reports one container fewer than the limit
     *                          allows, for as long as that container runs.
     *
     * Offering `visible` first and `known` second answers all three: a restart
     * keeps what it had, no slot is left empty while any container could hold it,
     * and a container that cannot publish takes only what nobody else wants.
     *
     * The same order decides a SHRINK. When the operator lowers the cap below
     * what is already admitted, the incumbents that can publish keep their slots
     * and the ones that cannot lose theirs first. Dropping the highest ids
     * instead -- the obvious reading of "keep the lowest" -- let a cap of one,
     * on a node whose lowest-id container happened to be unkeyed, keep exactly
     * the container that reports nothing and refuse both that could.
     *
     * What the ordering does NOT do is outrank an incumbent. It decides between
     * NEWCOMERS contesting a free slot; an unkeyed container already holding one
     * keeps it against a visible newcomer, both before and after this rule. Two
     * ways to reach that state, and neither is separable from a restart without a
     * per-container clock this layer does not have:
     *
     *   admitted while visible, then permanently unkeyed
     *   admitted into a leftover slot, never keyed at all
     *
     * Both are indistinguishable from a container that is merely restarting, and
     * treating them as departures is the first failure above. The cost is one
     * slot, and the "withheld by containers.synced_limit" line in the store will
     * attribute it to the limit -- which is true, in that raising the limit does
     * release the containers it is holding back, but it does not name the slot
     * that is going unused. Nothing on this path can name it either.
     */
    [[nodiscard]] inline std::set<std::string> admitContainers(const std::set<std::string>& known,
                                                               const std::set<std::string>& visible,
                                                               const std::set<std::string>& admitted,
                                                               int limit)
    {
        if (limit <= 0)
        {
            return known;
        }

        const auto ceiling = static_cast<std::size_t>(limit);

        // Incumbents that still EXIST -- keyed or not. Anything in `admitted`
        // but no longer in `known` has been removed by the runtime, and its slot
        // is free. A container that is merely unkeyed has not been removed.
        std::set<std::string> incumbents;
        std::set_intersection(admitted.begin(),
                              admitted.end(),
                              known.begin(),
                              known.end(),
                              std::inserter(incumbents, incumbents.end()));

        std::set<std::string> publishingIncumbents;
        std::set_intersection(incumbents.begin(),
                              incumbents.end(),
                              visible.begin(),
                              visible.end(),
                              std::inserter(publishingIncumbents, publishingIncumbents.end()));

        std::set<std::string> result;

        const auto take = [&](const std::set<std::string>& candidates)
        {
            for (const auto& containerId : candidates)
            {
                if (result.size() >= ceiling)
                {
                    return;
                }

                result.insert(containerId);
            }
        };

        // One priority order, applied once. Each set is ordered, so each pass
        // takes the lowest ids it has left, and a container already held is
        // re-inserted into a set that has it -- a no-op that costs a lookup.
        take(publishingIncumbents); // holding a slot and using it
        take(incumbents);           // holding a slot; a restart looks like this
        take(visible);              // new, and able to publish
        take(known);                // new, and not keyed yet

        return result;
    }

} // namespace wazuh::container_instances
