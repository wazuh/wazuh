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
     * @param publishedBefore  Containers that have been in @p visible at least
     *                     once since the caller first saw them. An incumbent in
     *                     this set that is absent from @p visible now is
     *                     restart-shaped; one that is not has never published
     *                     anything and is holding a slot it took for free.
     *                     Empty -- the default -- means "no incumbent has ever
     *                     published", which demotes every withheld incumbent.
     * @param writtenOff   Containers that have been running and unkeyed for
     *                     long enough, and across enough snapshots, that the
     *                     caller has stopped expecting a key. They are ranked
     *                     last rather than banned; see the WRITE-OFF paragraph.
     * @return The new admitted set, a subset of @p known.
     *
     * Three properties, and all of them are load-bearing:
     *
     * STICKY, FOR A CONTAINER THAT HAS PUBLISHED. An admitted container keeps
     * its slot until it genuinely leaves `known`. A new container never evicts
     * an incumbent, so a steady node never churns. The alternative -- ranking the whole set every pass -- looks
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
     * PROVENANCE DECIDES WHICH INCUMBENTS ARE PROTECTED. Two different things
     * used to look alike here, because both are "admitted and currently not in
     * `visible`":
     *
     *   admitted while visible, then unkeyed   a restart, or a re-resolve. It
     *                                          has documents on the manager
     *                                          already, and taking its slot
     *                                          withdraws them and creates
     *                                          another container's.
     *   admitted into a leftover slot,         it has never published anything.
     *   never keyed at all                     Its slot was free when it took
     *                                          it; it is not free now.
     *
     * @p publishedBefore separates them, and only the first is protected. The
     * second is ranked BELOW a visible newcomer, so resolving the container
     * that wants the slot is enough to get it -- which it was not before:
     * incumbency held, and only removal, a cap increase or a shrink corrected
     * it.
     *
     * WRITE-OFF. A protected incumbent is protected for a bounded time, not for
     * ever. A container the resolver can never key again would otherwise hold
     * its slot for the life of the process, publishing nothing; the caller
     * decides when to stop waiting and names it in @p writtenOff. A written-off
     * container is not refused -- it is simply last in line, so it still fills
     * a slot nothing else wants, and it is restored to its normal rank the
     * moment a key arrives. The write-off therefore only bites when the cap
     * actually binds.
     *
     * The judgement is the caller's because it needs a clock and a count of
     * snapshots, and this function has neither -- deliberately, so it stays
     * testable without either.
     */
    [[nodiscard]] inline std::set<std::string> admitContainers(const std::set<std::string>& known,
                                                               const std::set<std::string>& visible,
                                                               const std::set<std::string>& admitted,
                                                               int limit,
                                                               const std::set<std::string>& publishedBefore = {},
                                                               const std::set<std::string>& writtenOff = {})
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

        // Incumbents still worth protecting: not written off. Held apart from
        // `incumbents` so the written-off ones can still be offered a slot
        // nothing else wants, in the last pass.
        std::set<std::string> livingIncumbents;
        std::set_difference(incumbents.begin(),
                            incumbents.end(),
                            writtenOff.begin(),
                            writtenOff.end(),
                            std::inserter(livingIncumbents, livingIncumbents.end()));

        // ...and of those, the ones that have published at least once. This is
        // the set that outranks a visible newcomer; the rest do not.
        std::set<std::string> provenIncumbents;
        std::set_intersection(livingIncumbents.begin(),
                              livingIncumbents.end(),
                              publishedBefore.begin(),
                              publishedBefore.end(),
                              std::inserter(provenIncumbents, provenIncumbents.end()));

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
        take(provenIncumbents);     // has published before; a restart looks like this
        take(visible);              // keyed now, and wants a slot
        take(livingIncumbents);     // holding a slot it took for free
        take(known);                // anything else that exists, written off included

        return result;
    }

} // namespace wazuh::container_instances
