/*
 * Wazuh container_instances — container synchronization admission (#37532).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * The rule decides which containers may report to the manager at all. Two
 * properties carry the whole design, and each has a named case below plus the
 * mutation that kills it:
 *
 *   STICKY        drop the intersection with the previous decision and a
 *                 lower-id newcomer evicts an incumbent — the delete/create
 *                 storm this rule exists to avoid.
 *   DETERMINISTIC fill from anything other than an ordered set and two agents
 *                 with the same containers disagree about which ones report.
 *
 * Nothing here touches a store, a socket or a clock: that is the point of
 * keeping the rule in a header of its own.
 */

#include "cache/container_admission.hpp"

#include <gtest/gtest.h>

#include <set>
#include <string>

using wazuh::container_instances::admitContainers;

namespace
{
    const std::set<std::string> NONE {};

    std::set<std::string> ids(std::initializer_list<std::string> values)
    {
        return std::set<std::string> {values};
    }
} // namespace

TEST(ContainerAdmissionTest, UnlimitedAdmitsEverything)
{
    const auto known = ids({"a", "b", "c"});

    // 0 is the shipped default: a cap nobody configured must change nothing.
    EXPECT_EQ(admitContainers(known, NONE, 0), known);
    EXPECT_EQ(admitContainers(known, NONE, -1), known);
}

TEST(ContainerAdmissionTest, ColdStartTakesTheLowestIds)
{
    const auto known = ids({"e", "c", "a", "d", "b"});

    EXPECT_EQ(admitContainers(known, NONE, 3), ids({"a", "b", "c"}));
}

TEST(ContainerAdmissionTest, LimitAboveTheContainerCountAdmitsAll)
{
    const auto known = ids({"a", "b"});

    EXPECT_EQ(admitContainers(known, NONE, 10), known);
}

/* THE case. A newcomer sorting below every incumbent must not displace one.
 *
 * Mutation that kills it: return the lowest `limit` of `known` and ignore
 * `admitted` entirely — "b" and "c" are then evicted for "a", and the manager
 * is told to delete two containers' rows for a change that happened on neither.
 */
TEST(ContainerAdmissionTest, AnIncumbentIsNotEvictedByALowerId)
{
    const auto admitted = ids({"b", "c"});
    const auto known = ids({"a", "b", "c"});

    EXPECT_EQ(admitContainers(known, admitted, 2), admitted);
}

TEST(ContainerAdmissionTest, AFreedSlotGoesToTheLowestWaitingId)
{
    const auto admitted = ids({"b", "c"});
    // "c" is gone; "a" and "d" have been waiting.
    const auto known = ids({"a", "b", "d"});

    EXPECT_EQ(admitContainers(known, admitted, 2), ids({"a", "b"}));
}

TEST(ContainerAdmissionTest, ADepartedIncumbentIsDropped)
{
    const auto admitted = ids({"a", "b"});
    const auto known = ids({"a"});

    // The result is always a subset of what exists, so a stale id can never
    // keep a slot a live container could use.
    EXPECT_EQ(admitContainers(known, admitted, 5), ids({"a"}));
}

TEST(ContainerAdmissionTest, LoweringTheCapKeepsTheLowestIncumbents)
{
    const auto admitted = ids({"a", "b", "c", "d"});
    const auto known = ids({"a", "b", "c", "d"});

    // Trimmed to the same survivors a cold start at this limit would pick, so
    // the cap does not depend on how it was reached.
    EXPECT_EQ(admitContainers(known, admitted, 2), ids({"a", "b"}));
    EXPECT_EQ(admitContainers(known, admitted, 2), admitContainers(known, NONE, 2));
}

TEST(ContainerAdmissionTest, RaisingTheCapFillsFromTheWaitingIds)
{
    const auto admitted = ids({"b"});
    const auto known = ids({"a", "b", "c", "d"});

    EXPECT_EQ(admitContainers(known, admitted, 3), ids({"a", "b", "c"}));
}

TEST(ContainerAdmissionTest, TheDecisionIsReproducible)
{
    const auto known = ids({"f", "a", "e", "b", "d", "c"});

    // Same inputs, same answer — on this agent, on another, and after a restart.
    EXPECT_EQ(admitContainers(known, NONE, 3), admitContainers(known, NONE, 3));
    EXPECT_EQ(admitContainers(known, NONE, 3), ids({"a", "b", "c"}));
}

TEST(ContainerAdmissionTest, SteadyStateDoesNotChurn)
{
    const auto known = ids({"a", "b", "c", "d"});

    // Feeding the decision back in must be a fixed point, or every pass would
    // re-decide and every re-decision would move rows.
    auto admitted = admitContainers(known, NONE, 2);

    for (int pass = 0; pass < 5; ++pass)
    {
        const auto next = admitContainers(known, admitted, 2);
        EXPECT_EQ(next, admitted);
        admitted = next;
    }
}

TEST(ContainerAdmissionTest, AnEmptyNodeAdmitsNothing)
{
    EXPECT_TRUE(admitContainers(NONE, NONE, 5).empty());
    EXPECT_TRUE(admitContainers(NONE, ids({"a"}), 5).empty());
}
