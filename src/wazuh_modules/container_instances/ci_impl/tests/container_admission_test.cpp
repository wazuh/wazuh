/*
 * Wazuh container_instances — container synchronization admission.
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
    EXPECT_EQ(admitContainers(known, known, NONE, 0), known);
    EXPECT_EQ(admitContainers(known, known, NONE, -1), known);
}

TEST(ContainerAdmissionTest, ColdStartTakesTheLowestIds)
{
    const auto known = ids({"e", "c", "a", "d", "b"});

    EXPECT_EQ(admitContainers(known, known, NONE, 3), ids({"a", "b", "c"}));
}

TEST(ContainerAdmissionTest, LimitAboveTheContainerCountAdmitsAll)
{
    const auto known = ids({"a", "b"});

    EXPECT_EQ(admitContainers(known, known, NONE, 10), known);
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

    EXPECT_EQ(admitContainers(known, known, admitted, 2), admitted);
}

TEST(ContainerAdmissionTest, AFreedSlotGoesToTheLowestWaitingId)
{
    const auto admitted = ids({"b", "c"});
    // "c" is gone; "a" and "d" have been waiting.
    const auto known = ids({"a", "b", "d"});

    EXPECT_EQ(admitContainers(known, known, admitted, 2), ids({"a", "b"}));
}

TEST(ContainerAdmissionTest, ADepartedIncumbentIsDropped)
{
    const auto admitted = ids({"a", "b"});
    const auto known = ids({"a"});

    // The result is always a subset of what exists, so a stale id can never
    // keep a slot a live container could use.
    EXPECT_EQ(admitContainers(known, known, admitted, 5), ids({"a"}));
}

TEST(ContainerAdmissionTest, LoweringTheCapKeepsTheLowestIncumbents)
{
    const auto admitted = ids({"a", "b", "c", "d"});
    const auto known = ids({"a", "b", "c", "d"});

    // Trimmed to the same survivors a cold start at this limit would pick, so
    // the cap does not depend on how it was reached.
    EXPECT_EQ(admitContainers(known, known, admitted, 2), ids({"a", "b"}));
    EXPECT_EQ(admitContainers(known, known, admitted, 2), admitContainers(known, known, NONE, 2));
}

TEST(ContainerAdmissionTest, RaisingTheCapFillsFromTheWaitingIds)
{
    const auto admitted = ids({"b"});
    const auto known = ids({"a", "b", "c", "d"});

    EXPECT_EQ(admitContainers(known, known, admitted, 3), ids({"a", "b", "c"}));
}

TEST(ContainerAdmissionTest, TheDecisionIsReproducible)
{
    const auto known = ids({"f", "a", "e", "b", "d", "c"});

    // Same inputs, same answer — on this agent, on another, and after a restart.
    EXPECT_EQ(admitContainers(known, known, NONE, 3), admitContainers(known, known, NONE, 3));
    EXPECT_EQ(admitContainers(known, known, NONE, 3), ids({"a", "b", "c"}));
}

TEST(ContainerAdmissionTest, SteadyStateDoesNotChurn)
{
    const auto known = ids({"a", "b", "c", "d"});

    // Feeding the decision back in must be a fixed point, or every pass would
    // re-decide and every re-decision would move rows.
    auto admitted = admitContainers(known, known, NONE, 2);

    for (int pass = 0; pass < 5; ++pass)
    {
        const auto next = admitContainers(known, known, admitted, 2);
        EXPECT_EQ(next, admitted);
        admitted = next;
    }
}

TEST(ContainerAdmissionTest, AnEmptyNodeAdmitsNothing)
{
    EXPECT_TRUE(admitContainers(NONE, NONE, NONE, 5).empty());
    EXPECT_TRUE(admitContainers(NONE, NONE, ids({"a"}), 5).empty());
}

// The two sets answer two different questions, and the rule reads each for the
// half it decides. INCUMBENCY over what exists; NEW SLOTS from what can be
// published.
TEST(ContainerAdmissionTest, AnUnpublishableContainerNeverTakesAFreeSlot)
{
    // "a" exists but the resolver cannot key it, so it publishes nothing. It
    // sorts lowest, so a rule that filled from `known` would hand it the slot
    // and the node would report one container fewer than the limit allows --
    // for as long as that container runs.
    const auto known = ids({"a", "m", "n"});
    const auto visible = ids({"m", "n"});

    EXPECT_EQ(admitContainers(known, visible, NONE, 2), ids({"m", "n"}));
    EXPECT_EQ(admitContainers(known, visible, NONE, 1), ids({"m"}));
}

TEST(ContainerAdmissionTest, AnUnkeyedContainerTakesAFreeSlotNobodyElseWants)
{
    // Same three containers as the test above, and the cap no longer binds.
    // Refusing "a" here buys nothing: no publishable container wants the third
    // slot. What it costs is a retract-and-recreate cycle on every agent
    // restart, because the seconds before the resolver keys a container are the
    // ordinary state at startup, not an exception.
    const auto known = ids({"a", "m", "n"});
    const auto visible = ids({"m", "n"});

    EXPECT_EQ(admitContainers(known, visible, NONE, 3), known);

    // A slot free above what exists is still only three containers admitted.
    EXPECT_EQ(admitContainers(known, visible, NONE, 10), known);

    // The order holds where it matters: give the cap one slot fewer than there
    // are containers and the publishable ones still take them all, even though
    // "a" sorts below both.
    EXPECT_EQ(admitContainers(known, visible, NONE, 2), ids({"m", "n"}));
}

TEST(ContainerAdmissionTest, AnIncumbentKeepsItsSlotWhileItHasNoKey)
{
    // "b" was admitted and is now restarting: still known, not publishable for
    // the moment. Filling from `visible` must not be read as a departure --
    // "a" sorts below it and would take the slot, which withdraws every
    // document "b" holds and creates "a"'s in their place, once per restart.
    const auto known = ids({"a", "b"});
    const auto restarting = ids({"a"});

    EXPECT_EQ(admitContainers(known, restarting, ids({"b"}), 1), ids({"b"}));

    // ...and when its key comes back it is still the incumbent, so nothing
    // moved on the manager at all.
    EXPECT_EQ(admitContainers(known, known, ids({"b"}), 1), ids({"b"}));
}

// The deliberate limit of the rule, pinned so it cannot be tightened by
// accident. An incumbent that becomes unkeyable and NEVER comes back keeps its
// slot for as long as it exists, publishing nothing.
//
// That is the price of deciding incumbency by existence, and it is the right
// side of the trade: from here a container that will never be keyed again and
// one that is three seconds into a restart look identical, and treating either
// as a departure hands its slot away and withdraws every document it holds.
// Only the runtime removing it frees the slot -- see the test below.
TEST(ContainerAdmissionTest, AnIncumbentThatNeverRegainsAKeyKeepsItsSlot)
{
    const auto known = ids({"a", "b"});
    const auto visible = ids({"a"}); // "b" has no key, and will not get one

    EXPECT_EQ(admitContainers(known, visible, ids({"b"}), 1), ids({"b"}));

    // Still true however many times the rule runs: it is not a decision that
    // decays, and "a" never takes the slot while "b" exists.
    EXPECT_EQ(admitContainers(known, visible, admitContainers(known, visible, ids({"b"}), 1), 1), ids({"b"}));
}

TEST(ContainerAdmissionTest, AContainerThatLeavesFreesItsSlotEvenIfItWasNeverPublishable)
{
    // Gone from `known` is gone, whether or not it ever had a key. Otherwise a
    // node that churns unkeyable containers decays towards admitting nothing.
    EXPECT_EQ(admitContainers(ids({"a", "b"}), ids({"a", "b"}), ids({"z"}), 1), ids({"a"}));
}

TEST(ContainerAdmissionTest, NoLimitAdmitsEverythingThatExistsKeyedOrNot)
{
    // The shipped default. `visible` is not consulted: nothing is being ranked,
    // so nothing can be refused, and an unkeyed container reports as soon as it
    // can publish rather than waiting for a recompute.
    const auto known = ids({"a", "m", "n"});

    EXPECT_EQ(admitContainers(known, ids({"m"}), NONE, 0), known);
}
