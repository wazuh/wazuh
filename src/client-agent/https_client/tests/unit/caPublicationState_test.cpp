/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 16, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "caPublicationState.hpp"

#include <gtest/gtest.h>

// --- Rule 3, the whole table -------------------------------------------------------------

TEST(CaPublicationDecision, AnAbsentFieldIsAnOlderManagerAndMeansNothing)
{
    EXPECT_FALSE(caPublicationShouldFetch(1789000010, std::nullopt));
    EXPECT_FALSE(caPublicationShouldFetch(CA_PUBLICATION_UNKNOWN, std::nullopt));
}

TEST(CaPublicationDecision, ZeroIsABundleNobodyPublishedAndIsNeverAdopted)
{
    EXPECT_FALSE(caPublicationShouldFetch(1789000010, 0));

    // Even with nothing recorded locally: an unpublished bundle is not something to anchor on.
    EXPECT_FALSE(caPublicationShouldFetch(CA_PUBLICATION_UNKNOWN, 0));
}

TEST(CaPublicationDecision, AnUnknownLocalPublicationReAnchors)
{
    EXPECT_TRUE(caPublicationShouldFetch(CA_PUBLICATION_UNKNOWN, 1789000010));
}

TEST(CaPublicationDecision, ALowerPublicationIsALaggingNodeAndIsIgnored)
{
    EXPECT_FALSE(caPublicationShouldFetch(1789000012, 1789000010));
}

TEST(CaPublicationDecision, AnEqualPublicationIsAlreadyHeld)
{
    EXPECT_FALSE(caPublicationShouldFetch(1789000012, 1789000012));
}

TEST(CaPublicationDecision, AHigherPublicationIsFetched)
{
    EXPECT_TRUE(caPublicationShouldFetch(1789000012, 1789000013));
}

// --- The state that applies it ----------------------------------------------------------

TEST(CaPublicationState, ArmsOnceHoweverManyNotifiesRaiseTheTarget)
{
    CaPublicationState state {1789000010};

    // The first observation that warrants a fetch arms the wait...
    EXPECT_TRUE(state.observe(1789000011));
    EXPECT_EQ(state.pending(), 1789000011);

    // ...and later ones raise the target without arming a second wait.
    EXPECT_FALSE(state.observe(1789000012));
    EXPECT_EQ(state.pending(), 1789000012);
}

/* The contract's own sequence: 11, 10, 11, 12 must fetch once, for 12, and must never regress to
 * the content of 10. */
TEST(CaPublicationState, TheContractSequenceFetchesOnceForTheHighest)
{
    CaPublicationState state {1789000010};
    int arms = 0;

    for (const std::int64_t advertised :
            {
                1789000011, 1789000010, 1789000011, 1789000012
            })
    {
        if (state.observe(advertised))
        {
            ++arms;
        }
    }

    EXPECT_EQ(arms, 1);
    EXPECT_EQ(state.pending(), 1789000012);
}

TEST(CaPublicationState, ALowerAdvertisementNeverLowersAPendingTarget)
{
    CaPublicationState state {CA_PUBLICATION_UNKNOWN};

    EXPECT_TRUE(state.observe(1789000012));
    EXPECT_FALSE(state.observe(1789000011));
    EXPECT_EQ(state.pending(), 1789000012);
}

TEST(CaPublicationState, CommittingClearsATargetItSatisfies)
{
    CaPublicationState state {1789000010};

    state.observe(1789000012);
    state.setLocal(1789000012);

    EXPECT_EQ(state.local(), 1789000012);
    EXPECT_EQ(state.pending(), 0);
}

/* A commit that lands behind the target -- the manager published again while the fetch was in
 * flight -- leaves the higher one armed, so the agent goes back for it. */
TEST(CaPublicationState, CommittingBehindTheTargetLeavesItArmed)
{
    CaPublicationState state {1789000010};

    state.observe(1789000011);
    state.observe(1789000013);
    state.setLocal(1789000011);

    EXPECT_EQ(state.local(), 1789000011);
    EXPECT_EQ(state.pending(), 1789000013);
}

/* A discarded response (rule 5.3) must not lose the target: the trust store is untouched, so the
 * agent still needs to go back for the publication it was told about. */
TEST(CaPublicationState, ADiscardedResponseKeepsTheTargetArmed)
{
    CaPublicationState state {1789000010};

    EXPECT_TRUE(state.observe(1789000012));
    // ...fetch runs, response is discarded, nothing is committed.
    EXPECT_EQ(state.pending(), 1789000012);

    // And the next notify does not arm a second wait for what is already pending.
    EXPECT_FALSE(state.observe(1789000012));
}

TEST(CaPublicationState, ClearingAbandonsTheTarget)
{
    CaPublicationState state {1789000010};

    state.observe(1789000012);
    state.clearPending();

    EXPECT_EQ(state.pending(), 0);
    EXPECT_EQ(state.local(), 1789000010);

    // Armed afresh by the next advertisement, since nothing was installed.
    EXPECT_TRUE(state.observe(1789000012));
}
