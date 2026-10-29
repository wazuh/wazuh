/*
 * Wazuh container_baseline — the quiescence wait before a baseline (#37532).
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * A baseline run waits for the node's containers to stop moving before it acts
 * on who is there, because every consumer DELETES the rows of a container the
 * listing omits. What that wait gets wrong is expensive in one direction only:
 * calling a node settled too early, or handing back a list and a description of
 * a different list, both end in deleted rows for a container that is simply
 * coming back.
 *
 * The loop used to live inside a static function that opened a real socket, so
 * none of this was reachable. It is a free function over one value for that
 * reason.
 */

#include "container_baseline_scanner.hpp"

#include <gtest/gtest.h>

#include <optional>
#include <set>
#include <string>
#include <vector>

using wazuh::container_baseline::PolledListing;
using wazuh::container_baseline::SettleContainerListing;

namespace
{

    /// Stands in for the vector of ContainerRefs. What matters is only that it
    /// travels with the flags, so a name per poll is enough to tell them apart.
    using Payload = std::string;
    using Listing = PolledListing<Payload>;

    Listing
    Answer(const char* tag, std::set<std::string> ids, std::set<std::string> unkeyed = {}, bool unkeyedKnown = true)
    {
        Listing listing;
        listing.payload = tag;
        listing.ids = std::move(ids);
        listing.unkeyed = std::move(unkeyed);
        listing.unkeyedKnown = unkeyedKnown;
        listing.complete = listing.unkeyed.empty();
        return listing;
    }

    /// Hands out a scripted sequence of answers, one per poll.
    struct Script
    {
        std::vector<std::optional<Listing>> answers;
        std::size_t next {0};

        std::function<std::optional<Listing>()> fn()
        {
            return [this]() -> std::optional<Listing>
            {
                if (next >= answers.size())
                {
                    return std::nullopt;
                }
                return answers[next++];
            };
        }
    };

} // namespace

// A container restarting leaves the keyed list the moment its record is
// replaced and reappears among the unkeyed ids. Both consumers keep the rows of
// everything in EITHER set, so as far as anything downstream is concerned the
// node has not changed -- and the wait exists to protect those consumers.
//
// Comparing the keyed list alone disagreed with itself here: it saw the
// container leave, polled again, saw it come back, and burned the whole budget
// deciding that a node with one restarting container never settles.
TEST(ContainerListingQuiescence, AContainerCrossingIntoTheUnkeyedSetIsNotTheNodeChanging)
{
    auto listing = Answer("first", {"a", "flap"});

    Script script {{Answer("second", {"a"}, {"flap"})}};

    const auto settled = SettleContainerListing<Payload>(listing, 4, script.fn());

    EXPECT_TRUE(settled) << "the same containers exist; only one of them is momentarily unkeyable";
    EXPECT_EQ(listing.settledIds(), (std::set<std::string> {"a", "flap"}));
    EXPECT_EQ(listing.ids, (std::set<std::string> {"a"}));
    EXPECT_EQ(listing.unkeyed, (std::set<std::string> {"flap"}));
}

// THE finding. Whatever answer the wait ends on, the list and the facts
// describing it come from that one poll.
TEST(ContainerListingQuiescence, TheAdoptedListAndItsCoverageComeFromTheSamePoll)
{
    // Starts complete with nothing unkeyed, which is the state that used to
    // survive the whole wait no matter what the later polls said.
    auto listing = Answer("first", {"a", "flap"});
    ASSERT_TRUE(listing.complete);
    ASSERT_TRUE(listing.unkeyed.empty());

    Script script {{Answer("second", {"a"}, {"flap"})}};

    SettleContainerListing<Payload>(listing, 4, script.fn());

    EXPECT_EQ(listing.payload, "second");
    EXPECT_FALSE(listing.complete) << "the adopted answer is not complete, and must say so";
    EXPECT_EQ(listing.unkeyed, (std::set<std::string> {"flap"}))
        << "a list from the adopted poll with the unkeyed ids of the first leaves the restarting "
           "container in neither set, and the caller deletes every row it holds for it";
}

// A container genuinely appearing IS the node changing, and the wait must keep
// going until it stops.
TEST(ContainerListingQuiescence, AContainerActuallyAppearingKeepsTheWaitGoing)
{
    auto listing = Answer("first", {"a"});

    Script script {{Answer("second", {"a", "b"}), Answer("third", {"a", "b"})}};

    EXPECT_TRUE(SettleContainerListing<Payload>(listing, 4, script.fn()));
    EXPECT_EQ(listing.payload, "third") << "the first two disagree; the last two settle it";
    EXPECT_EQ(listing.settledIds(), (std::set<std::string> {"a", "b"}));
}

// Settling must not hand back the second-to-last answer. It used to: the list
// was replaced only on the path where the two polls DISAGREED.
TEST(ContainerListingQuiescence, TheSettledAnswerIsTheOneThatSettledIt)
{
    auto listing = Answer("first", {"a"});
    Script script {{Answer("second", {"a"})}};

    EXPECT_TRUE(SettleContainerListing<Payload>(listing, 4, script.fn()));
    EXPECT_EQ(listing.payload, "second");
}

// An unreachable connector is not an empty node, and must not overwrite the
// answer we already have.
TEST(ContainerListingQuiescence, AFailedPollLeavesTheLastRealAnswerAlone)
{
    auto listing = Answer("first", {"a", "b"});
    Script script {{std::nullopt}};

    EXPECT_FALSE(SettleContainerListing<Payload>(listing, 4, script.fn()));
    EXPECT_EQ(listing.payload, "first");
    EXPECT_EQ(listing.ids, (std::set<std::string> {"a", "b"}));
}

// Containers that never stop moving must not block the run for ever. The caller
// proceeds with the last answer and re-checks next time.
TEST(ContainerListingQuiescence, AChurningNodeGivesUpWithTheLatestAnswer)
{
    auto listing = Answer("first", {"a"});
    Script script {{Answer("second", {"a", "b"}), Answer("third", {"a", "b", "c"})}};

    EXPECT_FALSE(SettleContainerListing<Payload>(listing, 2, script.fn()));
    EXPECT_EQ(listing.payload, "third") << "give up with the freshest answer, not the oldest";
}
