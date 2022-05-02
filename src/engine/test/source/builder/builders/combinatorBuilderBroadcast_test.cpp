/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stdexcept>
#include <string>
#include <vector>

#include "combinatorBuilderBroadcast.hpp"
#include "registry.hpp"
#include "stageBuilderCheck.hpp"
#include "testUtils.hpp"

#include <gtest/gtest.h>

using namespace builder::internals::builders;

using base::Event;
using base::Lifter;
using base::Observable;

using FakeTrFn = std::function<void(std::string)>;

TEST(CombinatorBuilderBroadcastTest, combinedBroadcastEventsCount)
{
    // Register operation
    Registry::registerBuilder("combinator.broadcast",
                              combinatorBuilderBroadcast);

    std::vector<Lifter> lifters;

    auto liftersCount = 5;
    for (int i = 0; i < liftersCount; i++)
    {
        lifters.push_back([](Observable in) { return in; });
    }

    Lifter chain = builders::combinatorBuilderBroadcast(lifters);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = chain(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 4;
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(
            createSharedEvent(R"({})"));
    }

    ASSERT_EQ(expected.size(), liftersCount * eventsCount);
}

TEST(CombinatorBuilderBroadcastTest, combinedBroadcastSingleEmition)
{
    std::vector<Lifter> lifters;

    auto liftersCount = 5;
    for (int i = 0; i < liftersCount; i++)
    {
        lifters.push_back([](Observable in) { return in; });
    }

    // Filter outputs
    for (auto& lifter : lifters)
    {
        lifter = [lifter](Observable in)
        {
            return lifter(in).filter([](auto) { return false; });
        };
    }

    // Create dummy observable publisher (Single broadcast output)
    lifters.push_back([](Observable in) { return in; });
    Lifter chain = builders::combinatorBuilderBroadcast(lifters);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = chain(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 4;
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(
            createSharedEvent(R"({})"));
    }

    ASSERT_EQ(expected.size(), eventsCount);
}
