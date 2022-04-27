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

using types::Event;
using types::Lifter;
using types::Observable;

using FakeTrFn = std::function<void(std::string)>;

TEST(CombinatorBuilderBroadcastTest, combinedBroadcastEventsCount)
{
    // Register operation
    BuilderVariant c = combinatorBuilderBroadcast;
    Registry::registerBuilder("combinator.broadcast", c);

    std::vector<Lifter> lifters;

    auto liftersCount = 5;
    for (int i = 0; i < liftersCount; i++)
    {
        lifters.push_back([](Observable in) { return in; });
    }

    Lifter chain = std::get<types::CombinatorBuilder>(
        Registry::getBuilder("combinator.broadcast"))(lifters);

    auto eventsCount = 5;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(std::make_shared<json::Document>(R"({})"));
            }
            s.on_completed();
        });

    Observable output = chain(input);

    std::vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

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

    for (auto &lifter : lifters)
    {
        lifter = [lifter](Observable in)
        {
            // Filter outputs
            return lifter(in).filter([](auto) { return false; });
        };
    }

    // Create dummy observable publisher (Single broadcast output)
    lifters.push_back([](Observable in) { return in; });

    Lifter chain = std::get<types::CombinatorBuilder>(
        Registry::getBuilder("combinator.broadcast"))(lifters);

    auto eventsCount = 5;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(std::make_shared<json::Document>(R"({})"));
            }
            s.on_completed();
        });

    Observable output = chain(input);

    std::vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), eventsCount);
}
