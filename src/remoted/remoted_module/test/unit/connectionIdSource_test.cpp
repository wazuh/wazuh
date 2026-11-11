/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "http_server/connectionIdSource.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <thread>
#include <vector>

using remoted::http::ConnectionIdSource;

// RESTinio numbers its connections from 1; the replacement keeps that.
TEST(ConnectionIdSourceTest, StartsAtOneLikeRestinio)
{
    ConnectionIdSource ids;
    EXPECT_EQ(ids.next(), 1U);
    EXPECT_EQ(ids.next(), 2U);
}

// Connections are created on several I/O threads at once: every one of them must still get its own id.
TEST(ConnectionIdSourceTest, IdsAreDistinctAcrossThreads)
{
    constexpr std::size_t kThreads = 8;
    constexpr std::size_t kPerThread = 50000;

    ConnectionIdSource ids;
    std::vector<std::vector<std::uint64_t>> taken(kThreads);
    std::vector<std::thread> threads;
    for (std::size_t t = 0; t < kThreads; ++t)
    {
        threads.emplace_back(
            [&ids, &mine = taken[t]]
            {
                mine.reserve(kPerThread);
                for (std::size_t i = 0; i < kPerThread; ++i)
                {
                    mine.push_back(ids.next());
                }
            });
    }
    for (auto& thread : threads)
    {
        thread.join();
    }

    std::vector<std::uint64_t> all;
    all.reserve(kThreads * kPerThread);
    for (const auto& mine : taken)
    {
        all.insert(all.end(), mine.begin(), mine.end());
    }
    std::sort(all.begin(), all.end());

    EXPECT_EQ(std::adjacent_find(all.begin(), all.end()), all.end()) << "an id was handed out twice";
    EXPECT_EQ(all.front(), 1U);
    EXPECT_EQ(all.back(), kThreads * kPerThread);
}
