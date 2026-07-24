/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

// Direct tests of the production system seams (the rest of the suite injects
// fakes; these exercise the real implementations).

#include "sysSeams.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <cstdio>
#include <fstream>
#include <thread>
#include <vector>

TEST(SystemClockTest, WallAndSteadyAdvanceMonotonically)
{
    SystemClock clock;
    const auto wall1 = clock.wallSeconds();
    const auto steady1 = clock.steadyNow();
    EXPECT_GT(wall1, 0);
    EXPECT_GE(clock.wallSeconds(), wall1);
    EXPECT_GE(clock.steadyNow(), steady1);
}

TEST(Mt19937RandomTest, YieldsValuesInUnitInterval)
{
    Mt19937Random random;

    for (int index = 0; index < 1000; index++)
    {
        const double value = random.uniform01();
        EXPECT_GE(value, 0.0);
        EXPECT_LT(value, 1.0);
    }
}

TEST(Mt19937RandomTest, ProducesVariation)
{
    Mt19937Random random;
    const double first = random.uniform01();
    bool differs = false;

    for (int index = 0; index < 100 && !differs; index++)
    {
        differs = (random.uniform01() != first);
    }

    EXPECT_TRUE(differs); // Astronomically unlikely to be constant.
}

TEST(Mt19937RandomTest, ConcurrentCallsRemainInUnitInterval)
{
    Mt19937Random random;
    std::atomic<bool> valid {true};
    std::vector<std::thread> workers;

    for (int worker = 0; worker < 8; worker++)
    {
        workers.emplace_back(
            [&]
        {
            for (int sample = 0; sample < 10000; sample++)
            {
                const double value = random.uniform01();

                if (value < 0.0 || value >= 1.0)
                {
                    valid = false;
                }
            }
        });
    }

    for (auto& worker : workers)
    {
        worker.join();
    }

    EXPECT_TRUE(valid);
}

TEST(FsProbeTest, ReadableFileIsDetected)
{
    const std::string path = ::testing::TempDir() + "hc_fsprobe.tmp";
    {
        std::ofstream file {path, std::ios::binary};
        file << "x";
    }
    FsProbe probe;
    EXPECT_TRUE(probe.isReadableFile(path));
    std::remove(path.c_str());
}

TEST(FsProbeTest, MissingFileIsNotReadable)
{
    FsProbe probe;
    EXPECT_FALSE(probe.isReadableFile("/nonexistent/hc-fsprobe/missing.pem"));
}
