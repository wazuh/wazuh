/*
 * Wazuh indexer client
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

// The single time scale of the suites (plan 18, I113, testTimeScale.hpp): what INDEXER_CLIENT_TEST_TIME_SCALE accepts,
// and that a bad value aborts the run. A global environment checks the variable before the first case, so a bad value
// stops the whole binary at once (and --gtest_list_tests, which runs no environment, still works). It does not call
// timeScale() for a valid value: the cache stays empty for the death test's child.

#include "testTimeScale.hpp"

#include <gtest/gtest.h>

#include <cstdlib>

#include <dlfcn.h>

namespace
{
    using indexer_client::testing::parseTimeScale;
    using indexer_client::testing::TIME_SCALE_ENV;
    using indexer_client::testing::timeScale;

    class TimeScaleEnvironment final : public ::testing::Environment
    {
    public:
        void SetUp() override
        {
            if (!parseTimeScale(std::getenv(TIME_SCALE_ENV)))
            {
                timeScale(); // Prints the reason and aborts.
            }
        }
    };

    [[maybe_unused]] ::testing::Environment* const g_timeScaleEnvironment =
        ::testing::AddGlobalTestEnvironment(new TimeScaleEnvironment);
} // namespace

TEST(TestTimeScale, ParseDefaults)
{
    EXPECT_EQ(parseTimeScale(nullptr), 1);
    EXPECT_EQ(parseTimeScale(""), 1);
}

TEST(TestTimeScale, ParseValid)
{
    EXPECT_EQ(parseTimeScale("1"), 1);
    EXPECT_EQ(parseTimeScale("3"), 3);
    EXPECT_EQ(parseTimeScale("20"), 20);
}

TEST(TestTimeScale, ParseInvalid)
{
    for (const char* value : {"0", "abc", "21", "-1", "3x", " 3", "+3", "100"})
    {
        EXPECT_FALSE(parseTimeScale(value).has_value()) << "\"" << value << "\"";
    }
}

// The scale the run asked for is the one scaled() applies (the CI jobs set 2): a timeScale() that ignored the variable
// would only show as timing flakes under load (D57 reproduces only on a loaded host, plan 18 E6b).
TEST(TestTimeScale, EnvironmentReachesScaled)
{
    const auto requested = parseTimeScale(std::getenv(TIME_SCALE_ENV));
    ASSERT_TRUE(requested.has_value());
    EXPECT_EQ(timeScale(), *requested * indexer_client::testing::SANITIZER_TIME_SCALE);
    EXPECT_EQ(indexer_client::testing::scaled(std::chrono::milliseconds {100}),
              std::chrono::milliseconds {100 * *requested * indexer_client::testing::SANITIZER_TIME_SCALE});
}

// TSAN slows the suites about threefold: its builds multiply every bound by 3 on top of the variable. The TSAN runtime
// is detected here on its own (its entry point is in the process), not through the header's macro, so a wrong
// detection in testTimeScale.hpp fails too.
TEST(TestTimeScale, SanitizerFactor)
{
    const bool tsanRuntime = dlsym(RTLD_DEFAULT, "__tsan_init") != nullptr;
    EXPECT_EQ(indexer_client::testing::SANITIZER_TIME_SCALE, tsanRuntime ? 3 : 1);
}

// The variable is set inside the child (threadsafe style: a fresh process that runs only this case), before the
// first timeScale() call, which reads it once.
TEST(TestTimeScale, InvalidAborts)
{
    ::testing::FLAGS_gtest_death_test_style = "threadsafe";
    EXPECT_DEATH(
        {
            setenv(TIME_SCALE_ENV, "abc", 1);
            timeScale();
        },
        "INDEXER_CLIENT_TEST_TIME_SCALE");
}
