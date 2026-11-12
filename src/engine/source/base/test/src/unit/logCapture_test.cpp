// SPDX-License-Identifier: AGPL-3.0-or-later
#include <gtest/gtest.h>

#include <string>

#include <base/logCapture.hpp>
#include <base/logging.hpp>

// The helper is offered to every test that links base::test, so its own contract is checked here
// instead of only through whatever test happens to use it: a capture whose sink never got attached
// hands back no records, and an emptiness assertion built on it would pass for the wrong reason.

TEST(LogCapture, HoldsItsLevelAndRestoresTheOneItFound)
{
    logging::testInit(logging::Level::Warn);
    logging::setLevel(logging::Level::Err);

    {
        base::test::LogCapture capture {logging::Level::Debug};
        ASSERT_EQ(logging::getLevel(), logging::Level::Debug);
    }

    EXPECT_EQ(logging::getLevel(), logging::Level::Err);
}

TEST(LogCapture, CapturesFromItsLevelUpAndSelectsByLevel)
{
    base::test::LogCapture capture {logging::Level::Debug};

    LOG_TRACE("below the level of the capture");
    LOG_DEBUG("a debug line");
    LOG_WARNING("a warning line");

    const auto records = capture.records();
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[0].level, logging::Level::Debug);
    EXPECT_EQ(records[0].message, "a debug line");
    EXPECT_EQ(records[1].level, logging::Level::Warn);
    EXPECT_EQ(records[1].message, "a warning line");

    const auto warnings = capture.records(logging::Level::Warn);
    ASSERT_EQ(warnings.size(), 1u);
    EXPECT_EQ(warnings.front().message, "a warning line");
}

TEST(LogCapture, ClearDropsOnlyWhatWasCapturedSoFar)
{
    base::test::LogCapture capture {logging::Level::Debug};

    LOG_DEBUG("before the clear");
    ASSERT_EQ(capture.records().size(), 1u);

    capture.clear();
    EXPECT_TRUE(capture.records().empty());

    LOG_DEBUG("after the clear");
    const auto records = capture.records();
    ASSERT_EQ(records.size(), 1u);
    EXPECT_EQ(records.front().message, "after the clear");
}

TEST(LogCapture, NestedCapturesBothRecordAndRestoreInOrder)
{
    logging::testInit(logging::Level::Warn);
    logging::setLevel(logging::Level::Err);

    {
        base::test::LogCapture outer {logging::Level::Info};
        {
            base::test::LogCapture inner {logging::Level::Debug};
            LOG_DEBUG("seen by both captures");
            EXPECT_EQ(inner.records().size(), 1u);
            EXPECT_EQ(outer.records().size(), 1u);
        }

        // The inner capture restores the level the outer one had set, not the one before both.
        EXPECT_EQ(logging::getLevel(), logging::Level::Info);
    }

    EXPECT_EQ(logging::getLevel(), logging::Level::Err);
}

TEST(LogCapture, TakesItsSinkOffOnDestruction)
{
    base::test::LogCapture capture {logging::Level::Debug};
    const auto sinks = logging::getDefaultLogger()->sinks().size();

    {
        base::test::LogCapture nested {logging::Level::Debug};
        EXPECT_EQ(logging::getDefaultLogger()->sinks().size(), sinks + 1);
    }

    EXPECT_EQ(logging::getDefaultLogger()->sinks().size(), sinks);
}
