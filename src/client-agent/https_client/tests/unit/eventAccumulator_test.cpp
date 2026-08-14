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

#include "eventAccumulator.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <string>

namespace
{
    bool append(EventAccumulator& accumulator, const std::string& frame)
    {
        return accumulator.append(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
    }
} // namespace

TEST(EncodeStatelessEventLineTest, WrapsFrameAsEeLine)
{
    const std::string frame = "1:/var/log/syslog:hello";
    const auto line =
        encodeStatelessEventLine(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
    EXPECT_EQ("E 1:/var/log/syslog:hello\n", line);
}

TEST(EncodeStatelessEventLineTest, EscapesEmbeddedNewlinesWithLeadingSpace)
{
    const std::string frame = "line1\nline2\nline3";
    const auto line =
        encodeStatelessEventLine(reinterpret_cast<const uint8_t*>(frame.data()), frame.size());
    EXPECT_EQ("E line1\n line2\n line3\n", line);
}

TEST(EventAccumulatorTest, AppendAndSnapshotProducesEeLines)
{
    EventAccumulator accumulator {1024, 4, 10000};
    EXPECT_TRUE(append(accumulator, "a"));
    EXPECT_TRUE(append(accumulator, "b"));
    const auto snapshot = accumulator.snapshot(SIZE_MAX);
    EXPECT_EQ("E a\nE b\n", snapshot.body);
    EXPECT_EQ(2u, snapshot.eventCount);
    EXPECT_EQ(snapshot.body.size(), snapshot.byteLength);
}

TEST(EventAccumulatorTest, FlushDueOnSizeThreshold)
{
    EventAccumulator accumulator {8, 4, 10000}; // batch size 8 bytes.
    EXPECT_FALSE(accumulator.flushDue(0, 8));
    append(accumulator, "abc"); // "E abc\n" = 6 bytes < 8.
    EXPECT_FALSE(accumulator.flushDue(0, 8));
    append(accumulator, "d"); // + "E d\n" = 10 bytes >= 8.
    EXPECT_TRUE(accumulator.flushDue(0, 8));
}

TEST(EventAccumulatorTest, FlushDueOnAgeThreshold)
{
    EventAccumulator accumulator {1024, 4, 5000};
    append(accumulator, "a");
    EXPECT_FALSE(accumulator.flushDue(4999, 1024));
    EXPECT_TRUE(accumulator.flushDue(5000, 1024));
}

TEST(EventAccumulatorTest, EmptyBufferIsNeverFlushDue)
{
    EventAccumulator accumulator {1024, 4, 1};
    EXPECT_FALSE(accumulator.flushDue(1000000, 1024));
    EXPECT_TRUE(accumulator.empty());
}

TEST(EventAccumulatorTest, DropNewestWhenCapExceeded)
{
    // batch 8, multiplier 1 -> cap 8 bytes. "E aaaa\n" = 7 bytes fits; the
    // next 7-byte line would exceed 8 and is dropped.
    EventAccumulator accumulator {8, 1, 10000};
    EXPECT_TRUE(append(accumulator, "aaaa"));
    EXPECT_FALSE(append(accumulator, "bbbb"));
    const auto snapshot = accumulator.snapshot(SIZE_MAX);
    EXPECT_EQ("E aaaa\n", snapshot.body);
    EXPECT_EQ(1u, snapshot.eventCount);
}

TEST(EventAccumulatorTest, ConsumeIsTailPreserving)
{
    EventAccumulator accumulator {1024, 4, 10000};
    append(accumulator, "first");
    const auto snapshot = accumulator.snapshot(SIZE_MAX);
    // An event arrives AFTER the snapshot but BEFORE consume().
    append(accumulator, "second");
    accumulator.consume(snapshot);
    const auto remaining = accumulator.snapshot(SIZE_MAX);
    EXPECT_EQ("E second\n", remaining.body);
    EXPECT_EQ(1u, remaining.eventCount);
}

TEST(EventAccumulatorTest, OccupancyTracksBytesBothDirections)
{
    // cap = 100 bytes. Each "E " + 8 chars + "\n" = 11 bytes, so occupancy is
    // 11% per event. BufferLevelLadder turns this into the four-level ladder.
    EventAccumulator accumulator {25, 4, 100000};
    const std::string frame(8, 'x');

    EXPECT_EQ(0u, accumulator.occupancyPercent());

    for (int index = 0; index < 5; index++)
    {
        append(accumulator, frame);
    }

    EXPECT_EQ(55u, accumulator.occupancyPercent());

    for (int index = 0; index < 4; index++)
    {
        append(accumulator, frame);
    }

    EXPECT_EQ(99u, accumulator.occupancyPercent());

    // Draining most of the buffer walks occupancy back down.
    EventAccumulator::Snapshot partial;
    partial.byteLength = 88;
    partial.eventCount = 8;
    accumulator.consume(partial);
    EXPECT_EQ(11u, accumulator.occupancyPercent());
}

TEST(EventAccumulatorTest, ConsumeNeverUnderflowsCounts)
{
    EventAccumulator accumulator {1024, 4, 10000};
    append(accumulator, "one");
    EventAccumulator::Snapshot oversized;
    oversized.byteLength = 100000; // More than present.
    oversized.eventCount = 100;
    accumulator.consume(oversized);
    EXPECT_TRUE(accumulator.empty());
    EXPECT_EQ(0u, accumulator.snapshot(SIZE_MAX).eventCount);
}

TEST(EventAccumulatorTest, BoundedSnapshotCutsAtEventBoundary)
{
    // Each "E xx\n" line is 5 bytes. A 12-byte budget fits two whole lines
    // (10 bytes); the third would push to 15 and is left behind.
    EventAccumulator accumulator {1024, 4, 10000};
    append(accumulator, "aa");
    append(accumulator, "bb");
    append(accumulator, "cc");
    const auto snapshot = accumulator.snapshot(12);
    EXPECT_EQ("E aa\nE bb\n", snapshot.body);
    EXPECT_EQ(2u, snapshot.eventCount);
    EXPECT_EQ(10u, snapshot.byteLength);
}

TEST(EventAccumulatorTest, BoundedSnapshotAlwaysReturnsAtLeastOneEvent)
{
    // A budget smaller than the first line still returns that one event, so a
    // lone oversized event can be sent (or dropped) rather than wedging.
    EventAccumulator accumulator {1024, 4, 10000};
    append(accumulator, "a-long-single-event-frame");
    const auto snapshot = accumulator.snapshot(4); // Below the line length.
    EXPECT_EQ(1u, snapshot.eventCount);
    EXPECT_EQ("E a-long-single-event-frame\n", snapshot.body);
}

TEST(EventAccumulatorTest, ConsumeAfterBoundedSnapshotPreservesRemainderAndTail)
{
    EventAccumulator accumulator {1024, 4, 10000};
    append(accumulator, "aa");
    append(accumulator, "bb");
    const auto snapshot = accumulator.snapshot(5); // Just the first line.
    append(accumulator, "cc"); // Arrives before consume.
    accumulator.consume(snapshot);
    const auto remaining = accumulator.snapshot(SIZE_MAX);
    EXPECT_EQ("E bb\nE cc\n", remaining.body);
    EXPECT_EQ(2u, remaining.eventCount);
}
