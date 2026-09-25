/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * September 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "gtest/gtest.h"
#include "processHelperMac.h"

TEST(ProcessHelperMacTest, clockTicksFromMachTimeZeroAndInvalid)
{
    // Zero ticks should return 0
    EXPECT_EQ(0ULL, ProcessHelperMac::clockTicksFromMachTime(0, 1, 1, 100));
    EXPECT_EQ(0ULL, ProcessHelperMac::clockTicksFromMachTime(0, 125, 3, 100));

    // Zero denominator should be guarded and return 0
    EXPECT_EQ(0ULL, ProcessHelperMac::clockTicksFromMachTime(1000, 1, 0, 100));
}

TEST(ProcessHelperMacTest, clockTicksFromMachTimeIntel)
{
    // Intel: 1:1 timebase ratio (1 tick = 1 nanosecond)
    constexpr uint32_t numer { 1 };
    constexpr uint32_t denom { 1 };
    constexpr int64_t clkTck { 100 }; // 100 ticks per second (10 ms per tick)

    // 10 milliseconds = 10,000,000 nanoseconds -> 1 clock tick
    EXPECT_EQ(1ULL, ProcessHelperMac::clockTicksFromMachTime(10'000'000ULL, numer, denom, clkTck));

    // 1 second = 1,000,000,000 nanoseconds -> 100 clock ticks
    EXPECT_EQ(100ULL, ProcessHelperMac::clockTicksFromMachTime(1'000'000'000ULL, numer, denom, clkTck));

    // 10 seconds = 10,000,000,000 nanoseconds -> 1000 clock ticks
    EXPECT_EQ(1000ULL, ProcessHelperMac::clockTicksFromMachTime(10'000'000'000ULL, numer, denom, clkTck));

    // Sub-tick (5 ms = 5,000,000 ns) -> 0 clock ticks
    EXPECT_EQ(0ULL, ProcessHelperMac::clockTicksFromMachTime(5'000'000ULL, numer, denom, clkTck));
}

TEST(ProcessHelperMacTest, clockTicksFromMachTimeAppleSilicon)
{
    // Apple Silicon (ARM64): 24 MHz counter -> 1 tick = 125 / 3 nanoseconds
    constexpr uint32_t numer { 125 };
    constexpr uint32_t denom { 3 };
    constexpr int64_t clkTck { 100 };

    // 24,000,000 ticks = 1 second -> 100 clock ticks
    EXPECT_EQ(100ULL, ProcessHelperMac::clockTicksFromMachTime(24'000'000ULL, numer, denom, clkTck));

    // 12,000,000 ticks = 500 ms -> 50 clock ticks
    EXPECT_EQ(50ULL, ProcessHelperMac::clockTicksFromMachTime(12'000'000ULL, numer, denom, clkTck));

    // 240,000 ticks = 10 ms -> 1 clock tick
    EXPECT_EQ(1ULL, ProcessHelperMac::clockTicksFromMachTime(240'000ULL, numer, denom, clkTck));
}

TEST(ProcessHelperMacTest, clockTicksFromMachTimeLargeValuesNoOverflow)
{
    // 100 days of continuous process CPU time on Apple Silicon (24 MHz)
    // 100 days = 8,640,000 seconds = 207,360,000,000,000 mach ticks
    constexpr uint64_t hundredDaysTicks { 207'360'000'000'000ULL };
    constexpr uint32_t numer { 125 };
    constexpr uint32_t denom { 3 };
    constexpr int64_t clkTck { 100 };

    // Expected: 8,640,000 seconds * 100 ticks/sec = 864,000,000 clock ticks
    constexpr uint64_t expectedTicks { 864'000'000ULL };
    EXPECT_EQ(expectedTicks, ProcessHelperMac::clockTicksFromMachTime(hundredDaysTicks, numer, denom, clkTck));
}

TEST(ProcessHelperMacTest, clockTicksFromMachTimeFallbackClkTck)
{
    // Non-positive clkTck should fallback to 100
    EXPECT_EQ(100ULL, ProcessHelperMac::clockTicksFromMachTime(1'000'000'000ULL, 1, 1, 0));
    EXPECT_EQ(100ULL, ProcessHelperMac::clockTicksFromMachTime(1'000'000'000ULL, 1, 1, -1));
}

TEST(ProcessHelperMacTest, threadStateRankOrdering)
{
    EXPECT_EQ(1, ProcessHelperMac::threadStateRank(TH_STATE_RUNNING, 0));
    EXPECT_EQ(2, ProcessHelperMac::threadStateRank(TH_STATE_UNINTERRUPTIBLE, 0));
    EXPECT_EQ(3, ProcessHelperMac::threadStateRank(TH_STATE_WAITING, 0));
    EXPECT_EQ(3, ProcessHelperMac::threadStateRank(TH_STATE_WAITING, 20));
    EXPECT_EQ(4, ProcessHelperMac::threadStateRank(TH_STATE_WAITING, 21));
    EXPECT_EQ(5, ProcessHelperMac::threadStateRank(TH_STATE_STOPPED, 0));
    EXPECT_EQ(6, ProcessHelperMac::threadStateRank(TH_STATE_HALTED, 0));
    EXPECT_EQ(ProcessHelperMac::THREAD_STATE_RANK_UNKNOWN, ProcessHelperMac::threadStateRank(0, 0));
    EXPECT_EQ(ProcessHelperMac::THREAD_STATE_RANK_UNKNOWN, ProcessHelperMac::threadStateRank(99, 0));
}

TEST(ProcessHelperMacTest, getProcessStateFromThreads)
{
    // A process reported as running by the BSD status takes its state from its threads
    constexpr uint32_t runningStatus { 2 }; // SRUN
    EXPECT_EQ("R", ProcessHelperMac::getProcessState(runningStatus, 1));
    EXPECT_EQ("U", ProcessHelperMac::getProcessState(runningStatus, 2));
    EXPECT_EQ("S", ProcessHelperMac::getProcessState(runningStatus, 3));
    // Long idle threads are reported as sleeping so the state does not flip between scans
    EXPECT_EQ("S", ProcessHelperMac::getProcessState(runningStatus, 4));
    EXPECT_EQ("T", ProcessHelperMac::getProcessState(runningStatus, 5));
    EXPECT_EQ("H", ProcessHelperMac::getProcessState(runningStatus, 6));
}

TEST(ProcessHelperMacTest, getProcessStateStoppedAndZombie)
{
    // Stopped and zombie BSD statuses win over any thread state
    EXPECT_EQ("T", ProcessHelperMac::getProcessState(SSTOP, 1));
    EXPECT_EQ("Z", ProcessHelperMac::getProcessState(SZOMB, 1));
    EXPECT_EQ("Z", ProcessHelperMac::getProcessState(SZOMB, ProcessHelperMac::THREAD_STATE_RANK_UNKNOWN));
}

TEST(ProcessHelperMacTest, getProcessStateUnknown)
{
    EXPECT_EQ(UNKNOWN_VALUE, ProcessHelperMac::getProcessState(2, ProcessHelperMac::THREAD_STATE_RANK_UNKNOWN));
    EXPECT_EQ(UNKNOWN_VALUE, ProcessHelperMac::getProcessState(2, 0));
    EXPECT_EQ(UNKNOWN_VALUE, ProcessHelperMac::getProcessState(0, 99));
}
