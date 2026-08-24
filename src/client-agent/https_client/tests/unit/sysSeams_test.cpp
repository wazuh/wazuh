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

TEST(SkewCorrectedClockTest, DefaultsToNoCorrectionAndMirrorsTheBaseClock)
{
    SystemClock base;
    SkewCorrectedClock clock {base};
    EXPECT_EQ(base.wallSeconds(), clock.wallSeconds());
}

TEST(SkewCorrectedClockTest, AppliedOffsetShiftsWallSecondsOnly)
{
    class FixedClock final : public IClock
    {
        public:
            std::time_t wallSeconds() const override
            {
                return 1700000000;
            }

            std::chrono::steady_clock::time_point steadyNow() const override
            {
                return m_steady;
            }

        private:
            std::chrono::steady_clock::time_point m_steady {std::chrono::steady_clock::now()};
    };

    FixedClock base;
    SkewCorrectedClock clock {base};

    clock.correctToServerTime(1700000000 - 36000); // 10 h ahead, corrected back.
    EXPECT_EQ(1700000000 - 36000, clock.wallSeconds());
    EXPECT_EQ(base.steadyNow(), clock.steadyNow()); // Cadence timing untouched.
}

TEST(SkewCorrectedClockTest, EachCorrectionLandsExactlyOnItsOwnTargetRegardlessOfAnyPriorOne)
{
    // Each call recomputes its offset from the RAW base clock at commit
    // time, so a second, independent correction lands exactly on its own
    // target -- it does not stack on top of the first (a naive "add this
    // delta" design would give 1700000000 - 150 here instead of - 50,
    // reproducing the double-apply bug this design replaces).
    class FixedClock final : public IClock
    {
        public:
            std::time_t wallSeconds() const override
            {
                return 1700000000;
            }

            std::chrono::steady_clock::time_point steadyNow() const override
            {
                return {};
            }
    };

    FixedClock base;
    SkewCorrectedClock clock {base};

    clock.correctToServerTime(1700000000 - 100);
    EXPECT_EQ(1700000000 - 100, clock.wallSeconds());

    clock.correctToServerTime(1700000000 - 50); // A later, independent measurement.
    EXPECT_EQ(1700000000 - 50, clock.wallSeconds());
}

TEST(SkewCorrectedClockTest, ConcurrentCorrectionsToTheSameServerTimeConverge)
{
    // Regression test for a review-caught race: all 7 HTTPS senders share
    // ONE SkewCorrectedClock instance across 4 threads (control, stateless,
    // stateful, reporter -- httpsClientFacade.hpp), and a real clock jump
    // (NTP step, VM pause/resume) mid-session can make more than one of them
    // observe a 401 and call correctToServerTime() around the same moment.
    // Each call must derive its offset from a fresh raw read taken under its
    // own lock, not from a delta some caller computed earlier against a
    // stale wallSeconds() -- otherwise N racing callers applying "the same"
    // delta would sum to N times the correct magnitude instead of
    // converging, overcorrecting the clock the wrong way.
    class FixedClock final : public IClock
    {
        public:
            std::time_t wallSeconds() const override
            {
                return 1700000000;
            }

            std::chrono::steady_clock::time_point steadyNow() const override
            {
                return {};
            }
    };

    FixedClock base;
    SkewCorrectedClock clock {base};

    constexpr std::time_t serverTime = 1700000000 - 36000; // 10 h ahead, corrected back.
    constexpr int workerCount = 16;

    // A release barrier: without it, thread creation itself is slow enough
    // relative to correctToServerTime()'s tiny body that workers tend to run
    // one at a time anyway (each sees the PRIOR worker's already-applied
    // offset and harmlessly no-ops), never actually overlapping -- which
    // would let a genuinely racy implementation pass this test by luck. This
    // holds every worker spinning right at the call, then releases them all
    // at once, to actually force concurrent execution.
    std::atomic<int> readyCount {0};
    std::atomic<bool> go {false};
    std::vector<std::thread> workers;

    for (int worker = 0; worker < workerCount; worker++)
    {
        workers.emplace_back(
            [&]
        {
            readyCount.fetch_add(1, std::memory_order_relaxed);

            while (!go.load(std::memory_order_acquire))
            {
                // Spin until every worker is ready. The yield keeps this a
                // barrier rather than a busy-wait: under Valgrind every thread
                // shares one virtual CPU, and a spin that never yields holds
                // its whole scheduling quantum, which turns this barrier into
                // a multi-minute near-livelock.
                std::this_thread::yield();
            }

            clock.correctToServerTime(serverTime);
        });
    }

    while (readyCount.load(std::memory_order_relaxed) < workerCount)
    {
        // Wait for every worker to reach the spin point before releasing them.
        std::this_thread::yield();
    }

    go.store(true, std::memory_order_release);

    for (auto& worker : workers)
    {
        worker.join();
    }

    // Correctness/idempotency proof for the common case: many concurrent
    // callers correcting toward the SAME server time all converge on it.
    // (This alone is not a reliable regression guard for the review-caught
    // race -- empirically, even hundreds of unsynchronized repeats never
    // land inside the old bug's nanosecond-wide read/write window. The next
    // test below forces that exact interleaving deterministically.)
    EXPECT_EQ(serverTime, clock.wallSeconds());
}

TEST(SkewCorrectedClockTest, TheReadAndCommitAreOneCriticalSectionNotJustTheFinalStore)
{
    // Deterministic regression test for the review-caught race. A plain
    // multi-thread stress test (the one above) cannot reliably reproduce the
    // bug: the old implementation's read-then-fetch_add window is only a
    // couple of instructions wide, so real thread scheduling essentially
    // never lands two callers inside it, even under heavy contention. This
    // test instead uses a base clock that blocks mid-read to PIN one
    // correction while its raw read is in flight, and proves a second,
    // concurrent correction cannot start running (let alone read the base
    // clock or commit an offset) until the first has fully finished --
    // i.e. the critical section covers the raw read, not just the final
    // store. That is precisely the property the old fetch_add-based design
    // lacked: it read wallSeconds() OUTSIDE of any lock, so a second caller
    // could read the same pre-correction value and both would apply their
    // (near-identical) delta, overcorrecting by roughly double.
    class BlockingClock final : public IClock
    {
        public:
            std::time_t wallSeconds() const override
            {
                m_readStarted.store(true, std::memory_order_release);

                while (m_hold.load(std::memory_order_acquire))
                {
                    // Spin until the test releases this read. Yielding is what
                    // lets the other caller actually get scheduled and prove it
                    // is blocked on the mutex -- and keeps this from stalling
                    // for minutes under Valgrind's single virtual CPU.
                    std::this_thread::yield();
                }

                return m_value;
            }

            std::chrono::steady_clock::time_point steadyNow() const override
            {
                return {};
            }

            void waitUntilReadStarted() const
            {
                while (!m_readStarted.load(std::memory_order_acquire))
                {
                    // Spin until wallSeconds() has been entered.
                    std::this_thread::yield();
                }
            }

            void release()
            {
                m_hold.store(false, std::memory_order_release);
            }

        private:
            std::time_t m_value {1700000000};
            mutable std::atomic<bool> m_hold {true};
            mutable std::atomic<bool> m_readStarted {false};
    };

    BlockingClock base;
    SkewCorrectedClock clock {base};

    std::thread first([&] { clock.correctToServerTime(1700000000 - 100); });
    base.waitUntilReadStarted(); // `first` is now inside its raw read, blocked.

    std::atomic<bool> secondDone {false};
    std::thread second(
        [&]
    {
        clock.correctToServerTime(1700000000 - 200);
        secondDone.store(true, std::memory_order_release);
    });

    // `second` must be unable to make any progress -- not even its own raw
    // read -- while `first`'s critical section is still open. A generous
    // sleep here only risks a false pass (if scheduling were somehow this
    // slow), never a false failure: it cannot make this assertion wrongly
    // report "still blocked" for a `second` that actually finished. (Not
    // asserting on clock.wallSeconds() here: BlockingClock blocks ANY
    // caller while held, so even a same-thread read would deadlock.)
    std::this_thread::sleep_for(std::chrono::milliseconds {50});
    EXPECT_FALSE(secondDone.load(std::memory_order_acquire));

    // Release `first`'s read: it can now finish committing its own offset,
    // and -- since `second` was blocked on the SAME mutex the whole time --
    // `second` cannot acquire it (and start its own raw read) until `first`
    // fully releases. There is no reliable moment to inspect the clock
    // in between (once released, either thread may finish first depending
    // on scheduling); the only deterministic guarantee is the end state
    // once both have joined, which must be `second`'s target, since
    // `second` cannot commit until `first` already has.
    base.release();
    first.join();
    second.join();
    EXPECT_EQ(1700000000 - 200, clock.wallSeconds());
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
