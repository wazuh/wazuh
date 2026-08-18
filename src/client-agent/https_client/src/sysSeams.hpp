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

#ifndef _HC_SYS_SEAMS_HPP
#define _HC_SYS_SEAMS_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <mutex>
#include <random>
#include <string>

/// Wall + monotonic time source. Injected so tests control signing timestamps
/// and cadence decisions deterministically.
class IClock
{
    public:
        virtual ~IClock() = default;
        virtual std::time_t wallSeconds() const = 0;
        virtual std::chrono::steady_clock::time_point steadyNow() const = 0;

        /// Pushes a measured clock-skew correction (signed seconds) into this
        /// clock, applied to every wallSeconds() call from here on;
        /// steadyNow() (cadence) is never affected. Default no-op: only a
        /// clock that supports runtime correction (SkewCorrectedClock) needs
        /// to override it -- SystemClock and every test double that does not
        /// care about skew correction inherit this and stay unaffected.
        ///
        /// Contract for an overriding clock: the correction MUST accumulate,
        /// not replace. The caller always measures its delta against THIS
        /// clock's own (possibly already-corrected) wallSeconds(), so a
        /// second, independent skew event landing on top of an existing
        /// correction must fold its delta onto the prior offset rather than
        /// overwrite it -- replacing would silently undo the earlier
        /// correction by exactly its own magnitude. See SkewCorrectedClock's
        /// implementation comment for the algebra.
        virtual void applyOffsetSeconds(std::int64_t /*offsetSeconds*/) {}
};

/// Uniform randomness source for the full-jitter backoff.
class IRandom
{
    public:
        virtual ~IRandom() = default;
        virtual double uniform01() = 0;
};

/// Filesystem probe used by the fail-closed TLS validation.
class IFsProbe
{
    public:
        virtual ~IFsProbe() = default;
        virtual bool isReadableFile(const std::string& path) const = 0;
};

class SystemClock final : public IClock
{
    public:
        std::time_t wallSeconds() const override;
        std::chrono::steady_clock::time_point steadyNow() const override;
};

/// Decorates a base IClock with a runtime-correctable offset applied to
/// wallSeconds() only. All seven HTTPS senders share one instance of this
/// (HttpsClientFacade::m_clock) by reference, so a skew learned from any one
/// manager response (RetrySender's one-shot 401 retry, per #37828)
/// corrects every subsequent signing timestamp agent-wide, starting with the
/// very next request -- not just the sender that observed the 401.
class SkewCorrectedClock final : public IClock
{
    public:
        explicit SkewCorrectedClock(IClock& base)
            : m_base(base)
        {
        }

        std::time_t wallSeconds() const override
        {
            return m_base.wallSeconds() + m_offsetSeconds.load(std::memory_order_relaxed);
        }

        std::chrono::steady_clock::time_point steadyNow() const override
        {
            return m_base.steadyNow(); // Cadence timing is never skew-corrected.
        }

        void applyOffsetSeconds(std::int64_t offsetSeconds) override
        {
            // Accumulate, don't replace: the caller (RetrySender) measures
            // its delta against THIS clock's own wallSeconds() -- i.e.
            // against a reading that already includes any prior offset. A
            // second, independent skew event (further drift, or a second
            // clock jump, after the agent has already self-corrected once)
            // therefore yields a delta relative to the already-corrected
            // baseline, not to the raw one. Replacing here would discard the
            // earlier correction and leave the clock off by exactly its
            // magnitude; accumulating folds the new delta on top and lands
            // on the same result as re-measuring from the raw clock and
            // overwriting, algebraically: offset_new = offset_old + (server
            // - corrected) = offset_old + (server - raw - offset_old) =
            // server - raw.
            m_offsetSeconds.fetch_add(offsetSeconds, std::memory_order_relaxed);
        }

    private:
        IClock& m_base;
        std::atomic<std::int64_t> m_offsetSeconds {0};
};

class Mt19937Random final : public IRandom
{
    public:
        Mt19937Random();
        double uniform01() override;

    private:
        std::mutex m_mutex;
        std::mt19937_64 m_engine;
};

class FsProbe final : public IFsProbe
{
    public:
        bool isReadableFile(const std::string& path) const override;
};

#endif // _HC_SYS_SEAMS_HPP
