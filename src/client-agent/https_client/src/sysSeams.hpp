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

        /// Corrects this clock so wallSeconds() reports serverWallSeconds
        /// "now" and every subsequent wallSeconds() call from here on;
        /// steadyNow() (cadence) is never affected. Default no-op: only a
        /// clock that supports runtime correction (SkewCorrectedClock) needs
        /// to override it -- SystemClock and every test double that does not
        /// care about skew correction inherit this and stay unaffected.
        ///
        /// Contract for an overriding clock: this MUST be safe to call
        /// concurrently from multiple threads (every HTTPS sender shares one
        /// SkewCorrectedClock instance, and a real clock jump can make more
        /// than one of them observe a 401 around the same moment). The
        /// implementation must derive the new correction from its OWN raw
        /// clock read taken at commit time, not from a delta the caller
        /// computed earlier against a (possibly already stale, or
        /// concurrently-corrected) wallSeconds() reading -- otherwise two
        /// racing callers each read the same pre-correction time, each
        /// compute ~the same delta, and both apply it, overcorrecting by
        /// roughly double instead of converging. See SkewCorrectedClock's
        /// implementation comment for the algebra.
        virtual void correctToServerTime(std::time_t /*serverWallSeconds*/) {}
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

        /// verify_mode=system's trust anchor: the first well-known OS CA bundle
        /// path that exists on this host (Linux only -- Windows/macOS ask their
        /// native store instead and never call this). Empty when none is found.
        virtual std::string findSystemCaBundle() const = 0;
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

        void correctToServerTime(std::time_t serverWallSeconds) override
        {
            // Recompute the offset from the RAW base clock read at commit
            // time, under a lock, rather than accepting a delta the caller
            // measured earlier against wallSeconds() (this clock's own,
            // possibly already-corrected or concurrently-changing reading).
            // That makes every call idempotent and race-safe: no matter how
            // many threads call this at nearly the same moment (a real clock
            // jump can make more than one of the shared HTTPS senders 401
            // around the same time), each one lands on essentially the same
            // offset_new = serverWallSeconds - raw -- never a sum of two
            // callers' deltas. The lock only serializes rare correction
            // events; wallSeconds() stays lock-free.
            const std::lock_guard<std::mutex> lock(m_mutex);
            const auto raw = static_cast<std::int64_t>(m_base.wallSeconds());
            m_offsetSeconds.store(static_cast<std::int64_t>(serverWallSeconds) - raw,
                                  std::memory_order_relaxed);
        }

    private:
        IClock& m_base;
        std::atomic<std::int64_t> m_offsetSeconds {0};
        std::mutex m_mutex;
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
        std::string findSystemCaBundle() const override;
};

#endif // _HC_SYS_SEAMS_HPP
