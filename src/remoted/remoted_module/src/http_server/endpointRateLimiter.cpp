/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * September 14, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "endpointRateLimiter.hpp"

#include <algorithm>
#include <cmath>

namespace remoted::http
{
    namespace
    {
        double resolveBurst(double burst, double ratePerSecond)
        {
            // A burst below the rate is a legitimate setting, not an error: the bucket refills
            // continuously, so the route still reaches the full sustained rate -- the requests just
            // cannot arrive all at once. Only a missing value falls back to the rate.
            return burst > 0.0 ? burst : ratePerSecond;
        }

        unsigned resolveRetryAfterSeconds(double ratePerSecond)
        {
            if (ratePerSecond <= 0.0)
            {
                return 1U;
            }
            const auto seconds = std::ceil(1.0 / ratePerSecond);
            // Whole seconds is all Retry-After can express, and 0 would invite an immediate retry.
            return static_cast<unsigned>(std::max(1.0, seconds));
        }
    } // namespace

    EndpointRateLimiter::EndpointRateLimiter(Settings settings)
        : m_enabled {settings.ratePerSecond > 0.0}
        , m_ratePerSecond {settings.ratePerSecond}
        , m_burst {resolveBurst(settings.burst, settings.ratePerSecond)}
        , m_retryAfterSeconds {resolveRetryAfterSeconds(settings.ratePerSecond)}
        , m_tokens {resolveBurst(settings.burst, settings.ratePerSecond)}
    {
        // The bucket starts FULL: the route has served nothing yet, and starting it empty would
        // refuse the first requests after every restart -- on /enroll, exactly the moment a fleet
        // coming back up needs it.
    }

    double EndpointRateLimiter::refilledAt(Clock::time_point now) const
    {
        // First charge after construction: `m_last` is the epoch, so the elapsed time would be
        // enormous. Harmless (the refill saturates at m_burst, where the bucket already is) but
        // pointless to compute, hence the explicit branch.
        if (m_last.time_since_epoch().count() == 0)
        {
            return m_tokens;
        }

        const auto elapsed = std::chrono::duration_cast<std::chrono::duration<double>>(now - m_last).count();
        if (elapsed <= 0.0)
        {
            return m_tokens;
        }
        return std::min(m_burst, m_tokens + (elapsed * m_ratePerSecond));
    }

    bool EndpointRateLimiter::allow()
    {
        if (!m_enabled)
        {
            return true;
        }

        const auto now = Clock::now();
        std::lock_guard<std::mutex> lock {m_mutex};

        m_tokens = refilledAt(now);
        m_last = now;

        if (m_tokens < 1.0)
        {
            ++m_rejectedTotal;
            return false;
        }

        m_tokens -= 1.0;
        return true;
    }

    EndpointRateLimiter::Diagnostics EndpointRateLimiter::diagnostics() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        // Reports the refilled value without storing it: a scrape must observe the bucket, never
        // move it.
        return Diagnostics {m_enabled ? m_ratePerSecond : 0.0,
                            m_enabled ? m_burst : 0.0,
                            m_enabled ? refilledAt(Clock::now()) : 0.0,
                            m_rejectedTotal};
    }

} // namespace remoted::http
