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

#ifndef _INDEXER_CLIENT_BACKOFF_HPP
#define _INDEXER_CLIENT_BACKOFF_HPP

// The backoff, shared by the bucket retry lane and the query engine.

#include <algorithm>
#include <cstdint>
#include <random>

#include "indexer_client/types.hpp"

namespace indexer_client::detail
{
    /// Uniform in [-1, 1]: one draw per requeue in a bucket (the ops of one batch keep travelling together), one per
    /// wait in a query.
    inline double jitterDraw()
    {
        thread_local std::mt19937_64 engine {std::random_device {}()};
        return std::uniform_real_distribution<double>(-1.0, 1.0)(engine);
    }

    /// D = min(cap, base * 2^(attempts - 1)) with the exponent bounded (d = cap as soon as doubling reaches
    /// it, so an unlimited policy never overflows), then d * (1 + jitter * u), clamped to [0, cap].
    inline Duration backoffDelay(const RetryPolicy& retry, std::uint32_t attempts, double u)
    {
        using Rep = Duration::rep;
        const Rep cap = std::max<Rep>(retry.cap.count(), 0);
        Rep d = std::min<Rep>(std::max<Rep>(retry.base.count(), 0), cap);
        for (std::uint32_t k = 1; k < attempts && d < cap; ++k)
        {
            d = d > cap / 2 ? cap : d * 2;
        }
        const double scaled = static_cast<double>(d) * (1.0 + retry.jitter * u);
        if (!(scaled > 0.0)) // Also NaN.
        {
            return Duration::zero();
        }
        return scaled >= static_cast<double>(cap) ? Duration {cap} : Duration {static_cast<Rep>(scaled)};
    }
} // namespace indexer_client::detail

#endif // _INDEXER_CLIENT_BACKOFF_HPP
