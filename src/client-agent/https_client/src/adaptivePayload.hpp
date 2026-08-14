/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_ADAPTIVE_PAYLOAD_HPP
#define _HC_ADAPTIVE_PAYLOAD_HPP

#include <algorithm>
#include <cstdint>

/**
 * @brief The effective /stateless payload budget (#37835). Starts at the
 *        configured max; a 413 halves it, a successful send doubles it back
 *        toward the max. Halving has NO lower clamp (only never-zero): with a
 *        hard floor, a server cap below floor + header would wedge the stream
 *        retrying the same too-big batch forever. At one byte the snapshot
 *        still carries one whole event, so a persistent 413 converges onto
 *        the single-event drop path instead of livelocking. StatelessStream
 *        serializes access because intake also reads the current budget.
 */
class AdaptivePayload final
{
    public:
        explicit AdaptivePayload(uint64_t maxBytes)
            : m_max(maxBytes == 0 ? 1 : maxBytes)
            , m_effective(m_max)
        {
        }

        uint64_t effectiveBytes() const
        {
            return m_effective;
        }

        /// A 413: shrink so the next batch carries fewer events (never zero).
        void onPayloadTooLarge()
        {
            m_effective = std::max<uint64_t>(1, m_effective / 2);
        }

        /// A successful send: ramp back toward the configured max.
        void onSuccess()
        {
            m_effective = std::min(m_max, m_effective * 2);
        }

    private:
        uint64_t m_max;
        uint64_t m_effective;
};

#endif // _HC_ADAPTIVE_PAYLOAD_HPP
