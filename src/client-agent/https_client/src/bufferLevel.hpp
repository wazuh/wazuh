/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 24, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_BUFFER_LEVEL_HPP
#define _HC_BUFFER_LEVEL_HPP

#include "https_client.h"

#include <cstdint>

/**
 * @brief The four-level client-buffer ladder, re-based on byte occupancy
 *        (#37835).
 *
 * A port of the legacy leaky bucket's state machine (client-agent/src/buffer.c)
 * so the manager-side flood rules keep seeing the same transitions once
 * stateless events stop passing through buffer_append():
 *
 *   NORMAL  -> WARNING  at warn_level % occupancy
 *   any     -> FULL     the moment an event is actually dropped (the byte
 *                       analogue of buffer.c's full(): no room, event lost)
 *   FULL    -> FLOOD    once FULL has held for tolerance seconds
 *   any     -> NORMAL   at normal_level % occupancy
 *
 * The gap between warn_level and normal_level is the hysteresis that keeps a
 * buffer hovering around the warn mark from flapping; buffer.c's defaults
 * (agent.warn_level 90, agent.normal_level 70, agent.tolerance 15) are the
 * module's defaults too, and the bridge forwards whatever the operator set.
 *
 * observe() reports whether the transition is one the agent announces.
 * buffer.c deliberately does not announce the step down from FULL/FLOOD to
 * WARNING -- only the return to NORMAL is reported -- so neither does this.
 *
 * Pure and not thread-safe: StatelessStream owns one and calls it under its
 * own state mutex.
 */
class BufferLevelLadder final
{
    public:
        struct Transition
        {
            bool announce;          ///< True when the agent reports this step.
            hc_buffer_level_t level;
        };

        BufferLevelLadder(uint32_t warnLevel, uint32_t normalLevel, uint32_t toleranceSeconds)
            : m_warnLevel(warnLevel)
              // Mirrors internal_options' own constraint (normal_level max is
              // warn_level - 1): a config that inverts them would otherwise make
              // every observation both "warn" and "normal" at once.
            , m_normalLevel(normalLevel < warnLevel ? normalLevel
                            : (warnLevel > 0 ? warnLevel - 1 : 0))
            , m_toleranceSeconds(toleranceSeconds)
        {
        }

        /**
         * @brief Feeds one observation of the buffer.
         *
         * @param occupancyPercent Whole-buffer occupancy, 0-100.
         * @param eventDropped     True when this observation follows a
         *                         drop-newest rejection (buffer.c's full()).
         * @param nowSeconds       Monotonic seconds, for the FLOOD dwell.
         */
        Transition observe(unsigned occupancyPercent, bool eventDropped, int64_t nowSeconds)
        {
            // buffer.c: from NORMAL or WARNING, a full buffer goes straight to
            // FULL and starts the tolerance clock.
            if (eventDropped && m_level != HC_BUFFER_FULL && m_level != HC_BUFFER_FLOOD)
            {
                m_level = HC_BUFFER_FULL;
                m_fullSince = nowSeconds;
                return Transition {true, m_level};
            }

            switch (m_level)
            {
                case HC_BUFFER_NORMAL:
                    if (occupancyPercent >= m_warnLevel)
                    {
                        m_level = HC_BUFFER_WARNING;
                        return Transition {true, m_level};
                    }

                    break;

                case HC_BUFFER_WARNING:
                    if (occupancyPercent <= m_normalLevel)
                    {
                        m_level = HC_BUFFER_NORMAL;
                        return Transition {true, m_level};
                    }

                    break;

                case HC_BUFFER_FULL:
                    if (occupancyPercent <= m_normalLevel)
                    {
                        m_level = HC_BUFFER_NORMAL;
                        return Transition {true, m_level};
                    }

                    if (occupancyPercent <= m_warnLevel)
                    {
                        m_level = HC_BUFFER_WARNING; // Quiet step down, as in buffer.c.
                        return Transition {false, m_level};
                    }

                    if (nowSeconds - m_fullSince >= static_cast<int64_t>(m_toleranceSeconds))
                    {
                        m_level = HC_BUFFER_FLOOD;
                        return Transition {true, m_level};
                    }

                    break;

                case HC_BUFFER_FLOOD:
                    if (occupancyPercent <= m_normalLevel)
                    {
                        m_level = HC_BUFFER_NORMAL;
                        return Transition {true, m_level};
                    }

                    if (occupancyPercent <= m_warnLevel)
                    {
                        m_level = HC_BUFFER_WARNING; // Quiet step down, as in buffer.c.
                        return Transition {false, m_level};
                    }

                    break;
            }

            return Transition {false, m_level};
        }

        hc_buffer_level_t level() const
        {
            return m_level;
        }

    private:
        uint32_t m_warnLevel;
        uint32_t m_normalLevel;
        uint32_t m_toleranceSeconds;
        hc_buffer_level_t m_level {HC_BUFFER_NORMAL};
        int64_t m_fullSince {0};
};

#endif // _HC_BUFFER_LEVEL_HPP
