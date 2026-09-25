/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * September 16, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HC_CA_PUBLICATION_STATE_HPP
#define _HC_CA_PUBLICATION_STATE_HPP

#include <algorithm>
#include <cstdint>
#include <mutex>
#include <optional>

/// No publication is recorded locally. Mirrors W_CA_PUBLICATION_UNKNOWN on the C side, which
/// owns the on-disk half; kept as its own constant so this header pulls in nothing from there.
constexpr std::int64_t CA_PUBLICATION_UNKNOWN = -1;

/**
 * @brief Rule 3 of #39321: what a notify's advertised publication means for the agent.
 *
 * Pure, and deliberately so -- this is the whole of the adoption policy, it runs at the
 * keepalive cadence, and every interesting case is a pair of integers.
 *
 * @param local The publication recorded with the installed bundle, or CA_PUBLICATION_UNKNOWN.
 * @param advertised The `ca_generation` field: std::nullopt when the field was absent (a manager
 *        older than this feature), 0 when the node serves a bundle nobody has published.
 * @return true when the agent should fetch, false when it should leave its trust store alone.
 */
inline bool caPublicationShouldFetch(std::int64_t local, std::optional<std::int64_t> advertised)
{
    // Absent: an older manager, which says nothing about CA bundles at all.
    if (!advertised.has_value())
    {
        return false;
    }

    // 0 (and null, which arrives here as 0) is a node with no bundle, or one serving a bundle
    // nobody has published and which it therefore does not vouch for. Never adopted.
    if (*advertised <= 0)
    {
        return false;
    }

    // Nothing recorded locally: re-anchor on a known publication. This is how an agent that
    // bootstrapped a pinned certificate, or whose store was placed out of band, joins the
    // sequence at all -- without it, it would never have a `local` to compare against.
    if (local == CA_PUBLICATION_UNKNOWN)
    {
        return true;
    }

    // Strictly upward. A lower publication is a lagging node behind a load balancer, or a
    // rollback the operator has not published yet; either way it is never adopted, whatever its
    // content. Equal means there is nothing to do.
    return *advertised > local;
}

/**
 * @brief The module's view of the publication its trust store carries, and of the one it is on
 *        its way to adopting.
 *
 * Read and written from the control thread, and read from the C ABI, so guarded like
 * ConfigHashState next door.
 *
 * The pending target exists because of rule 5.1: a fetch waits out a random delay first, and
 * notifies keep arriving during it. Whatever the highest publication seen by the time the fetch
 * actually runs is what gets fetched -- not the one that happened to trigger the wait.
 */
class CaPublicationState final
{
    public:
        explicit CaPublicationState(std::int64_t local)
            : m_local(local)
        {
        }

        std::int64_t local() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_local;
        }

        /// Records what was actually installed, once a bundle has been committed to disk.
        void setLocal(std::int64_t local)
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_local = local;

            // A commit satisfies any target at or below it. Leaving a lower one armed would
            // spend a fetch re-learning what was just installed.
            if (m_pending <= m_local)
            {
                m_pending = 0;
            }
        }

        /// Applies rule 3 to one notify. Returns true when this is the observation that arms a
        /// fetch, so the caller schedules exactly one wait however many notifies raise the
        /// target while it is pending.
        bool observe(std::optional<std::int64_t> advertised)
        {
            std::lock_guard<std::mutex> lock(m_mutex);

            if (!caPublicationShouldFetch(m_local, advertised))
            {
                return false;
            }

            const bool armed = m_pending == 0;
            m_pending = std::max(m_pending, *advertised);

            return armed;
        }

        /// The publication to fetch, or 0 when none is pending. Left armed: it is cleared by
        /// setLocal() on a successful commit, so a discarded response (rule 5.3) still has a
        /// target to retry against.
        std::int64_t pending() const
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            return m_pending;
        }

        /// Abandons the pending target without installing anything. For the cases where
        /// retrying cannot help: the target was withdrawn, or the agent is giving up on it.
        void clearPending()
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_pending = 0;
        }

    private:
        mutable std::mutex m_mutex;
        std::int64_t m_local;
        std::int64_t m_pending {0};
};

#endif // _HC_CA_PUBLICATION_STATE_HPP
