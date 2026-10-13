/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * October 8, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "handshakeLedger.hpp"

namespace remoted::http
{
    void HandshakeLedger::setMaxPerSource(const std::size_t maxPerSource)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        m_maxPerSource = maxPerSource;
    }

    void HandshakeLedger::reset()
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        m_connections.clear();
        m_perSource.clear();
        m_handshaking = 0;
    }

    bool HandshakeLedger::beginHandshake(const std::uint64_t connectionId, const std::string& source)
    {
        std::lock_guard<std::mutex> lock {m_mutex};

        // Counted as open in every case: the connection already holds its slot, refused or not, and
        // its closed notice is what uncounts it.
        auto& entry = m_connections[connectionId];
        entry.source = source;

        if (!source.empty())
        {
            auto& inProgress = m_perSource[source];
            if (m_maxPerSource != 0 && inProgress >= m_maxPerSource)
            {
                ++m_rejectedPerSourceTotal;
                return false;
            }
            ++inProgress;
        }

        entry.handshaking = true;
        ++m_handshaking;
        return true;
    }

    void HandshakeLedger::finishHandshake(const std::uint64_t connectionId)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        if (const auto it = m_connections.find(connectionId); it != m_connections.end())
        {
            finishLocked(it->second);
        }
    }

    void HandshakeLedger::recordTimeout()
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        ++m_timeoutsTotal;
    }

    void HandshakeLedger::closed(const std::uint64_t connectionId)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        if (const auto it = m_connections.find(connectionId); it != m_connections.end())
        {
            finishLocked(it->second);
            m_connections.erase(it);
        }
    }

    HandshakeLedgerSnapshot HandshakeLedger::snapshot() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        HandshakeLedgerSnapshot snapshot;
        snapshot.open = m_connections.size();
        snapshot.handshaking = m_handshaking;
        snapshot.timeoutsTotal = m_timeoutsTotal;
        snapshot.rejectedPerSourceTotal = m_rejectedPerSourceTotal;
        return snapshot;
    }

    void HandshakeLedger::finishLocked(Entry& entry)
    {
        if (!entry.handshaking)
        {
            return;
        }
        entry.handshaking = false;
        --m_handshaking;

        if (entry.source.empty())
        {
            return;
        }
        // Erased at zero, so the table holds only the sources with a handshake in progress: it grows
        // with the handshakes in flight (bounded by max_parallel_connections), never with the number
        // of addresses ever seen.
        if (const auto it = m_perSource.find(entry.source); it != m_perSource.end() && --it->second == 0)
        {
            m_perSource.erase(it);
        }
    }
} // namespace remoted::http
