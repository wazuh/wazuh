/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "handshakeLedger.hpp"

#include <utility>

namespace remoted::http
{
    HandshakeLedger::Share::Share(HandshakeLedger& ledger, const std::uint64_t ticket) noexcept
        : m_ledger {&ledger}
        , m_ticket {ticket}
    {
    }

    HandshakeLedger::Share::Share(Share&& other) noexcept
        : m_ledger {std::exchange(other.m_ledger, nullptr)}
        , m_ticket {std::exchange(other.m_ticket, 0)}
    {
    }

    HandshakeLedger::Share& HandshakeLedger::Share::operator=(Share&& other) noexcept
    {
        if (this != &other)
        {
            release();
            m_ledger = std::exchange(other.m_ledger, nullptr);
            m_ticket = std::exchange(other.m_ticket, 0);
        }
        return *this;
    }

    HandshakeLedger::Share::~Share()
    {
        release();
    }

    void HandshakeLedger::Share::release() noexcept
    {
        if (m_ledger != nullptr)
        {
            std::exchange(m_ledger, nullptr)->release(m_ticket);
        }
    }

    void HandshakeLedger::setMaxPerSource(const std::size_t maxPerSource)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        m_maxPerSource = maxPerSource;
    }

    void HandshakeLedger::reset()
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        m_connections.clear();
        m_handshakes.clear();
        m_perSource.clear();
    }

    HandshakeLedger::Share HandshakeLedger::beginHandshake(const std::uint64_t connectionId, const std::string& source)
    {
        std::lock_guard<std::mutex> lock {m_mutex};

        // Counted as open in every case: the connection already holds its slot, refused or not, and
        // its closed notice is what uncounts it.
        auto& entry = m_connections[connectionId];

        const auto inProgress = source.empty() ? m_perSource.end() : m_perSource.try_emplace(source).first;
        if (inProgress != m_perSource.end() && m_maxPerSource != 0 && inProgress->second >= m_maxPerSource)
        {
            ++m_rejectedPerSourceTotal;
            return Share {};
        }

        // The handshake is recorded before the address is charged: the emplace allocates, and a throw
        // after the increment would leave the address a unit that no share gives back.
        const auto ticket = m_nextTicket;
        m_handshakes.emplace(ticket, source);
        ++m_nextTicket;
        if (inProgress != m_perSource.end())
        {
            ++inProgress->second;
        }

        // A second begin under the same id overwrites the entry's ticket: the first handshake is still
        // released by its own share, and the close notice releases whichever one it finds.
        entry.ticket = ticket;
        return Share {*this, ticket};
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
            releaseLocked(it->second.ticket);
            m_connections.erase(it);
        }
    }

    HandshakeLedgerSnapshot HandshakeLedger::snapshot() const
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        HandshakeLedgerSnapshot snapshot;
        snapshot.open = m_connections.size();
        snapshot.handshaking = m_handshakes.size();
        snapshot.timeoutsTotal = m_timeoutsTotal;
        snapshot.rejectedPerSourceTotal = m_rejectedPerSourceTotal;
        return snapshot;
    }

    void HandshakeLedger::release(const std::uint64_t ticket)
    {
        std::lock_guard<std::mutex> lock {m_mutex};
        releaseLocked(ticket);
    }

    void HandshakeLedger::releaseLocked(const std::uint64_t ticket)
    {
        const auto handshake = m_handshakes.find(ticket);
        if (handshake == m_handshakes.end())
        {
            return; // never counted, already released, or forgotten by reset()
        }
        const auto source = std::move(handshake->second);
        m_handshakes.erase(handshake);

        if (source.empty())
        {
            return;
        }
        // Erased at zero, so the table holds only the sources with a handshake in progress: it grows
        // with the handshakes in flight (bounded by max_parallel_connections), never with the number
        // of addresses ever seen.
        if (const auto it = m_perSource.find(source); it != m_perSource.end() && --it->second == 0)
        {
            m_perSource.erase(it);
        }
    }
} // namespace remoted::http
