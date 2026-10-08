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

#ifndef _REMOTED_HTTP_HANDSHAKE_LEDGER_HPP
#define _REMOTED_HTTP_HANDSHAKE_LEDGER_HPP

/**
 * @file handshakeLedger.hpp
 * @brief Which connections of the public listener hold a slot, which of them are still in the TLS
 *        handshake, and from where (issue #6883).
 *
 * WHY THIS EXISTS. RESTinio takes one of max_parallel_connections' slots when it accepts a socket,
 * and arms its first timer only once the TLS handshake has succeeded. A peer that connects and
 * sends nothing therefore held its slot forever, and 256 of them locked every agent out. The
 * handshake deadline (guardedTlsSocket.hpp) closes such a socket; this ledger is what makes the rest
 * of the defence possible:
 *
 * - The per-source cap. One address may have at most `maxPerSource` connections IN THE HANDSHAKE at
 *   once. A deadline alone only turns "hold forever" into "reconnect every few seconds", which one
 *   host can do as cheaply. Only connections still in the handshake are counted: an honest one
 *   leaves that state in milliseconds, so a fleet behind one NAT or L4 balancer address -- which
 *   shares ALL its established connections -- almost never has many there at once.
 * - The connection level. RESTinio's state listener reports `accepted` only AFTER a successful
 *   handshake, but `closed` for every connection it closes, including the ones whose handshake
 *   failed. Counting those two notices against each other underflowed on every failed handshake
 *   (a port scan, plain HTTP, a rejected client certificate) and never saw a stalled one at all.
 *   Here a connection is counted from the moment its handshake starts -- when it already holds its
 *   slot -- and only a connection that was counted is uncounted, once.
 *
 * Keys are RESTinio connection ids: unique per server run. They restart with a new server, which is
 * why start() calls reset(): no notice of the previous run can arrive once it has stopped, because
 * stop() joins the I/O threads first.
 *
 * Thread safety: every method may be called from any I/O thread; one mutex guards the tables. The
 * cost is one lock per connection event, never per request.
 *
 * Deliberately RESTinio- and asio-free, so it is unit-tested without a socket.
 */

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace remoted::http
{
    /// Point-in-time view of the ledger; all zeros when nothing was ever counted.
    struct HandshakeLedgerSnapshot
    {
        std::size_t open {0};                     ///< Connections holding a slot (handshake started, not closed).
        std::size_t handshaking {0};              ///< Of those, how many have not finished the TLS handshake.
        std::uint64_t timeoutsTotal {0};          ///< Handshakes closed by the deadline (cumulative).
        std::uint64_t rejectedPerSourceTotal {0}; ///< Connections refused by the per-source cap (cumulative).
    };

    class HandshakeLedger final
    {
    public:
        /**
         * @brief Sets the per-source cap on connections in the handshake. 0 disables it.
         *
         * Takes effect for the handshakes that start afterwards; the ones in progress keep counting.
         */
        void setMaxPerSource(std::size_t maxPerSource);

        /**
         * @brief Forgets every connection (the counters are kept). Called when a new server run starts.
         */
        void reset();

        /**
         * @brief A connection started its TLS handshake.
         *
         * The connection is counted as open whatever the answer: it holds a slot until it closes.
         *
         * @param connectionId RESTinio's id of the connection.
         * @param source       The peer address, as text. Empty when it could not be read (the peer is
         *                     already gone); such a connection is never refused.
         * @return false when the source already has the maximum number of handshakes in progress:
         *         the caller must close the connection. It is then NOT counted as handshaking.
         */
        bool beginHandshake(std::uint64_t connectionId, const std::string& source);

        /**
         * @brief The handshake of a connection ended, successfully or not. Idempotent.
         */
        void finishHandshake(std::uint64_t connectionId);

        /// The deadline closed a handshake.
        void recordTimeout();

        /**
         * @brief The connection closed. Uncounts it if it was counted; a second call, or a call for a
         *        connection that never began a handshake, is a no-op.
         */
        void closed(std::uint64_t connectionId);

        HandshakeLedgerSnapshot snapshot() const;

    private:
        struct Entry
        {
            std::string source;
            bool handshaking {false};
        };

        /// Caller holds m_mutex. Releases the entry's per-source share if it is still handshaking.
        void finishLocked(Entry& entry);

        mutable std::mutex m_mutex;
        std::size_t m_maxPerSource {0};
        std::unordered_map<std::uint64_t, Entry> m_connections;
        std::unordered_map<std::string, std::size_t> m_perSource;
        std::size_t m_handshaking {0};
        std::uint64_t m_timeoutsTotal {0};
        std::uint64_t m_rejectedPerSourceTotal {0};
    };
} // namespace remoted::http

#endif // _REMOTED_HTTP_HANDSHAKE_LEDGER_HPP
