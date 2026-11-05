/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
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
 *   slot -- until RESTinio's closed notice for its id.
 *
 * Each handshake is released through the Share that beginHandshake() returned for it, never through
 * the connection id: a share releases its own handshake once, whatever happened to the id. Two
 * connections that ever shared an id -- RESTinio's own connection factory could give two connections
 * created at the same moment the same one -- each count against their address and each give their
 * unit back. Keyed by id, the second handshake used to keep one slot of its address until remoted
 * restarted. The transport now also replaces that factory with one that takes its ids from
 * connectionIdSource.hpp, so the ids that drive the connection level are distinct for every connection
 * of a server run. They restart with a new server, which is why start() calls reset(): no notice of the
 * previous run can arrive once it has stopped, because stop() joins the I/O threads first.
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
         * @brief One handshake in progress, counted against its address until released.
         *
         * Move-only. release() gives the handshake's unit back, once; the destructor does it if
         * nobody did. An empty share (default-constructed, refused, released or moved from) releases
         * nothing. The ledger must outlive its shares. Not thread-safe on its own: one owner at a time.
         */
        class Share final
        {
        public:
            Share() noexcept = default;
            Share(Share&& other) noexcept;
            Share& operator=(Share&& other) noexcept;
            Share(const Share&) = delete;
            Share& operator=(const Share&) = delete;
            ~Share();

            /// Whether this share still holds a handshake.
            explicit operator bool() const noexcept
            {
                return m_ledger != nullptr;
            }

            /// The handshake ended, successfully or not. A second call is a no-op.
            void release() noexcept;

        private:
            friend class HandshakeLedger;
            Share(HandshakeLedger& ledger, std::uint64_t ticket) noexcept;

            HandshakeLedger* m_ledger {nullptr};
            std::uint64_t m_ticket {0};
        };

        /**
         * @brief Sets the per-source cap on connections in the handshake. 0 disables it.
         *
         * Takes effect for the handshakes that start afterwards; the ones in progress keep counting.
         */
        void setMaxPerSource(std::size_t maxPerSource);

        /**
         * @brief Forgets every connection (the counters are kept). Called when a new server run starts.
         *
         * A share taken before the reset releases nothing afterwards.
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
         * @return The share of this handshake, which the caller keeps until the handshake ends. Empty
         *         when the source already has the maximum number of handshakes in progress: the caller
         *         must close the connection, which is then NOT counted as handshaking.
         */
        [[nodiscard]] Share beginHandshake(std::uint64_t connectionId, const std::string& source);

        /// The deadline closed a handshake.
        void recordTimeout();

        /**
         * @brief The connection closed. Uncounts it, and releases its handshake if it closed in the
         *        middle of it; a second call, or a call for a connection that never began a handshake,
         *        is a no-op.
         */
        void closed(std::uint64_t connectionId);

        HandshakeLedgerSnapshot snapshot() const;

    private:
        struct Entry
        {
            std::uint64_t ticket {0}; ///< The connection's handshake while it may be in progress; 0 when none.
        };

        /// Caller holds m_mutex. Gives the handshake's unit back if it is still in progress.
        void releaseLocked(std::uint64_t ticket);

        /// Called by Share.
        void release(std::uint64_t ticket);

        mutable std::mutex m_mutex;
        std::size_t m_maxPerSource {0};
        /// Every open connection, by RESTinio id.
        std::unordered_map<std::uint64_t, Entry> m_connections;
        /// Every handshake in progress, by ticket, with its source. Tickets are never reused, not even
        /// across reset(), so a share can only ever release the handshake it was taken for.
        std::unordered_map<std::uint64_t, std::string> m_handshakes;
        std::unordered_map<std::string, std::size_t> m_perSource;
        std::uint64_t m_nextTicket {1};
        std::uint64_t m_timeoutsTotal {0};
        std::uint64_t m_rejectedPerSourceTotal {0};
    };
} // namespace remoted::http

#endif // _REMOTED_HTTP_HANDSHAKE_LEDGER_HPP
