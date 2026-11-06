/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_CONNECTION_ID_SOURCE_HPP
#define _REMOTED_HTTP_CONNECTION_ID_SOURCE_HPP

/**
 * @file connectionIdSource.hpp
 * @brief The ids of the public listener's connections: distinct for every connection of a server run.
 *
 * WHY THIS EXISTS. RESTinio 0.7.x numbers its connections with a plain post-increment of a counter
 * shared by the whole server (connection_factory_t::create_new_connection() in
 * restinio/impl/connection.hpp). That call runs on the acceptor's executor, which is the io_context
 * itself, not a strand, so with more than one I/O thread two connections created at the same moment
 * race on the counter and can get the same id. The handshake ledger, the connection level and the
 * verification_mode=full verdicts are all keyed by that id: a repeated one leaked a handshake slot of
 * its address for good. RestinioHttpServer.cpp replaces RESTinio's factory for its traits with one that
 * takes its ids from here, which keeps the concurrent accepts.
 *
 * The first id is 1, as in RESTinio. Uniqueness needs the increment to be atomic and nothing more:
 * no other memory is published through the id, so a relaxed order is enough.
 *
 * Deliberately RESTinio-free, so it is unit-tested on its own.
 */

#include <atomic>
#include <cstdint>

namespace remoted::http
{
    class ConnectionIdSource final
    {
    public:
        /// The next id; safe to call from any number of threads at once.
        std::uint64_t next() noexcept
        {
            return m_next.fetch_add(1, std::memory_order_relaxed);
        }

    private:
        std::atomic<std::uint64_t> m_next {1};
    };
} // namespace remoted::http

#endif // _REMOTED_HTTP_CONNECTION_ID_SOURCE_HPP
