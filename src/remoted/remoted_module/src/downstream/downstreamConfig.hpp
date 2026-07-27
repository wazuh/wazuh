/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 25, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_DOWNSTREAM_CONFIG_HPP
#define _REMOTED_DOWNSTREAM_CONFIG_HPP

#include <cstddef>
#include <string>

namespace remoted::downstream
{

    /**
     * @brief Tunables for the deferred-forwarding subsystem.
     *
     * v1: built-in defaults only (not env/C-ABI driven). The events socket path mirrors
     * remoted's C forwarder (ANLSYS_ENRICH_SOCK, relative to the chroot). Promotion to the
     * C-ABI config struct is a follow-up.
     */
    struct DownstreamConfig
    {
        /// Default UDS for the engine event ingress; the facade builds the /stateless target from it.
        std::string eventsSocketPath {"queue/sockets/queue-http.sock"};
        int connectTimeoutMs {2000};                           ///< Connect timeout per request.
        int writeTimeoutMs {5000};                             ///< Write (request body send) timeout per request.
        int responseTimeoutMs {5000};                          ///< Response (post-send) timeout per request.
        std::size_t ioThreads {1};                             ///< Threads running the client's io_context.
        std::size_t postProcessThreads {4};                    ///< Threads running the per-endpoint post-processors.
        std::size_t maxResponseBodySize {10U * 1024U * 1024U}; ///< Cap on a downstream response body.
    };

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_CONFIG_HPP
