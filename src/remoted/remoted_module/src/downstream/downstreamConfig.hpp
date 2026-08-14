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

#include "remoted_module.h"

#include <cstddef>
#include <string>

namespace remoted::downstream
{

    /**
     * @brief Tunables for the deferred-forwarding subsystem.
     *
     * The socket paths mirror the services they reach (relative to the chroot) and are not C-ABI
     * driven -- they are installation details, not ops tuning knobs. Every other field is populated
     * from the C-ABI struct by buildDownstreamConfig() below; the in-struct defaults here only apply
     * to a default-constructed DownstreamConfig (e.g. in tests).
     */
    struct DownstreamConfig
    {
        /// Default UDS for the engine event ingress; the facade builds the /stateless target from it.
        std::string eventsSocketPath {"queue/sockets/queue-http.sock"};
        /**
         * @brief Default UDS for modulesd's inventory sync server; /stats and /config target it.
         */
        std::string inventorySyncSocketPath {"queue/sockets/inventory-sync.sock"};
        int connectTimeoutMs {2000};  ///< Connect timeout per request.
        int writeTimeoutMs {5000};    ///< Write (request body send) timeout per request.
        int responseTimeoutMs {5000}; ///< Response (post-send) timeout per request.
        /// Response timeout for the /stateful route specifically (flows into its DownstreamTarget's
        /// responseTimeoutMs override). Longer than responseTimeoutMs because a sync session is
        /// indexed and flushed within the request (see remoted.downstream_stateful_response_timeout).
        int statefulResponseTimeoutMs {20000};
        std::size_t ioThreads {1};          ///< Threads running the client's io_context.
        std::size_t postProcessThreads {4}; ///< Threads running the per-endpoint post-processors.
        /// Cap on a downstream response body. Strictly larger than the 10 MiB agent-request cap:
        /// /stats and /config echo the agent's document back ENRICHED, so a cap equal to the
        /// request cap would turn a near-cap document into ResponseTooLarge -> 503.
        std::size_t maxResponseBodySize {11U * 1024U * 1024U};
    };

    /**
     * @brief Translate the module's C-ABI config into a DownstreamConfig.
     *
     * Every field resolves as **caller value (C-ABI struct) -> built-in default**, same pattern as
     * remoted::http::buildHttpServerConfig(). `downstream_io_threads`/`downstream_post_process_threads`
     * are thread-count fields: a `<=0` value resolves via cpp_get_nproc() (shared_modules/utils/proc.hpp)
     * instead of a fixed constant. Timeouts are read from the C-ABI struct in seconds and converted to
     * milliseconds here.
     *
     * @param config Configuration handed by remoted.
     * @return Resolved DownstreamConfig.
     */
    DownstreamConfig buildDownstreamConfig(const remoted_module_config_t& config);

} // namespace remoted::downstream

#endif // _REMOTED_DOWNSTREAM_CONFIG_HPP
