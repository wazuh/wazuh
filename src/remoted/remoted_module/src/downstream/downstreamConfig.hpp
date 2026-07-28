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
     * The events socket path mirrors remoted's C forwarder (ANLSYS_ENRICH_SOCK, relative to the
     * chroot) and is not C-ABI driven -- it is an installation detail, not an ops tuning knob.
     * Every other field is populated from the C-ABI struct by buildDownstreamConfig() below; the
     * in-struct defaults here only apply to a default-constructed DownstreamConfig (e.g. in tests).
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
