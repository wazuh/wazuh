/*
 * Wazuh auth middleware (framework-agnostic)
 * Copyright (C) 2015, Wazuh Inc.
 * July 20, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace wazuh_auth
{

    /**
     * @brief TLS material and version floor for an IAuthServer implementation.
     *
     * Lives here so a RESTinio server and a Beast server read the exact same
     * configuration surface and neither hides a tunable behind library-specific
     * defaults.
     */
    struct TlsConfig
    {
        std::string certificateChainFile; ///< Path to the PEM certificate chain file.
        std::string privateKeyFile;       ///< Path to the PEM private key file.
        std::string minVersion = "1.2";   ///< Minimum accepted TLS version. Only "1.2" and "1.3" are meaningful.
    };

    /**
     * @brief Every non-TLS server tunable (threading model, header/body limits,
     *        timeouts, listen backlog) an IAuthServer implementation must honor.
     */
    struct ServerConfig
    {
        std::string address = "0.0.0.0"; ///< Listen address.
        std::uint16_t port = 0;          ///< Listen port; 0 lets the OS pick one.

        std::size_t ioThreads = 0; ///< io_context thread pool size; 0 lets the implementation pick
                                   ///< (typically std::thread::hardware_concurrency()).

        std::size_t maxHeaderBytes = 16 * 1024;      ///< Hard cap on header size, enforced before auth/body processing.
        std::size_t maxBodyBytes = 10 * 1024 * 1024; ///< Hard cap on body size, enforced before auth/body processing.

        std::int64_t handshakeTimeoutSeconds = 10; ///< TLS handshake timeout.
        std::int64_t requestTimeoutSeconds = 30;   ///< Time allowed to read a full request after the handshake.

        int backlog = 1024; ///< TCP listen backlog.
    };

} // namespace wazuh_auth
