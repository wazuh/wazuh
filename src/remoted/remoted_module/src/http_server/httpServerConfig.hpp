/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 21, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_HTTP_SERVER_CONFIG_HPP
#define _REMOTED_HTTP_SERVER_CONFIG_HPP

#include "IHttpServer.hpp"
#include "remoted_module.h"

namespace remoted::http
{

    /**
     * @brief Translate the module's C-ABI config into an HttpServerConfig.
     *
     * Fields left empty/zero by the caller (remoted fills the struct with {0}) fall
     * back to environment variables and then to built-in defaults, so the server is
     * usable today without wiring every value from the C side:
     *   - port          <- config.port  | WAZUH_REMOTED_HTTPS_PORT          | 9443
     *   - ioThreads     <- config.io_threads | WAZUH_REMOTED_HTTPS_IO_THREADS | 2
     *   - workerThreads <- config.http_worker_threads | config.worker_threads
     *                        | WAZUH_REMOTED_HTTPS_WORKER_THREADS | 4
     *   - certificate   <- config.certificate_path | WAZUH_REMOTED_HTTPS_CERTIFICATE  | default
     *   - private key   <- config.private_key_path | WAZUH_REMOTED_HTTPS_PRIVATE_KEY  | default
     *   - bind address  <- WAZUH_REMOTED_HTTPS_ADDRESS | 127.0.0.1
     *   - max body size <- WAZUH_REMOTED_HTTPS_MAX_BODY_SIZE | 2 MiB
     *
     * @param config Configuration handed by remoted.
     * @return Resolved HttpServerConfig.
     * @throws std::invalid_argument if an environment override is not a valid integer in range.
     */
    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config);

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CONFIG_HPP
