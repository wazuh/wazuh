/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _INVSYNC_UDS_HTTP_SERVER_CONFIG_HPP
#define _INVSYNC_UDS_HTTP_SERVER_CONFIG_HPP

#include "IUdsHttpServer.hpp"
#include "inventory_sync_server.h"

namespace invsync::http
{

    /**
     * @brief Translate the C-ABI configuration struct into the server's own configuration.
     *
     * Applies the C-ABI's uniform sentinel rule -- an int <= 0 or an empty string means "the
     * caller has no opinion" -- so that every default lives here rather than being duplicated in
     * modulesd's C shim. Thread-count fields fall back to cpp_get_nproc() instead of a fixed
     * constant, so the server tracks the host/cgroup's available CPUs.
     *
     * @param config The caller's configuration (a zeroed struct yields all defaults).
     * @return The resolved server configuration.
     */
    UdsHttpServerConfig buildServerConfig(const inventory_sync_server_config_t& config);

} // namespace invsync::http

#endif // _INVSYNC_UDS_HTTP_SERVER_CONFIG_HPP
