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
     * @param config Configuration handed by remoted.
     * @return Resolved HttpServerConfig.
     */
    HttpServerConfig buildHttpServerConfig(const remoted_module_config_t& config);

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_CONFIG_HPP
