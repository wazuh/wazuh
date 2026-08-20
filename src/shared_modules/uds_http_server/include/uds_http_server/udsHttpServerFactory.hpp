/*
 * Wazuh shared UDS HTTP server library
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _WAZUH_UDS_HTTP_SERVER_FACTORY_HPP
#define _WAZUH_UDS_HTTP_SERVER_FACTORY_HPP

#include "IUdsHttpServer.hpp"

#include <memory>

namespace wazuh::uds_http
{

    /**
     * @brief Create the default HTTP-over-UDS server implementation.
     *
     * This is the single swap point for the transport library: today it returns the asio + llhttp
     * server; any replacement only needs a new IUdsHttpServer subclass and a one-line change here.
     * Callers never see the underlying library -- neither asio nor llhttp appears in any header
     * this module exposes.
     *
     * @return An owned IUdsHttpServer.
     */
    std::unique_ptr<IUdsHttpServer> makeUdsHttpServer();

} // namespace wazuh::uds_http

#endif // _WAZUH_UDS_HTTP_SERVER_FACTORY_HPP
