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

#ifndef _REMOTED_HTTP_SERVER_FACTORY_HPP
#define _REMOTED_HTTP_SERVER_FACTORY_HPP

#include "IHttpServer.hpp"

#include <memory>

namespace remoted::http
{

    /**
     * @brief Create the default HTTP(S) server implementation.
     *
     * This is the single swap point for the transport library: today it returns the
     * RESTinio-backed server; a future Boost.Beast implementation only needs a new
     * IHttpServer subclass and a one-line change here. Callers never see the
     * underlying library.
     *
     * @return An owned IHttpServer.
     */
    std::unique_ptr<IHttpServer> makeHttpServer();

} // namespace remoted::http

#endif // _REMOTED_HTTP_SERVER_FACTORY_HPP
