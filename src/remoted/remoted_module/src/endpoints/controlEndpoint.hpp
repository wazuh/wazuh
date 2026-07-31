/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 31, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENDPOINTS_CONTROL_ENDPOINT_HPP
#define _REMOTED_ENDPOINTS_CONTROL_ENDPOINT_HPP

#include "control/controlHandler.hpp" // remoted::control::ControlHandler
#include "endpoint.hpp"               // AuthenticatedHandler + shared type aliases

namespace remoted::endpoints::control
{

    /**
     * @brief Builds the `POST /control` AuthenticatedHandler.
     *
     * Parses the request body as JSON, dispatches on the top-level `"type"` field
     * to the matching @ref remoted::control::ControlHandler method, and forwards
     * the resulting @ref remoted::control::HttpResponse to the transport
     * responder. All three message types (`"startup"`, `"notify"`, `"shutdown"`)
     * are answered as `application/json`.
     *
     * The handler runs on the HTTP server's worker pool: parsing is synchronous;
     * the downstream side (wdb / task-manager sockets) is asynchronous, so the
     * responder is captured and answered later from a wdb/task worker thread.
     *
     * @warning The returned handler stores a reference to @p handler. The caller
     * must guarantee @p handler outlives every route registered with it -- i.e.
     * the HTTP server (which owns the route table holding this handler) must be
     * stopped/destroyed before @p handler is destroyed. RemotedModuleFacade::stop()
     * already orders teardown this way.
     */
    remoted::endpoints::AuthenticatedHandler makeHandler(remoted::control::ControlHandler& handler);

} // namespace remoted::endpoints::control

#endif // _REMOTED_ENDPOINTS_CONTROL_ENDPOINT_HPP
