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

#ifndef _INVSYNC_ENDPOINTS_SYNC_ENDPOINT_HPP
#define _INVSYNC_ENDPOINTS_SYNC_ENDPOINT_HPP

#include "http_server/IUdsHttpServer.hpp"

namespace invsync::endpoints::sync
{

    /**
     * @brief The inventory synchronization ingress endpoint.
     *
     * STUB. Today this route accepts a request, counts its bytes, and answers 202 -- it does not
     * decode the payload and it DISCARDS it. This is the seam where FlatBuffer decoding, the agent
     * session table and the indexer connector land; keeping it a separate unit from the start means
     * that work is a change to one file plus its test, not a change to the facade.
     *
     * @warning The path is PROVISIONAL. It has to match the target remoted's downstream
     * configuration will point at, and that side lands in a separate change. Until both agree,
     * treat a change here as a wire-protocol change: syncEndpoint_test.cpp pins the value so a
     * silent drift is caught.
     */

    /// @brief The verb this endpoint answers.
    constexpr http::Method method()
    {
        return http::Method::Post;
    }

    /// @brief The path this endpoint answers. PROVISIONAL -- see the note above.
    constexpr const char* path()
    {
        return "/inventory/sync";
    }

    /**
     * @brief Build the endpoint's route handler.
     *
     * The returned handler replies inline and holds no state, so it is safe to register on any
     * server instance and outlives nothing. When the real pipeline lands it will instead move the
     * responder onto a queue and return without answering -- which is exactly what the transport's
     * deferred-response contract exists to support, and why the handler signature already takes a
     * responder rather than returning a response.
     */
    http::RouteHandler makeHandler();

} // namespace invsync::endpoints::sync

#endif // _INVSYNC_ENDPOINTS_SYNC_ENDPOINT_HPP
